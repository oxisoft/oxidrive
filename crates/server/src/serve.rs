//! `serve` (server binary §3): the listeners, plain or TLS, the maintenance loop, the
//! heartbeat, certificate reloading and a graceful shutdown.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use axum::extract::Request;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;

use crate::api::{Api, ApiConfig, Deps, ServiceOf};
use crate::config::Config;
use crate::service::ServiceError;
use crate::tls::{Resolver, TlsError};

/// The name `serve` records its heartbeat under.
pub const HEARTBEAT: &str = "serve";
/// How often `serve` records that it is alive.
pub const HEARTBEAT_EVERY: Duration = Duration::from_secs(60);
/// A heartbeat older than this means no server is running.
pub const HEARTBEAT_STALE: Duration = Duration::from_secs(180);
/// How often the certificate files are checked for a renewal.
const CERTIFICATE_CHECK: Duration = Duration::from_secs(600);
/// How long a TLS handshake may take.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long running requests may take to finish at shutdown.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

/// Why `serve` couldn't start.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// An address couldn't be bound.
    #[error("listening on {addr}: {source}")]
    Bind {
        /// The address.
        addr: SocketAddr,
        /// What went wrong.
        source: std::io::Error,
    },
    /// The certificate couldn't be loaded.
    #[error("TLS: {0}")]
    Tls(#[from] TlsError),
}

/// A running server.
#[derive(Debug)]
pub struct Running<D: Deps> {
    api: Arc<Api<D>>,
    addrs: Vec<SocketAddr>,
    resolver: Option<Arc<Resolver>>,
    stop: watch::Sender<bool>,
    listeners: JoinSet<()>,
    background: JoinSet<()>,
}

/// Starts serving `service` as `config` says: binds every address, then serves until
/// [`Running::shutdown`].
///
/// # Errors
///
/// [`ServeError`] if an address can't be bound or the certificate can't be loaded.
pub async fn start<D: Deps>(
    config: &Config,
    service: ServiceOf<D>,
) -> Result<Running<D>, ServeError> {
    let resolver = config
        .tls
        .clone()
        .map(Resolver::new)
        .transpose()?
        .map(Arc::new);
    let acceptor = resolver
        .as_ref()
        .map(|resolver| {
            resolver
                .server_config()
                .map(|tls| TlsAcceptor::from(Arc::new(tls)))
        })
        .transpose()?;
    let mut bound = Vec::new();
    for addr in &config.listen {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|source| ServeError::Bind {
                addr: *addr,
                source,
            })?;
        let local = listener.local_addr().map_err(|source| ServeError::Bind {
            addr: *addr,
            source,
        })?;
        bound.push((listener, local));
    }
    let api = Api::new(
        service,
        ApiConfig {
            origin: config.origin.clone(),
            trusted_proxies: config.trusted_proxies.clone(),
            limits: config.rates,
        },
    );
    let router = api.router().layer(axum::middleware::from_fn(log_request));
    let (stop, stopped) = watch::channel(false);
    let mut listeners = JoinSet::new();
    let mut addrs = Vec::new();
    for (listener, local) in bound {
        tracing::info!(
            address = %local,
            tls = acceptor.is_some(),
            "listening"
        );
        addrs.push(local);
        listeners.spawn(accept_loop(
            listener,
            router.clone(),
            acceptor.clone(),
            stopped.clone(),
        ));
    }
    let mut background = JoinSet::new();
    background.spawn(heartbeat(Arc::clone(&api), stopped.clone()));
    background.spawn(maintenance(
        Arc::clone(&api),
        config.maintenance_interval,
        stopped.clone(),
    ));
    if let Some(resolver) = &resolver {
        background.spawn(watch_certificate(Arc::clone(resolver), stopped));
    }
    Ok(Running {
        api,
        addrs,
        resolver,
        stop,
        listeners,
        background,
    })
}

impl<D: Deps> Running<D> {
    /// The bound addresses (with the actual ports, when the config said 0).
    #[must_use]
    pub fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// The API, for its service.
    #[must_use]
    pub const fn api(&self) -> &Arc<Api<D>> {
        &self.api
    }

    /// Loads the certificate files again (`SIGHUP`). `Ok(false)` without TLS.
    ///
    /// # Errors
    ///
    /// [`TlsError`] if they don't load; the old certificate stays.
    pub fn reload_tls(&self) -> Result<bool, TlsError> {
        match &self.resolver {
            Some(resolver) => resolver.reload().map(|()| true),
            None => Ok(false),
        }
    }

    /// Stops accepting, lets running requests finish for up to `grace`, then stops; the
    /// heartbeat is removed.
    pub async fn shutdown(mut self, grace: Duration) {
        let _ = self.stop.send(true);
        self.background.shutdown().await;
        let drained = tokio::time::timeout(grace, async {
            while self.listeners.join_next().await.is_some() {}
        })
        .await;
        if drained.is_err() {
            tracing::warn!("requests still running after the grace time; closing them");
            self.listeners.shutdown().await;
        }
        if let Err(error) = self.api.service().stop_beat(HEARTBEAT).await {
            tracing::warn!(%error, "removing the heartbeat");
        }
        tracing::info!("stopped");
    }
}

/// Accepts connections until told to stop, then waits for the open ones to finish.
async fn accept_loop(
    listener: TcpListener,
    router: Router,
    tls: Option<TlsAcceptor>,
    mut stop: watch::Receiver<bool>,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    connections.spawn(connection(
                        stream,
                        peer,
                        router.clone(),
                        tls.clone(),
                        stop.clone(),
                    ));
                }
                Err(error) => {
                    // Out of file descriptors, say: don't spin.
                    tracing::warn!(%error, "accepting a connection");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    drop(listener);
    while connections.join_next().await.is_some() {}
}

async fn connection(
    stream: TcpStream,
    peer: SocketAddr,
    router: Router,
    tls: Option<TlsAcceptor>,
    stop: watch::Receiver<bool>,
) {
    let service = WithPeer { router, peer };
    match tls {
        None => serve_io(TokioIo::new(stream), service, stop).await,
        Some(acceptor) => {
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(stream)) => serve_io(TokioIo::new(stream), service, stop).await,
                Ok(Err(error)) => tracing::debug!(%peer, %error, "TLS handshake failed"),
                Err(_) => tracing::debug!(%peer, "TLS handshake timed out"),
            }
        }
    }
}

/// Serves one connection (HTTP/1.1, with upgrades for the event sockets, or HTTP/2); on
/// stop, it finishes its running requests and closes.
async fn serve_io<I>(io: I, service: WithPeer, mut stop: watch::Receiver<bool>)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let builder = auto::Builder::new(TokioExecutor::new());
    let connection = builder.serve_connection_with_upgrades(io, service);
    tokio::pin!(connection);
    tokio::select! {
        result = connection.as_mut() => {
            if let Err(error) = result {
                tracing::debug!(%error, "connection ended");
            }
        }
        _ = stop.changed() => {
            connection.as_mut().graceful_shutdown();
            let _ = connection.await;
        }
    }
}

/// The router, with the connection's peer address for the client address (server HTTP §6).
#[derive(Debug, Clone)]
struct WithPeer {
    router: Router,
    peer: SocketAddr,
}

impl hyper::service::Service<Request<Incoming>> for WithPeer {
    type Response = axum::response::Response;
    type Error = Infallible;
    type Future = <Router as tower::Service<Request<Incoming>>>::Future;

    fn call(&self, mut request: Request<Incoming>) -> Self::Future {
        request.extensions_mut().insert(ConnectInfo(self.peer));
        tower::Service::call(&mut self.router.clone(), request)
    }
}

/// Logs one line per request: method, route pattern (never the concrete path, which holds
/// IDs), status and time taken. Headers and bodies, with their tokens, are never logged.
async fn log_request(request: Request, next: axum::middleware::Next) -> axum::response::Response {
    let method = request.method().clone();
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map_or_else(|| "(no route)".to_owned(), |path| path.as_str().to_owned());
    let started = std::time::Instant::now();
    let response = next.run(request).await;
    tracing::info!(
        %method,
        route,
        status = response.status().as_u16(),
        ms = started.elapsed().as_millis(),
        "request"
    );
    response
}

/// Records the heartbeat every minute, and forgets idle clients' rate-limit state.
async fn heartbeat<D: Deps>(api: Arc<Api<D>>, mut stop: watch::Receiver<bool>) {
    let mut ticks = tokio::time::interval(HEARTBEAT_EVERY);
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            _ = ticks.tick() => {
                if let Err(error) = api.service().beat(HEARTBEAT).await {
                    tracing::warn!(%error, "recording the heartbeat");
                }
                api.forget_idle_clients();
            }
        }
    }
}

/// Prunes and collects garbage every `every`, first one interval after start.
async fn maintenance<D: Deps>(api: Arc<Api<D>>, every: Duration, mut stop: watch::Receiver<bool>) {
    let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            _ = ticks.tick() => {
                if let Err(error) = maintain::<D>(api.service()).await {
                    tracing::error!(%error, "maintenance");
                }
            }
        }
    }
}

/// One maintenance round: prune, then collect garbage (also `oxidrive-server gc`).
///
/// # Errors
///
/// Store and blob store failures.
pub async fn maintain<D: Deps>(
    service: &ServiceOf<D>,
) -> Result<(u64, crate::service::GcReport), ServiceError> {
    let pruned = service.prune().await?;
    let report = service.collect_garbage().await?;
    tracing::info!(
        pruned,
        collections = report.collections,
        sign_ins = report.sign_ins,
        leases = report.leases,
        marked = report.marked,
        chunks = report.chunks,
        bytes = report.bytes,
        "maintenance"
    );
    Ok((pruned, report))
}

/// Reloads the certificate when its files change.
async fn watch_certificate(resolver: Arc<Resolver>, mut stop: watch::Receiver<bool>) {
    let mut ticks = tokio::time::interval_at(
        tokio::time::Instant::now() + CERTIFICATE_CHECK,
        CERTIFICATE_CHECK,
    );
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            _ = ticks.tick() => match resolver.reload_if_changed() {
                Ok(true) => tracing::info!("certificate reloaded"),
                Ok(false) => {}
                Err(error) => tracing::error!(%error, "certificate changed but doesn't load; keeping the old one"),
            },
        }
    }
}
