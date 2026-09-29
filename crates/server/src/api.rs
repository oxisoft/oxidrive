//! The HTTP API (server HTTP, `server-api.md`): an axum router over the [`Service`].
//! Handlers decode CBOR, authenticate, rate-limit, call the service and encode; the rules
//! stay in the service.

mod events;
mod handlers;
mod limits;
mod wire;

use std::marker::PhantomData;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post, put};
use oxisoft_drive_crypto::CryptoRng;
use oxisoft_drive_server_store::MetaStore;
use tower_http::timeout::TimeoutLayer;

use crate::blob::BlobStore;
use crate::service::{Clock, Service};

pub use limits::RateLimits;

/// Largest body of requests other than commits and chunk objects.
const SMALL_BODY: usize = 1024 * 1024;
/// Room for the CBOR framing around a commit.
const COMMIT_FRAMING: usize = 64 * 1024;
/// How long any request may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// The types a server runs on, bundled so handlers carry one type parameter.
pub trait Deps: Send + Sync + 'static {
    /// The metadata store.
    type Meta: MetaStore + 'static;
    /// The blob store.
    type Blobs: BlobStore + 'static;
    /// The clock.
    type Clock: Clock + 'static;
    /// The random number generator.
    type Rng: CryptoRng + Send + 'static;
}

/// A type that names four types without holding them.
type Names<M, B, C, R> = fn() -> (M, B, C, R);

/// [`Deps`] for these four types.
#[derive(Debug)]
pub struct With<M, B, C, R>(PhantomData<Names<M, B, C, R>>);

impl<M, B, C, R> Deps for With<M, B, C, R>
where
    M: MetaStore + 'static,
    B: BlobStore + 'static,
    C: Clock + 'static,
    R: CryptoRng + Send + 'static,
{
    type Meta = M;
    type Blobs = B;
    type Clock = C;
    type Rng = R;
}

/// The service of a [`Deps`].
pub type ServiceOf<D> =
    Service<<D as Deps>::Meta, <D as Deps>::Blobs, <D as Deps>::Clock, <D as Deps>::Rng>;

/// How the API faces the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiConfig {
    /// The public URL devices use and sign into their sign-in answers (server API §2),
    /// e.g. `https://drive.example.com`.
    pub origin: String,
    /// Reverse proxies whose `X-Forwarded-For` names the client (S6).
    pub trusted_proxies: Vec<IpAddr>,
    /// Rate limits.
    pub limits: RateLimits,
}

/// The API: the service, the rate limiters and the event channels.
pub struct Api<D: Deps> {
    service: ServiceOf<D>,
    config: ApiConfig,
    limiters: limits::Limiters,
    events: events::Events,
}

impl<D: Deps> std::fmt::Debug for Api<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<D: Deps> Api<D> {
    /// The API over `service`.
    #[must_use]
    pub fn new(service: ServiceOf<D>, config: ApiConfig) -> Arc<Self> {
        let limiters = limits::Limiters::new(&config.limits);
        Arc::new(Self {
            service,
            config,
            limiters,
            events: events::Events::default(),
        })
    }

    /// The service, for maintenance and administration.
    #[must_use]
    pub const fn service(&self) -> &ServiceOf<D> {
        &self.service
    }

    /// Forgets rate-limit state of clients that have been quiet (call now and then).
    pub fn forget_idle_clients(&self) {
        self.limiters.forget_idle();
    }

    /// The routes of `/v1`.
    pub fn router(self: &Arc<Self>) -> Router {
        let limits = self.service.settings().limits;
        let commit_body = limits.max_commit as usize + COMMIT_FRAMING;
        let object_body = limits.max_object as usize;
        Router::new()
            .route("/v1/info", get(handlers::info::<D>))
            .route("/v1/auth/challenge", post(handlers::challenge::<D>))
            .route("/v1/auth/session", post(handlers::session::<D>))
            .route("/v1/accounts", post(handlers::create_account::<D>))
            .route(
                "/v1/accounts/{account}/recovery",
                get(handlers::recovery::<D>),
            )
            .route(
                "/v1/devices",
                get(handlers::devices::<D>).put(handlers::put_devices::<D>),
            )
            .route(
                "/v1/keys",
                get(handlers::keys::<D>).put(handlers::put_keys::<D>),
            )
            .route("/v1/pairings", post(handlers::create_pairing::<D>))
            .route("/v1/pairings/{pairing}", get(handlers::pairing::<D>))
            .route(
                "/v1/pairings/{pairing}/approve",
                post(handlers::approve_pairing::<D>),
            )
            .route(
                "/v1/collections",
                get(handlers::collections::<D>).post(handlers::create_collection::<D>),
            )
            .route(
                "/v1/collections/{collection}",
                axum::routing::patch(handlers::patch_collection::<D>)
                    .delete(handlers::delete_collection::<D>),
            )
            .route(
                "/v1/collections/{collection}/head",
                get(handlers::head::<D>),
            )
            .route(
                "/v1/collections/{collection}/commits",
                get(handlers::commits::<D>)
                    .post(handlers::append::<D>)
                    .layer(DefaultBodyLimit::max(commit_body)),
            )
            .route(
                "/v1/collections/{collection}/chunks/missing",
                post(handlers::missing::<D>),
            )
            .route(
                "/v1/collections/{collection}/chunks/{chunk}",
                put(handlers::put_chunk::<D>)
                    .get(handlers::get_chunk::<D>)
                    .layer(DefaultBodyLimit::max(object_body)),
            )
            .route(
                "/v1/collections/{collection}/heads",
                get(handlers::attestations::<D>).post(handlers::attest::<D>),
            )
            .route("/v1/events", get(handlers::events::<D>))
            .layer(DefaultBodyLimit::max(SMALL_BODY))
            .layer(TimeoutLayer::with_status_code(
                axum::http::StatusCode::REQUEST_TIMEOUT,
                REQUEST_TIMEOUT,
            ))
            .with_state(Arc::clone(self))
    }
}
