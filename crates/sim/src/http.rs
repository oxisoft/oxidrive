//! The simulator over real HTTP (client foundation B5): the real server, started in process,
//! reached through the client's `HttpServer`. The simulator's devices run on the testkit's
//! blocking executor, so each call runs to completion on this backend's own runtime.

use std::future::Future;

use oxisoft_drive_client::http::{Api, HttpServer, Session, Trust};
use oxisoft_drive_core::{ServerApi, ServerError};
use oxisoft_drive_proto::api::{AppendResult, Commits, Head, Missing};
use oxisoft_drive_proto::{ChunkId, CollectionId, Commit, LeaseId, Seq};
use oxisoft_drive_testkit::http_server::{Prepared, TestServer, device_key, prepare, start, stop};

/// No rate limit gets in the simulation's way: one session carries every device's requests.
const UNLIMITED: &str = "[rates]\ndevice_per_minute = 1000000000\n";

/// The real server over HTTP, as one [`ServerApi`] for every simulated device. The server
/// checks commits by their signatures, not by who is signed in, so one session (device 0's)
/// carries them all.
#[derive(Debug)]
pub struct HttpBackend {
    runtime: tokio::runtime::Runtime,
    server: Option<TestServer>,
    client: HttpServer,
    _prepared: Prepared,
}

impl HttpBackend {
    /// Starts a server whose account trusts devices `0..=trusted`.
    ///
    /// # Errors
    ///
    /// If the runtime or the client can't be set up.
    pub fn start(trusted: usize) -> Result<Self, String> {
        let prepared = prepare(trusted, None, UNLIMITED);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|error| error.to_string())?;
        let server = runtime.block_on(start(&prepared));
        let api = Api::new(&prepared.origin, Trust::System).map_err(|error| error.to_string())?;
        Ok(Self {
            client: HttpServer::new(Session::new(api, device_key(0))),
            server: Some(server),
            runtime,
            _prepared: prepared,
        })
    }

    fn run<T>(&self, call: impl Future<Output = T>) -> impl Future<Output = T> + Send
    where
        T: Send,
    {
        std::future::ready(self.runtime.block_on(call))
    }
}

impl Drop for HttpBackend {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            self.runtime.block_on(stop(server));
        }
    }
}

impl ServerApi for HttpBackend {
    fn head(
        &self,
        collection: CollectionId,
    ) -> impl Future<Output = Result<Option<Head>, ServerError>> + Send {
        self.run(self.client.head(collection))
    }

    fn commits_after(
        &self,
        collection: CollectionId,
        after: Seq,
        limit: u32,
    ) -> impl Future<Output = Result<Commits, ServerError>> + Send {
        self.run(self.client.commits_after(collection, after, limit))
    }

    fn append(
        &self,
        collection: CollectionId,
        expected: Option<Head>,
        commit: Commit,
    ) -> impl Future<Output = Result<AppendResult, ServerError>> + Send {
        self.run(self.client.append(collection, expected, commit))
    }

    fn missing(
        &self,
        collection: CollectionId,
        ids: Vec<ChunkId>,
    ) -> impl Future<Output = Result<Missing, ServerError>> + Send {
        self.run(self.client.missing(collection, ids))
    }

    fn put_chunk(
        &self,
        collection: CollectionId,
        lease: LeaseId,
        id: ChunkId,
        object: Vec<u8>,
    ) -> impl Future<Output = Result<(), ServerError>> + Send {
        self.run(self.client.put_chunk(collection, lease, id, object))
    }

    fn get_chunk(
        &self,
        collection: CollectionId,
        id: ChunkId,
    ) -> impl Future<Output = Result<Vec<u8>, ServerError>> + Send {
        self.run(self.client.get_chunk(collection, id))
    }
}
