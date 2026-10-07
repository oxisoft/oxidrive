//! [`HttpServer`]: core's [`ServerApi`] over the HTTP API (client foundation §4).

use std::sync::Arc;

use oxisoft_drive_core::{ServerApi, ServerError};
use oxisoft_drive_proto::api::{AppendResult, Commits, ErrorCode, Head, Missing};
use oxisoft_drive_proto::{ChunkId, CollectionId, Commit, LeaseId, Seq};

use super::{ApiError, Session};

/// The engine's server, reached over HTTPS with a device's session.
#[derive(Debug, Clone)]
pub struct HttpServer {
    session: Arc<Session>,
}

impl HttpServer {
    /// The server behind `session`.
    #[must_use]
    pub const fn new(session: Arc<Session>) -> Self {
        Self { session }
    }

    /// The session.
    #[must_use]
    pub const fn session(&self) -> &Arc<Session> {
        &self.session
    }
}

/// What the engine makes of an API error: unreachable, overloaded or failing servers are
/// tried again later; a refusal is reported.
fn server_error(error: ApiError) -> ServerError {
    match error {
        ApiError::Server {
            code: ErrorCode::NotFound,
            ..
        } => ServerError::NotFound,
        ApiError::Server {
            status,
            code,
            message,
            ..
        } if status >= 500 || code == ErrorCode::RateLimited => {
            ServerError::Unavailable(format!("{code:?}: {message}"))
        }
        ApiError::Server { code, message, .. } => {
            ServerError::Rejected(format!("{code:?}: {message}"))
        }
        ApiError::Network(message) => ServerError::Unavailable(message),
        other @ (ApiError::Tls(_) | ApiError::Decode(_)) => {
            ServerError::Rejected(other.to_string())
        }
    }
}

impl ServerApi for HttpServer {
    async fn head(&self, collection: CollectionId) -> Result<Option<Head>, ServerError> {
        self.session
            .with_token(|token| {
                let session = Arc::clone(&self.session);
                async move { session.api().head(&token, collection).await }
            })
            .await
            .map_err(server_error)
    }

    async fn commits_after(
        &self,
        collection: CollectionId,
        after: Seq,
        limit: u32,
    ) -> Result<Commits, ServerError> {
        self.session
            .with_token(|token| {
                let session = Arc::clone(&self.session);
                async move {
                    session
                        .api()
                        .commits(&token, collection, after, limit)
                        .await
                }
            })
            .await
            .map_err(server_error)
    }

    async fn append(
        &self,
        collection: CollectionId,
        expected: Option<Head>,
        commit: Commit,
    ) -> Result<AppendResult, ServerError> {
        self.session
            .with_token(|token| {
                let (session, commit) = (Arc::clone(&self.session), commit.clone());
                async move {
                    session
                        .api()
                        .append(&token, collection, expected, commit)
                        .await
                }
            })
            .await
            .map_err(server_error)
    }

    async fn missing(
        &self,
        collection: CollectionId,
        ids: Vec<ChunkId>,
    ) -> Result<Missing, ServerError> {
        self.session
            .with_token(|token| {
                let (session, ids) = (Arc::clone(&self.session), ids.clone());
                async move { session.api().missing(&token, collection, ids).await }
            })
            .await
            .map_err(server_error)
    }

    async fn put_chunk(
        &self,
        collection: CollectionId,
        lease: LeaseId,
        id: ChunkId,
        object: Vec<u8>,
    ) -> Result<(), ServerError> {
        self.session
            .with_token(|token| {
                let (session, object) = (Arc::clone(&self.session), object.clone());
                async move {
                    session
                        .api()
                        .put_chunk(&token, collection, lease, id, object)
                        .await
                }
            })
            .await
            .map_err(server_error)
    }

    async fn get_chunk(
        &self,
        collection: CollectionId,
        id: ChunkId,
    ) -> Result<Vec<u8>, ServerError> {
        self.session
            .with_token(|token| {
                let session = Arc::clone(&self.session);
                async move { session.api().get_chunk(&token, collection, id).await }
            })
            .await
            .map_err(server_error)
    }
}
