//! The server's API over HTTPS (client foundation §4): [`Api`] has one typed call per
//! endpoint of `server-http.md` §4; [`Session`] signs in and keeps a token; [`HttpServer`]
//! is core's `ServerApi` on top; [`Events`] follows the event socket.

mod events;
mod server;
mod session;
mod tls;

use std::time::Duration;

use minicbor::{Decode, Encode};
use oxisoft_drive_proto::api::{
    AccountCreated, AppendCommit, AppendResult, Challenge, ChallengeRequest, CollectionInfo,
    Commits, CreateAccount, CreateCollection, Devices, ErrorBody, ErrorCode, Head, Keys, Missing,
    MissingRequest, PairingApproval, PairingCreated, PairingRequest, PairingState, PatchCollection,
    PutDevices, PutKeys, Recovery, ServerInfo, Session as Token, SessionRequest,
};
use oxisoft_drive_proto::{
    AccountId, ChunkId, CollectionId, Commit, DeviceId, HeadAttestation, LeaseId, PairingId, Seq,
    Signed,
};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, RETRY_AFTER};
use reqwest::{Method, StatusCode};

pub use events::{Events, Notice};
pub use server::HttpServer;
pub use session::Session;
pub use tls::{Trust, client_config, key_pin};

const CBOR: &str = "application/cbor";
const OCTETS: &str = "application/octet-stream";
/// How long connecting may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a request may take (the server's own limit).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Why a call failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApiError {
    /// The server answered with an error.
    #[error("server: {status} {code:?}: {message}")]
    Server {
        /// The HTTP status.
        status: u16,
        /// The error code.
        code: ErrorCode,
        /// The server's explanation.
        message: String,
        /// The current head, on a commit conflict.
        head: Option<Head>,
        /// How long to wait, when rate-limited.
        retry_after: Option<Duration>,
    },
    /// The server couldn't be reached, or the connection broke.
    #[error("network: {0}")]
    Network(String),
    /// TLS couldn't be set up, or the server's certificate wasn't trusted.
    #[error("TLS: {0}")]
    Tls(String),
    /// The answer didn't make sense.
    #[error("bad answer: {0}")]
    Decode(String),
}

impl ApiError {
    /// The error code, if the server answered.
    #[must_use]
    pub const fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Server { code, .. } => Some(*code),
            _ => None,
        }
    }
}

/// What a request carries.
enum Body {
    None,
    Cbor(Vec<u8>),
    Octets(Vec<u8>),
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

fn encode<T: Encode<()>>(value: &T) -> Result<Vec<u8>, ApiError> {
    minicbor::to_vec(value).map_err(|error| ApiError::Decode(error.to_string()))
}

fn decode<T: for<'b> Decode<'b, ()>>(bytes: &[u8]) -> Result<T, ApiError> {
    minicbor::decode(bytes).map_err(|error| ApiError::Decode(error.to_string()))
}

/// The HTTP API of one server.
#[derive(Debug, Clone)]
pub struct Api {
    http: reqwest::Client,
    origin: String,
    trust: Trust,
}

impl Api {
    /// The server at `origin` (`https://host[:port]`, exactly as the server's config names
    /// it, since devices sign it), trusted as `trust` says.
    ///
    /// # Errors
    ///
    /// [`ApiError::Tls`] if TLS can't be set up.
    pub fn new(origin: &str, trust: Trust) -> Result<Self, ApiError> {
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(client_config(trust)?)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|error| ApiError::Tls(error.to_string()))?;
        Ok(Self {
            http,
            origin: origin.trim_end_matches('/').to_owned(),
            trust,
        })
    }

    /// The server's origin.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// How the server's certificate is trusted.
    #[must_use]
    pub const fn trust(&self) -> Trust {
        self.trust
    }

    /// Sends a request; the body of a 2xx answer, or the server's error.
    async fn send(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Body,
    ) -> Result<Vec<u8>, ApiError> {
        let mut request = self.http.request(method, format!("{}{path}", self.origin));
        if let Some(token) = token {
            request = request.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        request = match body {
            Body::None => request,
            Body::Cbor(bytes) => request.header(CONTENT_TYPE, CBOR).body(bytes),
            Body::Octets(bytes) => request.header(CONTENT_TYPE, OCTETS).body(bytes),
        };
        let response = request.send().await.map_err(network)?;
        let status = response.status();
        let retry_after = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok())
            .map(Duration::from_secs);
        let bytes = response.bytes().await.map_err(network)?.to_vec();
        if status.is_success() {
            return Ok(bytes);
        }
        let body: ErrorBody = decode(&bytes).unwrap_or_else(|_| ErrorBody {
            code: if status == StatusCode::NOT_FOUND {
                ErrorCode::NotFound
            } else {
                ErrorCode::Internal
            },
            message: String::from_utf8_lossy(&bytes).into_owned(),
            head: None,
        });
        Err(ApiError::Server {
            status: status.as_u16(),
            code: body.code,
            message: body.message,
            head: body.head,
            retry_after,
        })
    }

    async fn call<T: for<'b> Decode<'b, ()>>(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Body,
    ) -> Result<T, ApiError> {
        decode(&self.send(method, path, token, body).await?)
    }

    async fn empty(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Body,
    ) -> Result<(), ApiError> {
        self.send(method, path, token, body).await.map(|_| ())
    }

    // ── without a session ───────────────────────────────────────────────────────────

    /// `GET /v1/info`.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn info(&self) -> Result<ServerInfo, ApiError> {
        self.call(Method::GET, "/v1/info", None, Body::None).await
    }

    /// `POST /v1/auth/challenge`.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn challenge(&self, device: DeviceId) -> Result<Challenge, ApiError> {
        let body = encode(&ChallengeRequest { device })?;
        self.call(Method::POST, "/v1/auth/challenge", None, Body::Cbor(body))
            .await
    }

    /// `POST /v1/auth/session`.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn session(&self, request: &SessionRequest) -> Result<Token, ApiError> {
        self.call(
            Method::POST,
            "/v1/auth/session",
            None,
            Body::Cbor(encode(request)?),
        )
        .await
    }

    /// `POST /v1/accounts`.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn create_account(
        &self,
        request: &CreateAccount,
    ) -> Result<AccountCreated, ApiError> {
        self.call(
            Method::POST,
            "/v1/accounts",
            None,
            Body::Cbor(encode(request)?),
        )
        .await
    }

    /// `GET /v1/accounts/{id}/recovery`.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn recovery(&self, account: AccountId) -> Result<Recovery, ApiError> {
        let path = format!("/v1/accounts/{}/recovery", hex(account.as_bytes()));
        self.call(Method::GET, &path, None, Body::None).await
    }

    /// `POST /v1/pairings`.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn create_pairing(
        &self,
        request: &PairingRequest,
    ) -> Result<PairingCreated, ApiError> {
        self.call(
            Method::POST,
            "/v1/pairings",
            None,
            Body::Cbor(encode(request)?),
        )
        .await
    }

    /// `GET /v1/pairings/{id}?wait=…`: waits up to `wait_s` (at most 30) for an approval.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn pairing(&self, id: PairingId, wait_s: u64) -> Result<PairingState, ApiError> {
        let path = format!("/v1/pairings/{}?wait={wait_s}", hex(id.as_bytes()));
        self.call(Method::GET, &path, None, Body::None).await
    }

    /// `PUT /v1/devices`, signed in (`token`) or, for recovery, signed by the account key
    /// only (`None`).
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn put_devices(
        &self,
        token: Option<&str>,
        request: &PutDevices,
    ) -> Result<Devices, ApiError> {
        self.call(
            Method::PUT,
            "/v1/devices",
            token,
            Body::Cbor(encode(request)?),
        )
        .await
    }

    // ── signed in ───────────────────────────────────────────────────────────────────

    /// `GET /v1/devices`.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn devices(&self, token: &str) -> Result<Devices, ApiError> {
        self.call(Method::GET, "/v1/devices", Some(token), Body::None)
            .await
    }

    /// `GET /v1/keys`.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn keys(&self, token: &str) -> Result<Keys, ApiError> {
        self.call(Method::GET, "/v1/keys", Some(token), Body::None)
            .await
    }

    /// `PUT /v1/keys`.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn put_keys(&self, token: &str, request: &PutKeys) -> Result<Keys, ApiError> {
        self.call(
            Method::PUT,
            "/v1/keys",
            Some(token),
            Body::Cbor(encode(request)?),
        )
        .await
    }

    /// `POST /v1/pairings/{id}/approve`.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn approve_pairing(
        &self,
        token: &str,
        id: PairingId,
        approval: &PairingApproval,
    ) -> Result<(), ApiError> {
        let path = format!("/v1/pairings/{}/approve", hex(id.as_bytes()));
        self.empty(
            Method::POST,
            &path,
            Some(token),
            Body::Cbor(encode(approval)?),
        )
        .await
    }

    /// `GET /v1/collections`.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn collections(&self, token: &str) -> Result<Vec<CollectionInfo>, ApiError> {
        self.call(Method::GET, "/v1/collections", Some(token), Body::None)
            .await
    }

    /// `POST /v1/collections`.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn create_collection(
        &self,
        token: &str,
        request: &CreateCollection,
    ) -> Result<(), ApiError> {
        self.empty(
            Method::POST,
            "/v1/collections",
            Some(token),
            Body::Cbor(encode(request)?),
        )
        .await
    }

    fn collection_path(collection: CollectionId, rest: &str) -> String {
        format!("/v1/collections/{}{rest}", hex(collection.as_bytes()))
    }

    /// `PATCH /v1/collections/{id}`.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn patch_collection(
        &self,
        token: &str,
        collection: CollectionId,
        request: &PatchCollection,
    ) -> Result<(), ApiError> {
        let path = Self::collection_path(collection, "");
        self.empty(
            Method::PATCH,
            &path,
            Some(token),
            Body::Cbor(encode(request)?),
        )
        .await
    }

    /// `DELETE /v1/collections/{id}`: to the trash.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn delete_collection(
        &self,
        token: &str,
        collection: CollectionId,
    ) -> Result<(), ApiError> {
        let path = Self::collection_path(collection, "");
        self.empty(Method::DELETE, &path, Some(token), Body::None)
            .await
    }

    /// `GET /v1/collections/{id}/head`.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn head(
        &self,
        token: &str,
        collection: CollectionId,
    ) -> Result<Option<Head>, ApiError> {
        let path = Self::collection_path(collection, "/head");
        self.call(Method::GET, &path, Some(token), Body::None).await
    }

    /// `GET /v1/collections/{id}/commits?after=…&limit=…`.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn commits(
        &self,
        token: &str,
        collection: CollectionId,
        after: Seq,
        limit: u32,
    ) -> Result<Commits, ApiError> {
        let path =
            Self::collection_path(collection, &format!("/commits?after={after}&limit={limit}"));
        self.call(Method::GET, &path, Some(token), Body::None).await
    }

    /// `POST /v1/collections/{id}/commits`. A stale `expected` head is
    /// [`AppendResult::Conflict`], not an error (sync protocol §2).
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn append(
        &self,
        token: &str,
        collection: CollectionId,
        expected: Option<Head>,
        commit: Commit,
    ) -> Result<AppendResult, ApiError> {
        let path = Self::collection_path(collection, "/commits");
        let body = encode(&AppendCommit { expected, commit })?;
        match self
            .call(Method::POST, &path, Some(token), Body::Cbor(body))
            .await
        {
            Err(ApiError::Server {
                code: ErrorCode::Conflict,
                head,
                ..
            }) => Ok(AppendResult::Conflict(head)),
            other => other,
        }
    }

    /// `POST /v1/collections/{id}/chunks/missing`.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn missing(
        &self,
        token: &str,
        collection: CollectionId,
        ids: Vec<ChunkId>,
    ) -> Result<Missing, ApiError> {
        let path = Self::collection_path(collection, "/chunks/missing");
        let body = encode(&MissingRequest { ids })?;
        self.call(Method::POST, &path, Some(token), Body::Cbor(body))
            .await
    }

    /// `PUT /v1/collections/{id}/chunks/{chunk}?lease=…`.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn put_chunk(
        &self,
        token: &str,
        collection: CollectionId,
        lease: LeaseId,
        id: ChunkId,
        object: Vec<u8>,
    ) -> Result<(), ApiError> {
        let path = Self::collection_path(
            collection,
            &format!(
                "/chunks/{}?lease={}",
                hex(id.0.as_bytes()),
                hex(lease.as_bytes())
            ),
        );
        self.empty(Method::PUT, &path, Some(token), Body::Octets(object))
            .await
    }

    /// `GET /v1/collections/{id}/chunks/{chunk}`.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn get_chunk(
        &self,
        token: &str,
        collection: CollectionId,
        id: ChunkId,
    ) -> Result<Vec<u8>, ApiError> {
        let path = Self::collection_path(collection, &format!("/chunks/{}", hex(id.0.as_bytes())));
        self.send(Method::GET, &path, Some(token), Body::None).await
    }

    /// `POST /v1/collections/{id}/heads`.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn attest(
        &self,
        token: &str,
        collection: CollectionId,
        attestation: &Signed<HeadAttestation>,
    ) -> Result<(), ApiError> {
        let path = Self::collection_path(collection, "/heads");
        self.empty(
            Method::POST,
            &path,
            Some(token),
            Body::Cbor(encode(attestation)?),
        )
        .await
    }

    /// `GET /v1/collections/{id}/heads`.
    ///
    /// # Errors
    ///
    /// [`ApiError`].
    pub async fn attestations(
        &self,
        token: &str,
        collection: CollectionId,
    ) -> Result<Vec<Signed<HeadAttestation>>, ApiError> {
        let path = Self::collection_path(collection, "/heads");
        self.call(Method::GET, &path, Some(token), Body::None).await
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "passed to `map_err`, which hands over the error"
)]
fn network(error: reqwest::Error) -> ApiError {
    // A certificate the server's name or pin didn't match shows up as a connect error;
    // its chain of sources names the TLS failure.
    let mut text = error.to_string();
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        text = format!("{text}: {cause}");
        source = cause.source();
    }
    if text.contains("certificate") || text.contains("Certificate") {
        ApiError::Tls(text)
    } else {
        ApiError::Network(text)
    }
}
