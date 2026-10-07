//! The real server's rules and stores behind core's [`ServerApi`] (server storage §5), so
//! engine tests and the simulator run against SQLite or PostgreSQL as well as [`MemServer`].
//!
//! [`MemServer`]: crate::MemServer

use std::future::Future;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use oxisoft_drive_core::{ServerApi, ServerError};
use oxisoft_drive_crypto::keys::{AccountKey, AccountSigningKey, DeviceIdentity};
use oxisoft_drive_proto::api::{AppendResult, Commits, Head, Missing};
use oxisoft_drive_proto::{
    AccountId, CertificateHash, ChunkId, CollectionId, Commit, DEVICE_FORMAT, DeviceCertificate,
    DeviceEntry, DeviceId, DeviceList, LeaseId, Seq, Signed,
};
use oxisoft_drive_server::{FsBlobStore, Service, ServiceError, Settings, SystemClock};
use oxisoft_drive_server_postgres::PostgresStore;
use oxisoft_drive_server_sqlite::SqliteStore;
use oxisoft_drive_server_store::MetaStore;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sqlx::Connection;

use crate::world::{COLLECTION, World};

/// The service type behind a [`ServiceServer`].
type RealService<M> = Service<M, FsBlobStore, SystemClock, ChaCha20Rng>;

/// Core's [`ServerApi`] on the real service, for one account that trusts devices
/// `0..=trusted` of a [`World`] and owns its collection.
#[derive(Debug)]
pub struct ServiceServer<M> {
    service: RealService<M>,
    runtime: tokio::runtime::Runtime,
    account: AccountId,
    /// The temporary data directory, removed with the server, if it made one.
    temporary: Option<tempfile::TempDir>,
}

/// The account every [`ServiceServer`] sets up.
pub const ACCOUNT: AccountId = AccountId::from_bytes([5; 16]);

/// Why a real server couldn't be set up.
#[derive(Debug, thiserror::Error)]
#[error("setting up the server: {0}")]
pub struct SetupError(String);

fn setup(error: impl std::fmt::Display) -> SetupError {
    SetupError(error.to_string())
}

impl ServiceServer<SqliteStore> {
    /// A server on a new SQLite database in a temporary directory.
    ///
    /// # Errors
    ///
    /// If the database or the account can't be set up.
    pub fn sqlite(trusted: usize) -> Result<Self, SetupError> {
        let dir = tempfile::tempdir().map_err(setup)?;
        let mut server = Self::sqlite_at(dir.path(), Some(trusted), Settings::default())?;
        server.temporary = Some(dir);
        Ok(server)
    }

    /// A server in `data_dir` laid out as the server binary lays it out (`meta.sqlite`,
    /// `objects/`): new with `trusted` devices, or `None` for an existing one, such as a
    /// restored server.
    ///
    /// # Errors
    ///
    /// If the database or the account can't be set up.
    pub fn sqlite_at(
        data_dir: &Path,
        trusted: Option<usize>,
        settings: Settings,
    ) -> Result<Self, SetupError> {
        std::fs::create_dir_all(data_dir).map_err(setup)?;
        let runtime = runtime()?;
        let store = runtime
            .block_on(SqliteStore::open(&data_dir.join("meta.sqlite")))
            .map_err(setup)?;
        Self::new(store, runtime, data_dir, trusted, settings)
    }
}

/// Creates a new database on the PostgreSQL server at `base_url` (whose user may create
/// databases) and returns its URL.
///
/// # Errors
///
/// If the database can't be created.
pub async fn new_postgres_database(base_url: &str) -> Result<String, SetupError> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let name = format!(
        "sim{}_{}_{}",
        std::process::id(),
        stamp,
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let (prefix, _) = base_url
        .rsplit_once('/')
        .ok_or_else(|| setup("a PostgreSQL URL ends in /database"))?;
    let mut admin = sqlx::PgConnection::connect(base_url).await.map_err(setup)?;
    // The name is made of letters, digits and underscores only.
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .execute(&mut admin)
        .await
        .map_err(setup)?;
    Ok(format!("{prefix}/{name}"))
}

impl ServiceServer<PostgresStore> {
    /// A server on a new database of the PostgreSQL server at `base_url` (whose user may
    /// create databases).
    ///
    /// # Errors
    ///
    /// If the database or the account can't be set up.
    pub fn postgres(base_url: &str, trusted: usize) -> Result<Self, SetupError> {
        let dir = tempfile::tempdir().map_err(setup)?;
        let url = runtime()?.block_on(new_postgres_database(base_url))?;
        let mut server = Self::postgres_at(&url, dir.path(), Some(trusted), Settings::default())?;
        server.temporary = Some(dir);
        Ok(server)
    }

    /// A server on the PostgreSQL database at `url` with its objects in `data_dir/objects`:
    /// new with `trusted` devices, or `None` for an existing one, such as a restored server.
    ///
    /// # Errors
    ///
    /// If the database or the account can't be set up.
    pub fn postgres_at(
        url: &str,
        data_dir: &Path,
        trusted: Option<usize>,
        settings: Settings,
    ) -> Result<Self, SetupError> {
        let runtime = runtime()?;
        let store = runtime.block_on(PostgresStore::open(url)).map_err(setup)?;
        Self::new(store, runtime, data_dir, trusted, settings)
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, SetupError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(setup)
}

impl<M: MetaStore> ServiceServer<M> {
    fn new(
        store: M,
        runtime: tokio::runtime::Runtime,
        data_dir: &Path,
        trusted: Option<usize>,
        settings: Settings,
    ) -> Result<Self, SetupError> {
        // Each server its own random stream, as real ones draw from the operating system: a
        // restored server must not repeat the lease IDs its snapshot holds.
        static SERVERS: AtomicU64 = AtomicU64::new(0);
        let blobs = FsBlobStore::new(&data_dir.join("objects")).map_err(setup)?;
        let service = Service::new(
            store,
            blobs,
            SystemClock,
            ChaCha20Rng::seed_from_u64(SERVERS.fetch_add(1, Ordering::Relaxed)),
            settings,
        );
        let account = ACCOUNT;
        let Some(trusted) = trusted else {
            return Ok(Self {
                service,
                runtime,
                account,
                temporary: None,
            });
        };
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let signing = AccountSigningKey::generate(&mut rng);
        let meta = AccountKey::generate(&mut rng, 0).meta();
        let certificates: Vec<Signed<DeviceCertificate>> = (0..=trusted)
            .map(|number| {
                let key = World::<crate::MemServer>::signing_key(number).verifying_key();
                let kem = DeviceIdentity::generate(&mut rng).kem_public_key();
                DeviceCertificate::new(account, (key, kem), "device", &meta, &mut rng, 0)
                    .map(|certificate| Signed::sign(signing.signing_key(), &certificate))
                    .map_err(setup)
            })
            .collect::<Result<_, _>>()?;
        let list = DeviceList {
            format: DEVICE_FORMAT,
            account,
            version: 1,
            devices: certificates
                .iter()
                .map(|signed| {
                    let device: DeviceId = signed.decode_unverified().map_err(setup)?.device;
                    Ok(DeviceEntry {
                        device,
                        certificate: CertificateHash(signed.hash()),
                    })
                })
                .collect::<Result<_, SetupError>>()?,
            revoked: Vec::new(),
        };
        let list = Signed::sign(signing.signing_key(), &list);
        runtime
            .block_on(async {
                service
                    .create_account(account, &signing.verifying_key(), u64::MAX / 2)
                    .await?;
                service
                    .put_device_list(account, None, &list, &certificates)
                    .await?;
                service
                    .create_collection(account, COLLECTION, Vec::new(), 30)
                    .await
            })
            .map_err(setup)?;
        Ok(Self {
            service,
            runtime,
            account,
            temporary: None,
        })
    }

    /// The service, for checks such as fsck.
    #[must_use]
    pub const fn service(&self) -> &RealService<M> {
        &self.service
    }

    /// Runs a service call to completion on this server's runtime.
    pub fn run<T>(&self, future: impl Future<Output = T>) -> T {
        self.runtime.block_on(future)
    }
}

fn server_error(error: ServiceError) -> ServerError {
    match error {
        ServiceError::NotFound => ServerError::NotFound,
        ServiceError::Store(error) => ServerError::Unavailable(error.to_string()),
        ServiceError::Blob(error) => ServerError::Unavailable(error.to_string()),
        other => ServerError::Rejected(other.to_string()),
    }
}

impl<M: MetaStore> ServerApi for ServiceServer<M> {
    fn head(
        &self,
        collection: CollectionId,
    ) -> impl Future<Output = Result<Option<Head>, ServerError>> + Send {
        let result = self.run(self.service.head(self.account, collection));
        std::future::ready(result.map_err(server_error))
    }

    fn commits_after(
        &self,
        collection: CollectionId,
        after: Seq,
        limit: u32,
    ) -> impl Future<Output = Result<Commits, ServerError>> + Send {
        let result = self.run(
            self.service
                .commits_after(self.account, collection, after, limit),
        );
        std::future::ready(result.map_err(server_error))
    }

    fn append(
        &self,
        collection: CollectionId,
        expected: Option<Head>,
        commit: Commit,
    ) -> impl Future<Output = Result<AppendResult, ServerError>> + Send {
        let result =
            match self.run(
                self.service
                    .append(self.account, collection, expected, &commit),
            ) {
                Ok(head) => Ok(AppendResult::Appended(head)),
                Err(ServiceError::Conflict(current)) => Ok(AppendResult::Conflict(current)),
                Err(error) => Err(server_error(error)),
            };
        std::future::ready(result)
    }

    fn missing(
        &self,
        collection: CollectionId,
        ids: Vec<ChunkId>,
    ) -> impl Future<Output = Result<Missing, ServerError>> + Send {
        let result = self.run(self.service.missing(self.account, collection, &ids));
        std::future::ready(result.map_err(server_error))
    }

    fn put_chunk(
        &self,
        collection: CollectionId,
        lease: LeaseId,
        id: ChunkId,
        object: Vec<u8>,
    ) -> impl Future<Output = Result<(), ServerError>> + Send {
        let result = self.run(
            self.service
                .put_chunk(self.account, collection, lease, id, &object),
        );
        std::future::ready(result.map_err(server_error))
    }

    fn get_chunk(
        &self,
        collection: CollectionId,
        id: ChunkId,
    ) -> impl Future<Output = Result<Vec<u8>, ServerError>> + Send {
        let result = self.run(self.service.get_chunk(self.account, collection, id));
        std::future::ready(result.map_err(server_error))
    }
}
