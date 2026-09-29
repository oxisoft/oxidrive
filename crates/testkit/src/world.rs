//! A shared world for multi-device tests: one server, one clock, one collection, and devices
//! with their own file system, index and engine.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oxisoft_drive_chunking::ChunkParams;
use oxisoft_drive_core::{
    CollectionKeys, Engine, EngineConfig, EngineError, FsRules, MassDeleteBrake, RelPath,
    ServerApi, SyncReport,
};
use oxisoft_drive_crypto::keys::CollectionKey;
use oxisoft_drive_crypto::sign::SigningKey;
use oxisoft_drive_proto::{CollectionId, DeviceId};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use crate::{Flaky, ManualClock, MemFs, MemIndex, MemServer, block_on};

/// A folder's content: path → bytes, `None` for folders.
pub type Tree = BTreeMap<RelPath, Option<Vec<u8>>>;

/// The engine type every test device runs, on server `S`.
pub type DeviceEngine<S = MemServer> =
    Engine<Arc<MemFs>, Arc<Flaky<S>>, Arc<MemIndex>, Arc<ManualClock>, ChaCha20Rng>;

/// One collection shared by several devices, on server `S` (in memory by default), with
/// failure injection in front of it.
#[derive(Debug)]
pub struct World<S = MemServer> {
    /// The server.
    pub server: Arc<Flaky<S>>,
    /// The clock every device sees.
    pub clock: Arc<ManualClock>,
    /// The collection.
    pub collection: CollectionId,
    /// Name rules of every device's file system.
    pub rules: FsRules,
    /// How many devices are trusted (device numbers `0..=trusted`).
    pub trusted: usize,
    /// Engines opened so far: every engine gets its own random stream, as real ones draw from
    /// the operating system, so a restarted engine never repeats node IDs.
    opened: std::sync::atomic::AtomicU64,
}

/// One device.
#[derive(Debug)]
pub struct Device<S = MemServer> {
    /// Its number in the world.
    pub number: usize,
    /// Its folder.
    pub fs: Arc<MemFs>,
    /// Its index.
    pub index: Arc<MemIndex>,
    /// Its engine.
    pub engine: DeviceEngine<S>,
}

/// The collection every world syncs.
pub const COLLECTION: CollectionId = CollectionId::from_bytes([9; 16]);

impl World {
    /// A world on an in-memory server whose first `trusted + 1` device numbers may commit.
    #[must_use]
    pub fn new(rules: FsRules, trusted: usize) -> Self {
        Self::with_server(rules, trusted, MemServer::new())
    }
}

impl<S: ServerApi> World<S> {
    /// A world on `server`, whose first `trusted + 1` device numbers may commit.
    #[must_use]
    pub fn with_server(rules: FsRules, trusted: usize, server: S) -> Self {
        Self {
            server: Arc::new(Flaky::new(server)),
            clock: Arc::new(ManualClock::new(1_790_000_000_000)),
            collection: COLLECTION,
            rules,
            trusted,
            opened: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// The signing key of device `number` (the same in every world).
    #[must_use]
    pub fn signing_key(number: usize) -> SigningKey {
        let seed = u8::try_from(number + 1).unwrap_or(u8::MAX);
        SigningKey::generate(&mut ChaCha20Rng::from_seed([seed; 32]))
    }

    fn engine(
        &self,
        number: usize,
        fs: &Arc<MemFs>,
        index: &Arc<MemIndex>,
    ) -> Result<DeviceEngine<S>, EngineError> {
        let trusted = (0..=self.trusted)
            .map(|d| {
                let key = Self::signing_key(d).verifying_key();
                (DeviceId::from_key(&key), key)
            })
            .collect();
        let label = format!("d{number}");
        let config = EngineConfig {
            collection: self.collection,
            signing_key: Self::signing_key(number),
            // Every device unwraps the same collection key; a seeded RNG stands in for that.
            keys: CollectionKeys::new(CollectionKey::generate(
                &mut ChaCha20Rng::from_seed([77; 32]),
                0,
            )),
            trusted,
            // Small chunks, so small test files span several.
            chunk_params: ChunkParams::new(64, 256, 1024).unwrap_or(ChunkParams::DEFAULT),
            conflict_tag: Box::new(move |_| format!("conflict {label}")),
            is_ignored: Box::new(|_, _| false),
            brake: MassDeleteBrake::default(),
        };
        let instance = self
            .opened
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        block_on(Engine::open(
            Arc::clone(fs),
            Arc::clone(&self.server),
            Arc::clone(index),
            Arc::clone(&self.clock),
            ChaCha20Rng::seed_from_u64(instance),
            config,
        ))
    }

    /// A new device with an empty, initialised folder.
    ///
    /// # Errors
    ///
    /// If the engine can't be opened or the folder initialised.
    pub fn device(&self, number: usize) -> Result<Device<S>, EngineError> {
        let fs = Arc::new(MemFs::new(self.rules));
        let index = Arc::new(MemIndex::new());
        let engine = self.engine(number, &fs, &index)?;
        block_on(engine.init_folder())?;
        Ok(Device {
            number,
            fs,
            index,
            engine,
        })
    }

    /// Simulates a crash and restart: a fresh engine on the device's folder and index.
    ///
    /// # Errors
    ///
    /// If the engine can't be reopened from the index.
    pub fn reopen(&self, device: &mut Device<S>) -> Result<(), EngineError> {
        device.engine = self.engine(device.number, &device.fs, &device.index)?;
        Ok(())
    }
}

impl<S: ServerApi> Device<S> {
    /// One sync.
    ///
    /// # Errors
    ///
    /// Whatever the engine reports.
    pub fn sync(&mut self) -> Result<SyncReport, EngineError> {
        block_on(self.engine.sync_once(true))
    }

    /// The folder's content.
    #[must_use]
    pub fn tree(&self) -> Tree {
        self.fs.tree()
    }
}

/// Every file content of a tree.
#[must_use]
pub fn contents(tree: &Tree) -> BTreeSet<Vec<u8>> {
    tree.values().filter_map(Clone::clone).collect()
}
