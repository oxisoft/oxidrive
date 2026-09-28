//! A shared world for multi-device tests: one server, one clock, one collection, and devices
//! with their own file system, index and engine.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oxisoft_drive_chunking::ChunkParams;
use oxisoft_drive_core::{
    CollectionKeys, Engine, EngineConfig, EngineError, FsRules, MassDeleteBrake, RelPath,
    SyncReport,
};
use oxisoft_drive_crypto::keys::CollectionKey;
use oxisoft_drive_crypto::sign::SigningKey;
use oxisoft_drive_proto::{CollectionId, DeviceId};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use crate::{ManualClock, MemFs, MemIndex, MemServer, block_on};

/// A folder's content: path → bytes, `None` for folders.
pub type Tree = BTreeMap<RelPath, Option<Vec<u8>>>;

/// The engine type every test device runs.
pub type DeviceEngine =
    Engine<Arc<MemFs>, Arc<MemServer>, Arc<MemIndex>, Arc<ManualClock>, ChaCha20Rng>;

/// One collection shared by several devices.
#[derive(Debug)]
pub struct World {
    /// The server.
    pub server: Arc<MemServer>,
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
pub struct Device {
    /// Its number in the world.
    pub number: usize,
    /// Its folder.
    pub fs: Arc<MemFs>,
    /// Its index.
    pub index: Arc<MemIndex>,
    /// Its engine.
    pub engine: DeviceEngine,
}

impl World {
    /// A world whose first `trusted + 1` device numbers may commit.
    #[must_use]
    pub fn new(rules: FsRules, trusted: usize) -> Self {
        Self {
            server: Arc::new(MemServer::new()),
            clock: Arc::new(ManualClock::new(1_790_000_000_000)),
            collection: CollectionId::from_bytes([9; 16]),
            rules,
            trusted,
            opened: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn signing_key(number: usize) -> SigningKey {
        let seed = u8::try_from(number + 1).unwrap_or(u8::MAX);
        SigningKey::generate(&mut ChaCha20Rng::from_seed([seed; 32]))
    }

    fn engine(
        &self,
        number: usize,
        fs: &Arc<MemFs>,
        index: &Arc<MemIndex>,
    ) -> Result<DeviceEngine, EngineError> {
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
    pub fn device(&self, number: usize) -> Result<Device, EngineError> {
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
    pub fn reopen(&self, device: &mut Device) -> Result<(), EngineError> {
        device.engine = self.engine(device.number, &device.fs, &device.index)?;
        Ok(())
    }
}

impl Device {
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
