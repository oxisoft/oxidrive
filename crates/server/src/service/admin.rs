//! Administration (server binary §4, §6): what the admin CLI does to accounts, the server's
//! heartbeat, and the repairs fsck and a restore make.

use oxisoft_drive_crypto::CryptoRng;
use oxisoft_drive_proto::{AccountId, DeviceList, Signed};
use oxisoft_drive_server_store::{AccountRow, AccountStatus, MetaStore, StoreError};

use super::{Clock, FsckReport, Service, ServiceError, decode, invalid};
use crate::blob::{BlobKey, BlobStore};

/// An account as `user list` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSummary {
    /// The stored account.
    pub account: AccountRow,
    /// Devices its current list trusts.
    pub devices: usize,
}

/// What [`Service::repair_after_restore`] found and did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoreReport {
    /// Chunks whose object the backup didn't have, but which were garbage already (marked,
    /// unreferenced): forgotten.
    pub forgotten: u64,
    /// Objects no chunk lists (uploads after the snapshot): deleted.
    pub orphans_removed: u64,
    /// Chunks still in use whose object is missing: the backup is broken.
    pub missing_objects: Vec<BlobKey>,
    /// Objects whose size differs from the database's.
    pub wrong_sizes: Vec<BlobKey>,
}

impl RestoreReport {
    /// Whether the restored server is consistent.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.missing_objects.is_empty() && self.wrong_sizes.is_empty()
    }
}

impl<M, B, C, R> Service<M, B, C, R>
where
    M: MetaStore,
    B: BlobStore,
    C: Clock,
    R: CryptoRng + Send,
{
    /// Every account, deleted ones included, with how many devices it trusts.
    ///
    /// # Errors
    ///
    /// Store failures, or a stored device list that doesn't decode.
    pub async fn accounts(&self) -> Result<Vec<AccountSummary>, ServiceError> {
        let mut summaries = Vec::new();
        for account in self.meta.accounts().await? {
            let devices = match self.meta.device_list(account.id).await? {
                Some(stored) => {
                    let list: DeviceList = decode::<Signed<DeviceList>>(&stored.signed)?
                        .decode_unverified()
                        .map_err(invalid)?;
                    list.devices
                        .iter()
                        .filter(|entry| list.is_trusted(&entry.device))
                        .count()
                }
                None => 0,
            };
            summaries.push(AccountSummary { account, devices });
        }
        Ok(summaries)
    }

    /// Enables or disables an account. Disabling signs its devices out at once.
    ///
    /// # Errors
    ///
    /// [`ServiceError::NotFound`]; [`ServiceError::Forbidden`] for a deleted account.
    pub async fn set_account_status(
        &self,
        id: AccountId,
        status: AccountStatus,
    ) -> Result<(), ServiceError> {
        self.meta
            .set_account_status(id, status)
            .await
            .map_err(|error| match error {
                StoreError::NotFound => ServiceError::NotFound,
                StoreError::Conflict => ServiceError::Forbidden("the account is deleted".into()),
                other => other.into(),
            })
    }

    /// Sets an account's quota. Data already stored stays, even over the new quota.
    ///
    /// # Errors
    ///
    /// [`ServiceError::NotFound`].
    pub async fn set_quota(&self, id: AccountId, quota_bytes: u64) -> Result<(), ServiceError> {
        self.meta
            .set_quota(id, quota_bytes)
            .await
            .map_err(|error| match error {
                StoreError::NotFound => ServiceError::NotFound,
                other => other.into(),
            })
    }

    /// Deletes a disabled account (J7): its collections go to the trash with no retention,
    /// so the next garbage collections free its data.
    ///
    /// # Errors
    ///
    /// [`ServiceError::NotFound`]; [`ServiceError::Forbidden`] unless it is disabled.
    pub async fn delete_account(&self, id: AccountId) -> Result<(), ServiceError> {
        self.meta
            .delete_account(id, self.clock.now_ms())
            .await
            .map_err(|error| match error {
                StoreError::NotFound => ServiceError::NotFound,
                StoreError::Conflict => {
                    ServiceError::Forbidden("only a disabled account can be deleted".into())
                }
                other => other.into(),
            })
    }

    /// Records that the process `name` is alive now.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn beat(&self, name: &str) -> Result<(), ServiceError> {
        Ok(self.meta.beat(name, self.clock.now_ms()).await?)
    }

    /// Forgets `name`'s heartbeat, when it stops.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn stop_beat(&self, name: &str) -> Result<(), ServiceError> {
        Ok(self.meta.stop_beat(name).await?)
    }

    /// Whether `name` recorded a heartbeat within the last `within_ms`.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn is_alive(&self, name: &str, within_ms: u64) -> Result<bool, ServiceError> {
        let now = self.clock.now_ms();
        Ok(self
            .meta
            .last_beat(name)
            .await?
            .is_some_and(|beat| now.saturating_sub(beat) < within_ms))
    }

    /// Deletes the objects fsck found without a chunk row. Only safe while no server runs:
    /// an upload writes its object before its row.
    ///
    /// # Errors
    ///
    /// Blob store failures.
    pub async fn remove_orphans(&self, report: &FsckReport) -> Result<u64, ServiceError> {
        for key in &report.orphan_objects {
            self.blobs.delete(key).await?;
        }
        Ok(report.orphan_objects.len() as u64)
    }

    /// Makes a freshly restored server consistent (server binary §6). The backup copied the
    /// objects after its database snapshot, so:
    /// - a chunk the snapshot lists without an object was garbage already, marked longer
    ///   ago than the backup took; it is forgotten;
    /// - an object no chunk lists was uploaded after the snapshot; it is deleted.
    ///
    /// Anything else missing means the backup is broken, and the report says so.
    ///
    /// # Errors
    ///
    /// Store and blob store failures.
    pub async fn repair_after_restore(&self) -> Result<RestoreReport, ServiceError> {
        let fsck = self.fsck().await?;
        let mut report = RestoreReport {
            orphans_removed: self.remove_orphans(&fsck).await?,
            wrong_sizes: fsck.wrong_sizes,
            ..RestoreReport::default()
        };
        let now = self.clock.now_ms();
        for key in fsck.missing_objects {
            let row = self.meta.chunk(key.collection, key.chunk.into()).await?;
            let forgotten = match row {
                Some(row) if row.garbage_ms.is_some() => !self
                    .meta
                    .forget_chunks(&[row], now, u64::MAX)
                    .await?
                    .is_empty(),
                _ => false,
            };
            if forgotten {
                report.forgotten += 1;
            } else {
                report.missing_objects.push(key);
            }
        }
        Ok(report)
    }
}
