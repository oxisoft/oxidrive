//! Collections as a whole, and head attestations (server API §5, crypto §8).

use oxisoft_drive_crypto::CryptoRng;
use oxisoft_drive_proto::api::{CollectionInfo, CreateCollection, PatchCollection};
use oxisoft_drive_proto::{
    AccountId, CollectionId, DeviceCertificate, Envelope, EnvelopeKind, HeadAttestation, Signed,
};
use oxisoft_drive_server_store::{MetaStore, NewCollection, StoredAttestation};

use super::accounts::{kind_code, stored_envelope};
use super::{Caller, Clock, Service, ServiceError, decode, encode, invalid};
use crate::blob::BlobStore;

impl<M, B, C, R> Service<M, B, C, R>
where
    M: MetaStore,
    B: BlobStore,
    C: Clock,
    R: CryptoRng + Send,
{
    /// The account's collections (not those in the trash), with their key envelopes, usage
    /// and head.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn collections(
        &self,
        account: AccountId,
    ) -> Result<Vec<CollectionInfo>, ServiceError> {
        self.active_account(account).await?;
        let envelopes = self.meta.envelopes(account).await?;
        let mut infos = Vec::new();
        for row in self.meta.collections(account).await? {
            let keys = envelopes
                .iter()
                .filter(|stored| {
                    stored.kind == kind_code(EnvelopeKind::CollectionKey)
                        && stored.collection == Some(row.id)
                })
                .map(|stored| decode::<Envelope>(&stored.encoded))
                .collect::<Result<Vec<_>, _>>()?;
            infos.push(CollectionInfo {
                id: row.id,
                keys,
                usage: self.meta.collection_usage(row.id).await?,
                head: self.meta.head(row.id).await?,
                config: row.config,
                retention_days: row.retention_days,
            });
        }
        Ok(infos)
    }

    /// Creates a collection with its key (wrapped with the account key) and sealed
    /// configuration, with the default retention.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Invalid`] if the key isn't this collection's key;
    /// [`ServiceError::Conflict`] if the ID is taken.
    pub async fn create_collection_with_key(
        &self,
        account: AccountId,
        request: &CreateCollection,
    ) -> Result<(), ServiceError> {
        self.active_account(account).await?;
        let key = &request.key;
        if key.kind != EnvelopeKind::CollectionKey
            || key.collection != Some(request.id)
            || key.device.is_some()
        {
            return Err(invalid("not this collection's key"));
        }
        let created = self
            .meta
            .create_collection(&NewCollection {
                id: request.id,
                account,
                config: request.config.clone(),
                retention_days: self.settings.default_retention_days,
                created_ms: self.clock.now_ms(),
                key: Some(stored_envelope(key)?),
            })
            .await;
        match created {
            Err(oxisoft_drive_server_store::StoreError::Duplicate) => {
                Err(ServiceError::Conflict(None))
            }
            other => Ok(other?),
        }
    }

    /// Changes a collection's retention and/or sealed configuration.
    ///
    /// # Errors
    ///
    /// [`ServiceError::NotFound`] for another account's or a trashed collection.
    pub async fn patch_collection(
        &self,
        account: AccountId,
        id: CollectionId,
        request: &PatchCollection,
    ) -> Result<(), ServiceError> {
        self.owned(account, id).await?;
        self.meta
            .update_collection(id, request.retention_days, request.config.as_deref())
            .await?;
        Ok(())
    }

    /// Moves a collection to the trash; garbage collection empties it after its retention.
    ///
    /// # Errors
    ///
    /// [`ServiceError::NotFound`] for another account's or a trashed collection.
    pub async fn delete_collection(
        &self,
        account: AccountId,
        id: CollectionId,
    ) -> Result<(), ServiceError> {
        self.owned(account, id).await?;
        self.meta.delete_collection(id, self.clock.now_ms()).await?;
        Ok(())
    }

    /// Stores the calling device's attestation of the newest head it has seen (crypto §8),
    /// signed by that device.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Invalid`] if it isn't the caller's, for this collection, validly
    /// signed.
    pub async fn put_attestation(
        &self,
        caller: Caller,
        collection: CollectionId,
        attestation: &Signed<HeadAttestation>,
    ) -> Result<(), ServiceError> {
        let (row, _) = self.owned(caller.account, collection).await?;
        let key = Self::account_key(&row)?;
        let certificate = self
            .meta
            .certificate(caller.account, caller.device)
            .await?
            .ok_or(ServiceError::Untrusted)?;
        let certificate =
            DeviceCertificate::verify(&decode(&certificate.signed)?, caller.account, &key)
                .map_err(invalid)?;
        let stated = attestation
            .verify(&certificate.verifying_key)
            .map_err(invalid)?;
        if stated.device != caller.device || stated.collection != collection {
            return Err(invalid("another device's or collection's attestation"));
        }
        self.meta
            .put_attestation(
                collection,
                &StoredAttestation {
                    device: caller.device,
                    signed: encode(attestation)?,
                },
            )
            .await?;
        Ok(())
    }

    /// Every device's latest attestation for a collection (server HTTP I4).
    ///
    /// # Errors
    ///
    /// [`ServiceError::NotFound`] for another account's or a trashed collection.
    pub async fn attestations(
        &self,
        account: AccountId,
        collection: CollectionId,
    ) -> Result<Vec<Signed<HeadAttestation>>, ServiceError> {
        self.owned(account, collection).await?;
        self.meta
            .attestations(collection)
            .await?
            .iter()
            .map(|stored| decode(&stored.signed))
            .collect()
    }
}
