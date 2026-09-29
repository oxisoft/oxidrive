//! Accounts, sign-in, devices, keys, recovery and pairing (server HTTP §3–§4): the rules
//! behind the endpoints that aren't about one collection's content.

use oxisoft_drive_crypto::CryptoRng;
use oxisoft_drive_crypto::hash;
use oxisoft_drive_crypto::sign::{SignContext, Signature, VerifyingKey};
use oxisoft_drive_proto::api::{
    Challenge, CreateAccount, Devices, Keys, PairingApproval, PairingCreated, PairingRequest,
    PairingState, PutDevices, PutKeys, Recovery, Session,
};
use oxisoft_drive_proto::{
    AccountId, CertificateHash, DeviceCertificate, DeviceId, DeviceList, Envelope, EnvelopeKind,
    PairingId, Signed, auth_message,
};
use oxisoft_drive_server_store::{
    MetaStore, NewAccount, PairingRow, SessionRow, StoreError, StoredCertificate, StoredDeviceList,
    StoredEnvelope,
};
use rand_core::Rng;

use super::{Clock, Service, ServiceError, decode, encode, invalid};
use crate::blob::BlobStore;

/// A signed-in device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caller {
    /// Its account.
    pub account: AccountId,
    /// The device.
    pub device: DeviceId,
}

/// The stored code of an envelope kind (the same numbers as on the wire).
pub(super) const fn kind_code(kind: EnvelopeKind) -> u8 {
    match kind {
        EnvelopeKind::AccountKeyToDevice => 0,
        EnvelopeKind::AccountKeyToRecovery => 1,
        EnvelopeKind::OlderAccountKey => 2,
        EnvelopeKind::CollectionKey => 3,
        EnvelopeKind::AccountSigningKey => 4,
        EnvelopeKind::AccountKemKey => 5,
    }
}

/// An envelope as the store keeps it.
pub(super) fn stored_envelope(envelope: &Envelope) -> Result<StoredEnvelope, ServiceError> {
    Ok(StoredEnvelope {
        kind: kind_code(envelope.kind),
        epoch: envelope.epoch,
        device: envelope.device,
        collection: envelope.collection,
        encoded: encode(envelope)?,
    })
}

/// The key under which a secret (an invite code, a session token) is stored.
fn secret_hash(secret: &str) -> [u8; 32] {
    *hash::hash(secret.as_bytes()).as_bytes()
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(2 * bytes.len()), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

impl<M, B, C, R> Service<M, B, C, R>
where
    M: MetaStore,
    B: BlobStore,
    C: Clock,
    R: CryptoRng + Send,
{
    fn random<const N: usize>(&self) -> [u8; N] {
        let mut bytes = [0; N];
        self.rng
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .fill_bytes(&mut bytes);
        bytes
    }

    /// An account's current device list, as verified with its key.
    async fn current_list(
        &self,
        account: AccountId,
        key: &VerifyingKey,
    ) -> Result<Option<DeviceList>, ServiceError> {
        match self.meta.device_list(account).await? {
            Some(stored) => Ok(Some(
                decode::<Signed<DeviceList>>(&stored.signed)?
                    .verify(key)
                    .map_err(invalid)?,
            )),
            None => Ok(None),
        }
    }

    // ── invites and accounts ────────────────────────────────────────────────────────

    /// A new one-time invite code, valid for `valid_ms` (for the admin CLI).
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn create_invite(&self, valid_ms: u64) -> Result<String, ServiceError> {
        let code = hex(&self.random::<16>());
        let expires = self.clock.now_ms().saturating_add(valid_ms);
        self.meta.create_invite(secret_hash(&code), expires).await?;
        Ok(code)
    }

    /// Creates an account with an invite (server API §3). Everything must be signed by the
    /// new account key: its KEM key, the first device's certificate, and a first list that
    /// trusts exactly that device. The envelopes are the first device's account key, the
    /// recovery envelope and the wrapped account keys, all of epoch 0.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Forbidden`] for an unknown, used or expired invite;
    /// [`ServiceError::Invalid`] for anything inconsistent; [`ServiceError::Conflict`] if the
    /// account exists.
    pub async fn create_account_by_invite(
        &self,
        request: &CreateAccount,
    ) -> Result<AccountId, ServiceError> {
        let (account, key) = (request.account, &request.signing_key);
        let kem = request.kem_key.verify(key).map_err(invalid)?;
        if kem.account != account {
            return Err(invalid("KEM key of another account"));
        }
        let certificate =
            DeviceCertificate::verify(&request.first_device, account, key).map_err(invalid)?;
        let list = request.list.verify(key).map_err(invalid)?;
        list.check_update(None).map_err(invalid)?;
        let only_first = list.devices.len() == 1
            && list.devices[0].device == certificate.device
            && list.devices[0].certificate == CertificateHash(request.first_device.hash());
        if list.account != account || list.version != 1 || !list.revoked.is_empty() || !only_first {
            return Err(invalid(
                "the first list must trust exactly the first device",
            ));
        }
        let mut kinds = Vec::new();
        for envelope in &request.envelopes {
            let allowed = match envelope.kind {
                EnvelopeKind::AccountKeyToDevice => envelope.device == Some(certificate.device),
                EnvelopeKind::AccountKeyToRecovery
                | EnvelopeKind::AccountSigningKey
                | EnvelopeKind::AccountKemKey => envelope.device.is_none(),
                EnvelopeKind::OlderAccountKey | EnvelopeKind::CollectionKey => false,
            };
            if !allowed || envelope.epoch != 0 || envelope.collection.is_some() {
                return Err(invalid("unexpected envelope for a new account"));
            }
            kinds.push(envelope.kind);
        }
        let needed = [
            EnvelopeKind::AccountKeyToDevice,
            EnvelopeKind::AccountKeyToRecovery,
            EnvelopeKind::AccountSigningKey,
        ];
        if !needed.iter().all(|kind| kinds.contains(kind)) {
            return Err(invalid(
                "a new account needs its device, recovery and signing key envelopes",
            ));
        }
        let envelopes = request
            .envelopes
            .iter()
            .map(stored_envelope)
            .collect::<Result<Vec<_>, _>>()?;
        let now = self.clock.now_ms();
        let created = self
            .meta
            .create_account_by_invite(
                secret_hash(&request.invite),
                now,
                &NewAccount {
                    id: account,
                    signing_key: key.to_bytes().to_vec(),
                    kem_key: encode(&request.kem_key)?,
                    quota_bytes: self.settings.default_quota,
                    created_ms: now,
                },
                &StoredDeviceList {
                    version: 1,
                    signed: encode(&request.list)?,
                },
                &StoredCertificate {
                    device: certificate.device,
                    signed: encode(&request.first_device)?,
                },
                &envelopes,
            )
            .await;
        match created {
            Ok(()) => Ok(account),
            Err(StoreError::NotFound) => Err(ServiceError::Forbidden(
                "invite unknown, used or expired".into(),
            )),
            Err(StoreError::Duplicate) => Err(ServiceError::Conflict(None)),
            Err(error) => Err(error.into()),
        }
    }

    // ── sign-in ─────────────────────────────────────────────────────────────────────

    /// A challenge for `device` to sign (server API §2). Unknown devices get one too, which
    /// they can't use, so the answer tells nobody which devices exist.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn challenge(&self, device: DeviceId) -> Result<Challenge, ServiceError> {
        let nonce = self.random::<32>();
        let expires_ms = self
            .clock
            .now_ms()
            .saturating_add(self.settings.challenge_ms);
        if self.meta.account_of_device(device).await?.is_some() {
            self.meta.put_challenge(device, nonce, expires_ms).await?;
        }
        Ok(Challenge { nonce, expires_ms })
    }

    /// Signs a device in: its unused, unexpired challenge, signed for this server's
    /// `origin`, by a device its account trusts. Returns a new session token.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Unauthorized`] for anything wrong with the answer or the device;
    /// [`ServiceError::Disabled`] for a disabled account.
    pub async fn sign_in(
        &self,
        device: DeviceId,
        nonce: &[u8; 32],
        signature: &Signature,
        origin: &str,
    ) -> Result<Session, ServiceError> {
        // Used up whatever happens next.
        let challenge = self.meta.take_challenge(device).await?;
        let now = self.clock.now_ms();
        if !challenge.is_some_and(|(stored, expires)| stored == *nonce && now < expires) {
            return Err(ServiceError::Unauthorized);
        }
        let account = self
            .meta
            .account_of_device(device)
            .await?
            .ok_or(ServiceError::Unauthorized)?;
        let row = self.active_account(account).await?;
        let key = Self::account_key(&row)?;
        if !self
            .current_list(account, &key)
            .await?
            .is_some_and(|list| list.is_trusted(&device))
        {
            return Err(ServiceError::Unauthorized);
        }
        let certificate = self
            .meta
            .certificate(account, device)
            .await?
            .ok_or(ServiceError::Unauthorized)?;
        let certificate = DeviceCertificate::verify(&decode(&certificate.signed)?, account, &key)
            .map_err(invalid)?;
        certificate
            .verifying_key
            .verify(
                SignContext::AuthChallenge,
                &auth_message(origin, nonce, device),
                signature,
            )
            .map_err(|_| ServiceError::Unauthorized)?;
        let token = hex(&self.random::<32>());
        let expires_ms = now.saturating_add(self.settings.session_ms);
        self.meta
            .create_session(
                secret_hash(&token),
                &SessionRow {
                    account,
                    device,
                    expires_ms,
                },
            )
            .await?;
        Ok(Session { token, expires_ms })
    }

    /// The device behind a session token.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Unauthorized`] for an unknown or expired token;
    /// [`ServiceError::Disabled`] for a disabled account.
    pub async fn authenticate(&self, token: &str) -> Result<Caller, ServiceError> {
        let session = self
            .meta
            .session(secret_hash(token))
            .await?
            .filter(|session| self.clock.now_ms() < session.expires_ms)
            .ok_or(ServiceError::Unauthorized)?;
        self.active_account(session.account).await?;
        Ok(Caller {
            account: session.account,
            device: session.device,
        })
    }

    // ── devices ─────────────────────────────────────────────────────────────────────

    /// The account's signed device list and the certificates of its listed devices.
    ///
    /// # Errors
    ///
    /// [`ServiceError::NotFound`] if the account has no list.
    pub async fn devices(&self, account: AccountId) -> Result<Devices, ServiceError> {
        self.active_account(account).await?;
        let stored = self
            .meta
            .device_list(account)
            .await?
            .ok_or(ServiceError::NotFound)?;
        let list: Signed<DeviceList> = decode(&stored.signed)?;
        let listed = list.decode_unverified().map_err(invalid)?;
        let certificates = self
            .meta
            .certificates(account)
            .await?
            .into_iter()
            .filter(|certificate| {
                listed
                    .devices
                    .iter()
                    .any(|entry| entry.device == certificate.device)
            })
            .map(|certificate| decode(&certificate.signed))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Devices { list, certificates })
    }

    /// Replaces the device list (server API §4): by a signed-in device of the account
    /// (`caller`), or with no session by whoever holds the account key, as a device restored
    /// from the recovery key does (server HTTP I2). The envelopes must be account keys for
    /// devices the new list trusts. Returns the new list.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Forbidden`] for another account's list; otherwise as
    /// [`Service::put_device_list`].
    pub async fn put_devices(
        &self,
        caller: Option<Caller>,
        request: &PutDevices,
    ) -> Result<DeviceList, ServiceError> {
        let account = request.list.decode_unverified().map_err(invalid)?.account;
        if caller.is_some_and(|caller| caller.account != account) {
            return Err(ServiceError::Forbidden("another account's list".into()));
        }
        let claimed = request.list.decode_unverified().map_err(invalid)?;
        for envelope in &request.envelopes {
            let for_trusted = envelope.kind == EnvelopeKind::AccountKeyToDevice
                && envelope.collection.is_none()
                && envelope
                    .device
                    .is_some_and(|device| claimed.is_trusted(&device));
            if !for_trusted {
                return Err(invalid("only account keys for trusted devices"));
            }
        }
        let envelopes = request
            .envelopes
            .iter()
            .map(stored_envelope)
            .collect::<Result<Vec<_>, _>>()?;
        let expected = self
            .meta
            .device_list(account)
            .await?
            .map(|stored| stored.version);
        self.replace_device_list(
            account,
            expected,
            &request.list,
            &request.new_certificates,
            &envelopes,
        )
        .await
    }

    // ── keys ────────────────────────────────────────────────────────────────────────

    /// Every envelope the calling device needs: its own account keys, the account's other
    /// wrapped keys and every collection key. Other devices' and the recovery envelopes stay
    /// on the server.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn keys(&self, caller: Caller) -> Result<Keys, ServiceError> {
        let envelopes = self
            .meta
            .envelopes(caller.account)
            .await?
            .into_iter()
            .filter(|stored| match stored.kind {
                0 => stored.device == Some(caller.device),
                1 => false,
                _ => true,
            })
            .map(|stored| decode(&stored.encoded))
            .collect::<Result<Vec<Envelope>, _>>()?;
        Ok(Keys { envelopes })
    }

    /// Adds a new key epoch (crypto §5.3): one batch of envelopes of that epoch, carrying the
    /// account key for every trusted device and for recovery, and the link to the previous
    /// account key.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Invalid`] for a batch that misses one of those or carries another
    /// epoch; [`ServiceError::Conflict`] unless the epoch follows the newest.
    pub async fn put_keys(&self, caller: Caller, request: &PutKeys) -> Result<u32, ServiceError> {
        let row = self.active_account(caller.account).await?;
        let key = Self::account_key(&row)?;
        let list = self
            .current_list(caller.account, &key)
            .await?
            .ok_or(ServiceError::NotFound)?;
        if request
            .envelopes
            .iter()
            .any(|envelope| envelope.epoch != request.epoch)
        {
            return Err(invalid("envelopes of another epoch"));
        }
        let has = |kind: EnvelopeKind, device: Option<DeviceId>| {
            request
                .envelopes
                .iter()
                .any(|envelope| envelope.kind == kind && envelope.device == device)
        };
        let complete = list
            .devices
            .iter()
            .all(|entry| has(EnvelopeKind::AccountKeyToDevice, Some(entry.device)))
            && has(EnvelopeKind::AccountKeyToRecovery, None)
            && has(EnvelopeKind::OlderAccountKey, None);
        let stray = request.envelopes.iter().any(|envelope| {
            envelope.kind == EnvelopeKind::AccountKeyToDevice
                && !envelope
                    .device
                    .is_some_and(|device| list.is_trusted(&device))
        });
        if !complete || stray {
            return Err(invalid(
                "a new epoch needs the account key for every trusted device, recovery and the older key",
            ));
        }
        let envelopes = request
            .envelopes
            .iter()
            .map(stored_envelope)
            .collect::<Result<Vec<_>, _>>()?;
        match self
            .meta
            .add_epoch(caller.account, request.epoch, &envelopes)
            .await
        {
            Ok(()) => Ok(request.epoch),
            Err(StoreError::Conflict) => Err(ServiceError::Conflict(None)),
            Err(error) => Err(error.into()),
        }
    }

    /// What a device restoring the account with its recovery key needs (server API §4.1):
    /// the newest recovery envelope, the newest wrapped signing key, and its public half.
    ///
    /// # Errors
    ///
    /// [`ServiceError::NotFound`] for an unknown account or one without those envelopes.
    pub async fn recovery(&self, account: AccountId) -> Result<Recovery, ServiceError> {
        let row = self.active_account(account).await?;
        let envelopes = self.meta.envelopes(account).await?;
        let newest = |kind: EnvelopeKind| {
            envelopes
                .iter()
                .filter(|stored| stored.kind == kind_code(kind))
                .max_by_key(|stored| stored.epoch)
                .map(|stored| decode::<Envelope>(&stored.encoded))
                .transpose()?
                .ok_or(ServiceError::NotFound)
        };
        Ok(Recovery {
            account_key: newest(EnvelopeKind::AccountKeyToRecovery)?,
            signing_key: newest(EnvelopeKind::AccountSigningKey)?,
            signing_public: Self::account_key(&row)?,
        })
    }

    // ── pairing ─────────────────────────────────────────────────────────────────────

    /// Records a new device waiting to be approved (server API §4.1).
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn create_pairing(
        &self,
        request: &PairingRequest,
    ) -> Result<PairingCreated, ServiceError> {
        let pairing = PairingId::from_bytes(self.random::<16>());
        let expires_ms = self.clock.now_ms().saturating_add(self.settings.pairing_ms);
        self.meta
            .create_pairing(&PairingRow {
                id: pairing,
                request: encode(request)?,
                expires_ms,
                approval: None,
            })
            .await?;
        Ok(PairingCreated {
            pairing,
            expires_ms,
        })
    }

    /// Where a pairing stands: pending (with the new device's keys, for the approving device
    /// to check), approved (with what the new device needs), or expired.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn pairing_state(&self, id: PairingId) -> Result<PairingState, ServiceError> {
        let Some(row) = self
            .meta
            .pairing(id)
            .await?
            .filter(|row| self.clock.now_ms() < row.expires_ms)
        else {
            return Ok(PairingState::Expired);
        };
        Ok(match row.approval {
            Some(approval) => PairingState::Approved(Box::new(decode(&approval)?)),
            None => PairingState::Pending(Box::new(decode(&row.request)?)),
        })
    }

    /// Approves a pairing from a signed-in device of the account the new device joins. The
    /// certificate must be for exactly the keys the new device sent, signed by the account
    /// key, and the device already trusted by the current list (the approving device puts
    /// the new list first). The pairing MAC is for the new device to check; the server
    /// doesn't know the secret.
    ///
    /// # Errors
    ///
    /// [`ServiceError::NotFound`] for an unknown, expired or already approved pairing;
    /// [`ServiceError::Forbidden`] for another account; [`ServiceError::Invalid`] otherwise.
    pub async fn approve_pairing(
        &self,
        caller: Caller,
        id: PairingId,
        approval: &PairingApproval,
    ) -> Result<(), ServiceError> {
        let now = self.clock.now_ms();
        let row = self
            .meta
            .pairing(id)
            .await?
            .filter(|row| now < row.expires_ms && row.approval.is_none())
            .ok_or(ServiceError::NotFound)?;
        let request: PairingRequest = decode(&row.request)?;
        let account = self.active_account(caller.account).await?;
        let key = Self::account_key(&account)?;
        if approval.account != caller.account || approval.signing_key != key {
            return Err(ServiceError::Forbidden("another account".into()));
        }
        let certificate = DeviceCertificate::verify(&approval.certificate, caller.account, &key)
            .map_err(invalid)?;
        if certificate.verifying_key != request.verifying_key
            || certificate.kem_key != request.kem_key
        {
            return Err(invalid("the certificate is for other keys"));
        }
        if !self
            .current_list(caller.account, &key)
            .await?
            .is_some_and(|list| list.is_trusted(&certificate.device))
        {
            return Err(invalid("add the device to the list before approving"));
        }
        if self
            .meta
            .approve_pairing(id, &encode(approval)?, now)
            .await?
        {
            Ok(())
        } else {
            Err(ServiceError::NotFound)
        }
    }
}
