//! The HTTP client against the real server in process (client foundation §5): every call,
//! sign-in and renewal, TLS with and without a pin, rate limits and error mapping.

#![cfg(test)]

use std::sync::Arc;
use std::time::Duration;

use oxisoft_drive_client::http::{Api, ApiError, HttpServer, Session, Trust, key_pin};
use oxisoft_drive_core::{ServerApi, ServerError};
use oxisoft_drive_crypto::hash::Digest;
use oxisoft_drive_crypto::keys::DeviceIdentity;
use oxisoft_drive_proto::api::{
    CreateCollection, ErrorCode, PairingRequest, PairingState, PatchCollection,
};
use oxisoft_drive_proto::{
    AccountId, ChunkId, CollectionId, CommitHash, DEVICE_FORMAT, Envelope, EnvelopeKind,
    HeadAttestation, LeaseId, PairingId, Signed,
};
use oxisoft_drive_testkit::http_server::{Prepared, certificate, device_key, prepare, start, stop};
use oxisoft_drive_testkit::{ACCOUNT, COLLECTION};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

fn session(prepared: &Prepared, number: usize) -> Arc<Session> {
    let api = Api::new(&prepared.origin, Trust::System).unwrap();
    Session::new(api, device_key(number))
}

fn code<T: std::fmt::Debug>(result: Result<T, ApiError>) -> ErrorCode {
    match result {
        Err(error) => error
            .code()
            .unwrap_or_else(|| panic!("no server answer: {error}")),
        Ok(value) => panic!("expected an error, got {value:?}"),
    }
}

#[test]
#[expect(clippy::too_many_lines, reason = "one walk through every call")]
fn every_call_reaches_the_server() {
    let prepared = prepare(1, None, "");
    runtime().block_on(async {
        let server = start(&prepared).await;
        let session = session(&prepared, 0);
        let api = session.api().clone();
        assert_eq!(api.origin(), prepared.origin);
        assert_eq!(api.trust(), Trust::System);
        let info = api.info().await.unwrap();
        assert!(info.limits.max_object > 0);

        // Signed in, the account's calls work.
        let token = session.token().await.unwrap();
        assert_eq!(session.token().await.unwrap(), token, "kept, not renewed");
        assert_eq!(
            session.device(),
            oxisoft_drive_proto::DeviceId::from_key(&device_key(0).verifying_key())
        );
        let devices = api.devices(&token).await.unwrap();
        assert_eq!(devices.certificates.len(), 2);
        api.keys(&token).await.unwrap();
        let collections = api.collections(&token).await.unwrap();
        assert_eq!(collections.len(), 1);
        assert_eq!(collections[0].id, COLLECTION);
        assert_eq!(api.head(&token, COLLECTION).await.unwrap(), None);
        assert!(
            api.commits(&token, COLLECTION, 0, 10)
                .await
                .unwrap()
                .commits
                .is_empty()
        );
        let chunk = ChunkId(Digest::from_bytes([1; 32]));
        let missing = api.missing(&token, COLLECTION, vec![chunk]).await.unwrap();
        assert_eq!(missing.ids, [chunk]);
        assert!(
            api.attestations(&token, COLLECTION)
                .await
                .unwrap()
                .is_empty()
        );
        api.patch_collection(
            &token,
            COLLECTION,
            &PatchCollection {
                retention_days: Some(7),
                config: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(api.collections(&token).await.unwrap()[0].retention_days, 7);

        // And the server's refusals come back as codes.
        assert_eq!(
            code(
                api.put_chunk(&token, COLLECTION, missing.lease, chunk, vec![1, 2, 3])
                    .await
            ),
            ErrorCode::BadRequest
        );
        assert_eq!(
            code(
                api.put_chunk(
                    &token,
                    COLLECTION,
                    LeaseId::from_bytes([9; 16]),
                    chunk,
                    vec![1]
                )
                .await
            ),
            ErrorCode::BadRequest
        );
        assert_eq!(
            code(api.get_chunk(&token, COLLECTION, chunk).await),
            ErrorCode::NotFound
        );
        let other = CollectionId::from_bytes([8; 16]);
        assert_eq!(code(api.head(&token, other).await), ErrorCode::NotFound);
        assert_eq!(
            code(api.recovery(AccountId::from_bytes([7; 16])).await),
            ErrorCode::NotFound
        );
        let unsigned = api.devices("not-a-token").await;
        assert_eq!(code(unsigned), ErrorCode::Unauthorized);
        assert_eq!(
            code(api.collections("not-a-token").await),
            ErrorCode::Unauthorized
        );

        // Pairing, unauthenticated: created, pending, not approvable with nonsense.
        let identity = DeviceIdentity::generate(&mut ChaCha20Rng::seed_from_u64(5));
        let request = PairingRequest {
            verifying_key: identity.verifying_key(),
            kem_key: identity.kem_public_key(),
        };
        let created = api.create_pairing(&request).await.unwrap();
        assert_eq!(
            api.pairing(created.pairing, 0).await.unwrap(),
            PairingState::Pending(Box::new(request.clone()))
        );
        // An unknown pairing looks expired: the server doesn't say which exist.
        assert_eq!(
            api.pairing(PairingId::from_bytes([1; 16]), 0).await,
            Ok(PairingState::Expired)
        );

        // A head attestation, signed by the device.
        let attestation = Signed::sign(
            &device_key(0),
            &HeadAttestation {
                format: DEVICE_FORMAT,
                collection: COLLECTION,
                seq: 0,
                hash: CommitHash(Digest::from_bytes([0; 32])),
                device: session.device(),
                time_ms: 1,
            },
        );
        api.attest(&token, COLLECTION, &attestation).await.unwrap();
        assert_eq!(api.attestations(&token, COLLECTION).await.unwrap().len(), 1);

        // A collection created, then moved to the trash.
        let fresh = CollectionId::from_bytes([6; 16]);
        let envelope = Envelope {
            kind: EnvelopeKind::CollectionKey,
            epoch: 0,
            device: None,
            collection: Some(fresh),
            wrapped: vec![0; 72],
        };
        api.create_collection(
            &token,
            &CreateCollection {
                id: fresh,
                key: envelope,
                config: vec![1],
            },
        )
        .await
        .unwrap();
        assert_eq!(api.collections(&token).await.unwrap().len(), 2);
        api.delete_collection(&token, fresh).await.unwrap();
        assert_eq!(api.collections(&token).await.unwrap().len(), 1);
        assert_eq!(
            code(api.delete_collection(&token, fresh).await),
            ErrorCode::NotFound
        );
        stop(server).await;
    });
}

#[test]
fn tls_needs_the_pinned_key() {
    let certs = tempfile::tempdir().unwrap();
    let (cert, key, der) = certificate(certs.path());
    let prepared = prepare(0, Some((&cert, &key)), "");
    let pin = key_pin(&der).unwrap();
    let hex = pin.iter().fold(String::new(), |mut text, byte| {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
        text
    });
    assert_eq!(
        Trust::pinned_from_hex(&hex.to_uppercase()),
        Ok(Trust::PinnedKey(pin))
    );
    assert!(Trust::pinned_from_hex("abc").is_err());
    assert!(Trust::pinned_from_hex(&"zz".repeat(32)).is_err());
    runtime().block_on(async {
        let server = start(&prepared).await;
        let pinned = Api::new(&prepared.origin, Trust::PinnedKey(pin)).unwrap();
        pinned.info().await.unwrap();
        // The OS doesn't trust a self-signed certificate; another pin doesn't match.
        let system = Api::new(&prepared.origin, Trust::System).unwrap();
        assert!(matches!(system.info().await, Err(ApiError::Tls(_))));
        let wrong = Api::new(&prepared.origin, Trust::PinnedKey([1; 32])).unwrap();
        assert!(matches!(wrong.info().await, Err(ApiError::Tls(_))));
        // The right key under another name is refused too: the name is still checked.
        let port = prepared.origin.rsplit(':').next().unwrap();
        let by_address =
            Api::new(&format!("https://127.0.0.1:{port}"), Trust::PinnedKey(pin)).unwrap();
        assert!(matches!(by_address.info().await, Err(ApiError::Tls(_))));
        // The whole account works over TLS.
        let session = Session::new(pinned, device_key(0));
        let server_api = HttpServer::new(Arc::clone(&session));
        assert_eq!(server_api.head(COLLECTION).await, Ok(None));
        assert!(Arc::ptr_eq(server_api.session(), &session));
        stop(server).await;
    });
    assert!(key_pin(&rustls_pki_types::CertificateDer::from(vec![1, 2, 3])).is_err());
}

#[test]
fn sessions_renew_and_errors_map_for_the_engine() {
    // Sessions of two seconds; signed-in devices may make five requests a minute.
    let prepared = prepare(
        1,
        None,
        "[limits]\nsession = \"2s\"\n[rates]\ndevice_per_minute = 5\ninfo_per_minute = 1\n",
    );
    runtime().block_on(async {
        let server = start(&prepared).await;
        let session = session(&prepared, 0);
        let first = session.token().await.unwrap();
        // Shorter than the renewal margin: every request renews.
        let second = session.token().await.unwrap();
        assert_ne!(first, second);
        tokio::time::sleep(Duration::from_millis(2100)).await;
        assert_eq!(
            code(session.api().devices(&first).await),
            ErrorCode::Unauthorized
        );
        let devices = session
            .with_token(|token| {
                let session = Arc::clone(&session);
                async move { session.api().devices(&token).await }
            })
            .await
            .unwrap();
        assert_eq!(devices.certificates.len(), 2);

        // Rate limits: the server says when to come back; the engine sees "later".
        session.api().info().await.unwrap();
        match session.api().info().await {
            Err(ApiError::Server {
                code: ErrorCode::RateLimited,
                retry_after,
                ..
            }) => {
                assert!(retry_after.is_some());
            }
            other => panic!("expected a rate limit, got {other:?}"),
        }
        let engine_view = HttpServer::new(Arc::clone(&session));
        let mut results = Vec::new();
        for _ in 0..6 {
            results.push(engine_view.head(COLLECTION).await);
        }
        assert!(
            results
                .iter()
                .any(|result| matches!(result, Err(ServerError::Unavailable(_)))),
            "{results:?}"
        );
        // A collection of another account is "not found".
        let other = HttpServer::new(session_of_unknown(&prepared));
        assert!(matches!(
            other.head(COLLECTION).await,
            Err(ServerError::Rejected(_))
        ));
        stop(server).await;
    });
}

/// A device the account doesn't know: it can't sign in.
fn session_of_unknown(prepared: &Prepared) -> Arc<Session> {
    let api = Api::new(&prepared.origin, Trust::System).unwrap();
    Session::new(api, device_key(9))
}

#[test]
fn an_absent_server_is_a_network_error() {
    let prepared = prepare(0, None, "");
    runtime().block_on(async {
        // Never started.
        let api = Api::new(&prepared.origin, Trust::System).unwrap();
        assert!(matches!(api.info().await, Err(ApiError::Network(_))));
        let engine_view = HttpServer::new(Session::new(api, device_key(0)));
        assert!(matches!(
            engine_view.head(COLLECTION).await,
            Err(ServerError::Unavailable(_))
        ));
        assert_eq!(ACCOUNT, AccountId::from_bytes([5; 16]));
    });
}
