//! One handler per endpoint (server HTTP §4).

use std::sync::Arc;
use std::time::Duration;

use super::limits::Class;
use super::wire::{ApiError, Authed, Cbor, ClientIp, MaybeAuthed, OCTETS, body_bytes, hex_id};
use super::{Api, Deps, events};
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Path, Query, Request, State};
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use oxisoft_drive_crypto::hash::Digest;
use oxisoft_drive_crypto::suite::Suite;
use oxisoft_drive_proto::api::{
    AccountCreated, AppendCommit, AppendResult, Challenge, ChallengeRequest, CollectionInfo,
    Commits, CreateAccount, CreateCollection, Devices, ErrorCode, Event, Head, Keys, Missing,
    MissingRequest, PROTOCOL_VERSION, PairingApproval, PairingCreated, PairingRequest,
    PairingState, PatchCollection, PutDevices, PutKeys, Recovery, ServerInfo, Session,
    SessionRequest,
};
use oxisoft_drive_proto::{
    AccountId, ChunkId, CollectionId, HeadAttestation, LeaseId, PairingId, Seq, Signed,
};

type ApiState<D> = State<Arc<Api<D>>>;
type Result<T> = std::result::Result<T, ApiError>;

/// The longest pairing long poll.
const MAX_WAIT: Duration = Duration::from_secs(30);

fn collection_id(text: &str) -> Result<CollectionId> {
    hex_id(text).map(CollectionId::from_bytes)
}

fn query_number(query: Option<&str>, name: &str) -> Result<Option<u64>> {
    let Some(query) = query else {
        return Ok(None);
    };
    for pair in query.split('&') {
        if let Some(value) = pair
            .strip_prefix(name)
            .and_then(|rest| rest.strip_prefix('='))
        {
            return value
                .parse()
                .map(Some)
                .map_err(|_| ApiError::new(ErrorCode::BadRequest, format!("bad {name}")));
        }
    }
    Ok(None)
}

fn query_text<'a>(query: Option<&'a str>, name: &str) -> Option<&'a str> {
    query?
        .split('&')
        .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
}

// ── open endpoints ──────────────────────────────────────────────────────────────────

pub(crate) async fn info<D: Deps>(
    State(api): ApiState<D>,
    ClientIp(client): ClientIp,
) -> Result<Cbor<ServerInfo>> {
    api.limiters.check(Class::Info, client)?;
    Ok(Cbor(ServerInfo {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        protocols: vec![PROTOCOL_VERSION],
        suites: vec![Suite::CURRENT.id()],
        limits: api.service.settings().limits,
    }))
}

pub(crate) async fn challenge<D: Deps>(
    State(api): ApiState<D>,
    ClientIp(client): ClientIp,
    Cbor(request): Cbor<ChallengeRequest>,
) -> Result<Cbor<Challenge>> {
    api.limiters.check(Class::Auth, client)?;
    Ok(Cbor(api.service.challenge(request.device).await?))
}

pub(crate) async fn session<D: Deps>(
    State(api): ApiState<D>,
    ClientIp(client): ClientIp,
    Cbor(request): Cbor<SessionRequest>,
) -> Result<Cbor<Session>> {
    api.limiters.check(Class::Auth, client)?;
    let session = api
        .service
        .sign_in(
            request.device,
            &request.nonce,
            &request.signature,
            &api.config.origin,
        )
        .await?;
    Ok(Cbor(session))
}

pub(crate) async fn create_account<D: Deps>(
    State(api): ApiState<D>,
    ClientIp(client): ClientIp,
    Cbor(request): Cbor<CreateAccount>,
) -> Result<Cbor<AccountCreated>> {
    api.limiters.check(Class::Accounts, client)?;
    let account = api.service.create_account_by_invite(&request).await?;
    Ok(Cbor(AccountCreated { account }))
}

pub(crate) async fn recovery<D: Deps>(
    State(api): ApiState<D>,
    ClientIp(client): ClientIp,
    Path(account): Path<String>,
) -> Result<Cbor<Recovery>> {
    api.limiters.check(Class::Recovery, client)?;
    let account = AccountId::from_bytes(hex_id(&account)?);
    Ok(Cbor(api.service.recovery(account).await?))
}

pub(crate) async fn create_pairing<D: Deps>(
    State(api): ApiState<D>,
    ClientIp(client): ClientIp,
    Cbor(request): Cbor<PairingRequest>,
) -> Result<Cbor<PairingCreated>> {
    api.limiters.check(Class::Pairings, client)?;
    Ok(Cbor(api.service.create_pairing(&request).await?))
}

/// The pairing's state; with `?wait=N`, waits up to `N` seconds (at most 30) for an
/// approval before answering "pending".
pub(crate) async fn pairing<D: Deps>(
    State(api): ApiState<D>,
    ClientIp(client): ClientIp,
    Path(pairing): Path<String>,
    request: Request,
) -> Result<Cbor<PairingState>> {
    api.limiters.check(Class::Auth, client)?;
    let pairing = PairingId::from_bytes(hex_id(&pairing)?);
    let seconds = query_number(request.uri().query(), "wait")?.unwrap_or(0);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds).min(MAX_WAIT);
    loop {
        // Registered before looking, so an approval in between isn't missed.
        let approved = api.events.pairings.notified();
        tokio::pin!(approved);
        approved.as_mut().enable();
        let state = api.service.pairing_state(pairing).await?;
        if !matches!(state, PairingState::Pending(_))
            || tokio::time::timeout_at(deadline, approved).await.is_err()
        {
            return Ok(Cbor(state));
        }
    }
}

// ── signed-in endpoints ─────────────────────────────────────────────────────────────

pub(crate) async fn devices<D: Deps>(
    State(api): ApiState<D>,
    Authed(caller): Authed,
) -> Result<Cbor<Devices>> {
    Ok(Cbor(api.service.devices(caller.account).await?))
}

/// Replaces the device list; with no session, only a list signed by the account key (a
/// device restored from the recovery key), which raises the recovery alarm.
pub(crate) async fn put_devices<D: Deps>(
    State(api): ApiState<D>,
    ClientIp(client): ClientIp,
    MaybeAuthed(caller): MaybeAuthed,
    Cbor(request): Cbor<PutDevices>,
) -> Result<Cbor<Devices>> {
    if caller.is_none() {
        api.limiters.check(Class::Recovery, client)?;
    }
    let list = api.service.put_devices(caller, &request).await?;
    api.events.publish(
        list.account,
        Event::Devices {
            version: list.version,
            by_recovery: caller.is_none(),
        },
    );
    Ok(Cbor(api.service.devices(list.account).await?))
}

pub(crate) async fn keys<D: Deps>(
    State(api): ApiState<D>,
    Authed(caller): Authed,
) -> Result<Cbor<Keys>> {
    Ok(Cbor(api.service.keys(caller).await?))
}

pub(crate) async fn put_keys<D: Deps>(
    State(api): ApiState<D>,
    Authed(caller): Authed,
    Cbor(request): Cbor<PutKeys>,
) -> Result<Cbor<Keys>> {
    let epoch = api.service.put_keys(caller, &request).await?;
    api.events.publish(caller.account, Event::Keys { epoch });
    Ok(Cbor(api.service.keys(caller).await?))
}

pub(crate) async fn approve_pairing<D: Deps>(
    State(api): ApiState<D>,
    Authed(caller): Authed,
    Path(pairing): Path<String>,
    Cbor(approval): Cbor<PairingApproval>,
) -> Result<Response> {
    let pairing = PairingId::from_bytes(hex_id(&pairing)?);
    api.service
        .approve_pairing(caller, pairing, &approval)
        .await?;
    api.events.pairings.notify_waiters();
    Ok(axum::http::StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn collections<D: Deps>(
    State(api): ApiState<D>,
    Authed(caller): Authed,
) -> Result<Cbor<Vec<CollectionInfo>>> {
    Ok(Cbor(api.service.collections(caller.account).await?))
}

pub(crate) async fn create_collection<D: Deps>(
    State(api): ApiState<D>,
    Authed(caller): Authed,
    Cbor(request): Cbor<CreateCollection>,
) -> Result<Response> {
    api.service
        .create_collection_with_key(caller.account, &request)
        .await?;
    Ok(axum::http::StatusCode::CREATED.into_response())
}

pub(crate) async fn patch_collection<D: Deps>(
    State(api): ApiState<D>,
    Authed(caller): Authed,
    Path(collection): Path<String>,
    Cbor(request): Cbor<PatchCollection>,
) -> Result<Response> {
    let collection = collection_id(&collection)?;
    api.service
        .patch_collection(caller.account, collection, &request)
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn delete_collection<D: Deps>(
    State(api): ApiState<D>,
    Authed(caller): Authed,
    Path(collection): Path<String>,
) -> Result<Response> {
    let collection = collection_id(&collection)?;
    api.service
        .delete_collection(caller.account, collection)
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn head<D: Deps>(
    State(api): ApiState<D>,
    Authed(caller): Authed,
    Path(collection): Path<String>,
) -> Result<Cbor<Option<Head>>> {
    let collection = collection_id(&collection)?;
    Ok(Cbor(api.service.head(caller.account, collection).await?))
}

pub(crate) async fn commits<D: Deps>(
    State(api): ApiState<D>,
    Authed(caller): Authed,
    Path(collection): Path<String>,
    Query(query): Query<Vec<(String, String)>>,
) -> Result<Cbor<Commits>> {
    let collection = collection_id(&collection)?;
    let number = |name: &str| -> Result<Option<u64>> {
        query
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| {
                value
                    .parse()
                    .map_err(|_| ApiError::new(ErrorCode::BadRequest, format!("bad {name}")))
            })
            .transpose()
    };
    let after: Seq = number("after")?.unwrap_or(0);
    let limit = u32::try_from(number("limit")?.unwrap_or(1000)).unwrap_or(u32::MAX);
    Ok(Cbor(
        api.service
            .commits_after(caller.account, collection, after, limit)
            .await?,
    ))
}

pub(crate) async fn append<D: Deps>(
    State(api): ApiState<D>,
    Authed(caller): Authed,
    Path(collection): Path<String>,
    Cbor(request): Cbor<AppendCommit>,
) -> Result<Cbor<AppendResult>> {
    let collection = collection_id(&collection)?;
    let head = api
        .service
        .append(
            caller.account,
            collection,
            request.expected,
            &request.commit,
        )
        .await?;
    api.events.publish(
        caller.account,
        Event::Head {
            collection,
            seq: head.seq,
        },
    );
    Ok(Cbor(AppendResult::Appended(head)))
}

pub(crate) async fn missing<D: Deps>(
    State(api): ApiState<D>,
    Authed(caller): Authed,
    Path(collection): Path<String>,
    Cbor(request): Cbor<MissingRequest>,
) -> Result<Cbor<Missing>> {
    let collection = collection_id(&collection)?;
    Ok(Cbor(
        api.service
            .missing(caller.account, collection, &request.ids)
            .await?,
    ))
}

pub(crate) async fn put_chunk<D: Deps>(
    State(api): ApiState<D>,
    Authed(caller): Authed,
    Path((collection, chunk)): Path<(String, String)>,
    request: Request,
) -> Result<Response> {
    let collection = collection_id(&collection)?;
    let chunk = ChunkId(Digest::from_bytes(hex_id(&chunk)?));
    let lease = query_text(request.uri().query(), "lease")
        .ok_or_else(|| ApiError::new(ErrorCode::BadRequest, "lease missing"))
        .and_then(hex_id)
        .map(LeaseId::from_bytes)?;
    let object = body_bytes(request, &api, OCTETS).await?;
    api.service
        .put_chunk(caller.account, collection, lease, chunk, &object)
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn get_chunk<D: Deps>(
    State(api): ApiState<D>,
    Authed(caller): Authed,
    Path((collection, chunk)): Path<(String, String)>,
) -> Result<Response> {
    let collection = collection_id(&collection)?;
    let chunk = ChunkId(Digest::from_bytes(hex_id(&chunk)?));
    let object = api
        .service
        .get_chunk(caller.account, collection, chunk)
        .await?;
    Ok(([(CONTENT_TYPE, OCTETS)], object).into_response())
}

pub(crate) async fn attest<D: Deps>(
    State(api): ApiState<D>,
    Authed(caller): Authed,
    Path(collection): Path<String>,
    Cbor(attestation): Cbor<Signed<HeadAttestation>>,
) -> Result<Response> {
    let collection = collection_id(&collection)?;
    api.service
        .put_attestation(caller, collection, &attestation)
        .await?;
    api.events
        .publish(caller.account, Event::Attestation { collection });
    Ok(axum::http::StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn attestations<D: Deps>(
    State(api): ApiState<D>,
    Authed(caller): Authed,
    Path(collection): Path<String>,
) -> Result<Cbor<Vec<Signed<HeadAttestation>>>> {
    let collection = collection_id(&collection)?;
    Ok(Cbor(
        api.service.attestations(caller.account, collection).await?,
    ))
}

/// The account's events over a WebSocket.
pub(crate) async fn events<D: Deps>(
    State(api): ApiState<D>,
    Authed(caller): Authed,
    upgrade: WebSocketUpgrade,
) -> Response {
    let receiver = api.events.subscribe(caller.account);
    upgrade.on_upgrade(move |socket| events::forward(socket, receiver))
}
