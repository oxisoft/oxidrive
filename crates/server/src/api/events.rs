//! Notifications (server API §7): one broadcast channel per account, forwarded to each of
//! its `WebSocket`s, and a wake-up for pairing long polls.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use axum::extract::ws::{Message, WebSocket};
use oxisoft_drive_proto::AccountId;
use oxisoft_drive_proto::api::Event;
use tokio::sync::{Notify, broadcast};

/// Events kept for a slow WebSocket before it is dropped (it reconnects and fetches).
const BACKLOG: usize = 64;

#[derive(Debug, Default)]
pub(crate) struct Events {
    channels: Mutex<HashMap<AccountId, broadcast::Sender<Event>>>,
    /// Woken on every pairing approval.
    pub(crate) pairings: Notify,
}

impl Events {
    fn lock(&self) -> MutexGuard<'_, HashMap<AccountId, broadcast::Sender<Event>>> {
        self.channels.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Sends `event` to the account's open `WebSocket`s, if any.
    pub(crate) fn publish(&self, account: AccountId, event: Event) {
        let mut channels = self.lock();
        let listening = channels
            .get(&account)
            .is_some_and(|sender| sender.send(event).is_ok());
        if !listening {
            channels.remove(&account);
        }
    }

    /// A new listener for the account's events.
    pub(crate) fn subscribe(&self, account: AccountId) -> broadcast::Receiver<Event> {
        self.lock()
            .entry(account)
            .or_insert_with(|| broadcast::channel(BACKLOG).0)
            .subscribe()
    }
}

/// Forwards events to one WebSocket as binary CBOR frames until either side goes away or
/// the socket falls too far behind.
pub(crate) async fn forward(mut socket: WebSocket, mut events: broadcast::Receiver<Event>) {
    loop {
        tokio::select! {
            event = events.recv() => {
                let Ok(event) = event else {
                    break;
                };
                let Ok(frame) = minicbor::to_vec(event) else {
                    break;
                };
                if socket.send(Message::Binary(frame.into())).await.is_err() {
                    break;
                }
            }
            incoming = socket.recv() => {
                if !matches!(incoming, Some(Ok(message)) if !matches!(message, Message::Close(_))) {
                    break;
                }
            }
        }
    }
}
