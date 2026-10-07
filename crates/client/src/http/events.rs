//! [`Events`]: the server's event socket (server API §7), followed in a task that reconnects
//! with backoff and says when it is connected, so the daemon knows when to poll instead.

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt as _;
use oxisoft_drive_proto::api::Event;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::Connector;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::http::HeaderValue;

use super::{ApiError, Session, client_config, decode};

/// The first wait after a lost connection; it doubles up to [`MAX_BACKOFF`].
const FIRST_BACKOFF: Duration = Duration::from_secs(1);
/// The longest wait between reconnection attempts.
const MAX_BACKOFF: Duration = Duration::from_mins(1);

/// What the event socket reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    /// Connected: events arrive from now on.
    Connected,
    /// The connection is gone (with the reason); it is retried, and meanwhile the daemon
    /// should poll.
    Disconnected(String),
    /// An event.
    Event(Event),
}

/// The event socket of a session, followed in the background until dropped.
#[derive(Debug)]
pub struct Events {
    notices: mpsc::Receiver<Notice>,
    task: JoinHandle<()>,
}

impl Events {
    /// Starts following the event socket. Needs a tokio runtime.
    #[must_use]
    pub fn start(session: Arc<Session>) -> Self {
        let (sender, notices) = mpsc::channel(64);
        let task = tokio::spawn(follow(session, sender));
        Self { notices, task }
    }

    /// The next notice; `None` once the task ended.
    pub async fn next(&mut self) -> Option<Notice> {
        self.notices.recv().await
    }
}

impl Drop for Events {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn follow(session: Arc<Session>, sender: mpsc::Sender<Notice>) {
    let mut backoff = FIRST_BACKOFF;
    loop {
        let reason = match connect_and_read(&session, &sender, &mut backoff).await {
            Ok(Closed::ByServer) => "closed by the server".to_owned(),
            Ok(Closed::ByReceiver) => return,
            Err(error) => error.to_string(),
        };
        if sender.send(Notice::Disconnected(reason)).await.is_err() {
            return;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

enum Closed {
    ByServer,
    ByReceiver,
}

async fn connect_and_read(
    session: &Session,
    sender: &mpsc::Sender<Notice>,
    backoff: &mut Duration,
) -> Result<Closed, ApiError> {
    let token = session.token().await?;
    let origin = session.api().origin();
    let url = if let Some(rest) = origin.strip_prefix("https://") {
        format!("wss://{rest}/v1/events")
    } else {
        format!("ws://{}/v1/events", origin.trim_start_matches("http://"))
    };
    let mut request = url
        .as_str()
        .into_client_request()
        .map_err(|error| ApiError::Network(error.to_string()))?;
    request.headers_mut().insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|error| ApiError::Decode(error.to_string()))?,
    );
    let connector = if origin.starts_with("https://") {
        Connector::Rustls(Arc::new(client_config(session.api().trust())?))
    } else {
        Connector::Plain
    };
    let (mut socket, _) =
        tokio_tungstenite::connect_async_tls_with_config(request, None, false, Some(connector))
            .await
            .map_err(|error| ApiError::Network(format!("event socket: {error}")))?;
    *backoff = FIRST_BACKOFF;
    if sender.send(Notice::Connected).await.is_err() {
        return Ok(Closed::ByReceiver);
    }
    while let Some(message) = socket.next().await {
        let message = message.map_err(|error| ApiError::Network(error.to_string()))?;
        match message {
            Message::Binary(bytes) => {
                let event: Event = decode(&bytes)?;
                if sender.send(Notice::Event(event)).await.is_err() {
                    return Ok(Closed::ByReceiver);
                }
            }
            Message::Close(_) => return Ok(Closed::ByServer),
            _ => {}
        }
    }
    // A token that expired meanwhile is renewed on the next connection.
    session.forget_token().await;
    Ok(Closed::ByServer)
}
