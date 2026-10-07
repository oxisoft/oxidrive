//! Signing in (server API §2) and keeping a token: renewed before it expires, and once when
//! the server says it is no longer valid. Callers needing a token at the same moment share
//! one sign-in.

use std::future::Future;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use oxisoft_drive_crypto::sign::{SignContext, SigningKey};
use oxisoft_drive_proto::api::{ErrorCode, SessionRequest};
use oxisoft_drive_proto::{DeviceId, auth_message};
use tokio::sync::Mutex;

use super::{Api, ApiError};

/// Renew a token this long before it expires.
const RENEW_BEFORE_MS: u64 = 5 * 60_000;

#[derive(Debug, Clone)]
struct Token {
    value: String,
    expires_ms: u64,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// A device's session with one server.
pub struct Session {
    api: Api,
    key: SigningKey,
    device: DeviceId,
    token: Mutex<Option<Token>>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("origin", &self.api.origin())
            .field("device", &self.device)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// The session of the device whose signing key is `key`; it signs in when first needed.
    #[must_use]
    pub fn new(api: Api, key: SigningKey) -> Arc<Self> {
        let device = DeviceId::from_key(&key.verifying_key());
        Arc::new(Self {
            api,
            key,
            device,
            token: Mutex::new(None),
        })
    }

    /// The API.
    #[must_use]
    pub const fn api(&self) -> &Api {
        &self.api
    }

    /// The signed-in device.
    #[must_use]
    pub const fn device(&self) -> DeviceId {
        self.device
    }

    /// A valid token, signing in if there is none or it expires soon.
    ///
    /// # Errors
    ///
    /// [`ApiError`] if signing in fails.
    pub async fn token(&self) -> Result<String, ApiError> {
        let mut held = self.token.lock().await;
        if let Some(token) = held.as_ref()
            && now_ms().saturating_add(RENEW_BEFORE_MS) < token.expires_ms
        {
            return Ok(token.value.clone());
        }
        let challenge = self.api.challenge(self.device).await?;
        let message = auth_message(self.api.origin(), &challenge.nonce, self.device);
        let signature = self.key.sign(SignContext::AuthChallenge, &message);
        let session = self
            .api
            .session(&SessionRequest {
                device: self.device,
                nonce: challenge.nonce,
                signature,
            })
            .await?;
        let value = session.token.clone();
        *held = Some(Token {
            value: session.token,
            expires_ms: session.expires_ms,
        });
        Ok(value)
    }

    /// Forgets the token, so the next call signs in again.
    pub async fn forget_token(&self) {
        *self.token.lock().await = None;
    }

    /// Runs `call` with a token; if the server no longer accepts it, signs in again and
    /// retries once.
    ///
    /// # Errors
    ///
    /// The call's or the sign-in's [`ApiError`].
    pub async fn with_token<T, F, Fut>(&self, call: F) -> Result<T, ApiError>
    where
        F: Fn(String) -> Fut,
        Fut: Future<Output = Result<T, ApiError>>,
    {
        let first = call(self.token().await?).await;
        match first {
            Err(error) if error.code() == Some(ErrorCode::Unauthorized) => {
                self.forget_token().await;
                call(self.token().await?).await
            }
            other => other,
        }
    }
}
