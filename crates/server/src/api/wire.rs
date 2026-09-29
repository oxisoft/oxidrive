//! What travels over the wire (server HTTP §2): CBOR bodies, error bodies and their
//! statuses, IDs in paths, the client's address, and the session.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, FromRequest, FromRequestParts, Request};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, RETRY_AFTER};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use oxisoft_drive_proto::api::{ErrorBody, ErrorCode, Head};

use super::{Api, Deps};
use crate::service::{Caller, ServiceError};

/// The metadata content type.
pub(crate) const CBOR: &str = "application/cbor";
/// The chunk object content type.
pub(crate) const OCTETS: &str = "application/octet-stream";

/// An error answer: a code, a message and, for commit conflicts, the current head.
#[derive(Debug)]
pub(crate) struct ApiError {
    code: ErrorCode,
    message: String,
    head: Option<Head>,
    retry_after_s: Option<u64>,
}

impl ApiError {
    pub(crate) fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            head: None,
            retry_after_s: None,
        }
    }

    pub(crate) fn rate_limited(retry_after_s: u64) -> Self {
        Self {
            retry_after_s: Some(retry_after_s),
            ..Self::new(ErrorCode::RateLimited, "too many requests")
        }
    }

    const fn status(&self) -> StatusCode {
        match self.code {
            ErrorCode::BadRequest => StatusCode::BAD_REQUEST,
            ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
            ErrorCode::Forbidden => StatusCode::FORBIDDEN,
            ErrorCode::NotFound => StatusCode::NOT_FOUND,
            ErrorCode::Conflict => StatusCode::CONFLICT,
            ErrorCode::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::QuotaExceeded => StatusCode::INSUFFICIENT_STORAGE,
            ErrorCode::Unsupported => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<ServiceError> for ApiError {
    fn from(error: ServiceError) -> Self {
        let code = match &error {
            ServiceError::NotFound => ErrorCode::NotFound,
            ServiceError::Disabled | ServiceError::Untrusted | ServiceError::Forbidden(_) => {
                ErrorCode::Forbidden
            }
            ServiceError::Unauthorized => ErrorCode::Unauthorized,
            ServiceError::Invalid(_) | ServiceError::MissingChunks(_) | ServiceError::BadLease => {
                ErrorCode::BadRequest
            }
            ServiceError::Conflict(_) => ErrorCode::Conflict,
            ServiceError::TooLarge => ErrorCode::TooLarge,
            ServiceError::QuotaExceeded => ErrorCode::QuotaExceeded,
            ServiceError::Store(_) | ServiceError::Blob(_) => ErrorCode::Internal,
        };
        let message = if code == ErrorCode::Internal {
            // The details stay on the server.
            "internal error".to_owned()
        } else {
            error.to_string()
        };
        let head = match error {
            ServiceError::Conflict(head) => head,
            _ => None,
        };
        Self {
            head,
            ..Self::new(code, message)
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = ErrorBody {
            code: self.code,
            message: self.message,
            head: self.head,
        };
        let mut response = (status, Cbor(body)).into_response();
        if let Some(seconds) = self.retry_after_s {
            response
                .headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from(seconds));
        }
        response
    }
}

/// A CBOR body, decoded from a request or encoded into a response.
#[derive(Debug)]
pub(crate) struct Cbor<T>(pub T);

fn has_content_type(headers: &HeaderMap, wanted: &str) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case(wanted))
}

/// The raw body, within the route's size limit.
pub(crate) async fn body_bytes<S: Send + Sync>(
    request: Request,
    state: &S,
    content_type: &str,
) -> Result<Bytes, ApiError> {
    if !has_content_type(request.headers(), content_type) {
        return Err(ApiError::new(
            ErrorCode::Unsupported,
            format!("expected {content_type}"),
        ));
    }
    Bytes::from_request(request, state)
        .await
        .map_err(|rejection| {
            if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
                ApiError::new(ErrorCode::TooLarge, "body too large")
            } else {
                ApiError::new(ErrorCode::BadRequest, rejection.body_text())
            }
        })
}

impl<T, S> FromRequest<S> for Cbor<T>
where
    T: for<'b> minicbor::Decode<'b, ()>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, ApiError> {
        let bytes = body_bytes(request, state, CBOR).await?;
        minicbor::decode(&bytes)
            .map(Cbor)
            .map_err(|error| ApiError::new(ErrorCode::BadRequest, error.to_string()))
    }
}

impl<T: minicbor::Encode<()>> IntoResponse for Cbor<T> {
    fn into_response(self) -> Response {
        match minicbor::to_vec(&self.0) {
            Ok(bytes) => ([(CONTENT_TYPE, CBOR)], bytes).into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

/// A path segment holding an ID in lowercase or uppercase hex.
pub(crate) fn hex_id<const N: usize>(text: &str) -> Result<[u8; N], ApiError> {
    let bad = || ApiError::new(ErrorCode::BadRequest, "malformed ID");
    if text.len() != 2 * N {
        return Err(bad());
    }
    let mut out = [0; N];
    for (index, byte) in out.iter_mut().enumerate() {
        let pair = text.get(2 * index..2 * index + 2).ok_or_else(bad)?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| bad())?;
    }
    Ok(out)
}

/// The client's address: the connection's peer, or, behind a trusted reverse proxy, the
/// nearest untrusted address in `X-Forwarded-For`. In-process requests (tests) have no peer
/// and count as `0.0.0.0`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ClientIp(pub IpAddr);

pub(crate) fn client_ip(parts: &Parts, trusted: &[IpAddr]) -> IpAddr {
    let peer = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |info| info.0.ip());
    if !trusted.contains(&peer) {
        return peer;
    }
    let forwarded = parts
        .headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|entry| entry.trim().parse::<IpAddr>().ok())
        .collect::<Vec<_>>();
    forwarded
        .into_iter()
        .rev()
        .find(|address| !trusted.contains(address))
        .unwrap_or(peer)
}

impl<D: Deps> FromRequestParts<Arc<Api<D>>> for ClientIp {
    type Rejection = ApiError;

    fn from_request_parts(
        parts: &mut Parts,
        api: &Arc<Api<D>>,
    ) -> impl Future<Output = Result<Self, ApiError>> + Send {
        std::future::ready(Ok(Self(client_ip(parts, &api.config.trusted_proxies))))
    }
}

fn bearer(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

/// A signed-in device (a valid `Authorization: Bearer` session), within its rate limit.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Authed(pub Caller);

impl<D: Deps> FromRequestParts<Arc<Api<D>>> for Authed {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, api: &Arc<Api<D>>) -> Result<Self, ApiError> {
        let token =
            bearer(parts).ok_or_else(|| ApiError::new(ErrorCode::Unauthorized, "sign in first"))?;
        let caller = api.service.authenticate(token).await?;
        api.limiters.check_device(caller.device)?;
        Ok(Self(caller))
    }
}

/// A signed-in device if the request carries a session, `None` if it carries none (an
/// invalid session is still refused).
#[derive(Debug, Clone, Copy)]
pub(crate) struct MaybeAuthed(pub Option<Caller>);

impl<D: Deps> FromRequestParts<Arc<Api<D>>> for MaybeAuthed {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, api: &Arc<Api<D>>) -> Result<Self, ApiError> {
        if bearer(parts).is_none() {
            return Ok(Self(None));
        }
        Authed::from_request_parts(parts, api)
            .await
            .map(|Authed(caller)| Self(Some(caller)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request as HttpRequest;

    fn parts(peer: Option<&str>, forwarded: &[&str]) -> Parts {
        let mut builder = HttpRequest::builder();
        for value in forwarded {
            builder = builder.header("x-forwarded-for", *value);
        }
        let (mut parts, ()) = builder.body(()).unwrap().into_parts();
        if let Some(peer) = peer {
            parts
                .extensions
                .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
        }
        parts
    }

    #[test]
    fn the_client_is_the_peer_unless_a_trusted_proxy_forwards() {
        let proxy: IpAddr = "10.0.0.1".parse().unwrap();
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        // A direct client, forwarding header or not.
        let direct = parts(Some("203.0.113.5:4000"), &["198.51.100.1"]);
        assert_eq!(client_ip(&direct, &[proxy]), ip("203.0.113.5"));
        // Through the proxy: the nearest address the proxy didn't add itself.
        let proxied = parts(
            Some("10.0.0.1:4000"),
            &["198.51.100.1, 203.0.113.9", "10.0.0.1"],
        );
        assert_eq!(client_ip(&proxied, &[proxy]), ip("203.0.113.9"));
        // The proxy without a header, and no peer at all.
        assert_eq!(client_ip(&parts(Some("10.0.0.1:1"), &[]), &[proxy]), proxy);
        assert_eq!(client_ip(&parts(None, &[]), &[]), ip("0.0.0.0"));
    }

    #[test]
    fn ids_are_hex() {
        assert_eq!(hex_id::<2>("0aFf").unwrap(), [10, 255]);
        assert!(hex_id::<2>("0aF").is_err());
        assert!(hex_id::<2>("zzzz").is_err());
    }
}
