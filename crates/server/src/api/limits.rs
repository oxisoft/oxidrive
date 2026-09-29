//! Rate limits (server HTTP §6): per client address on the endpoints that need no session,
//! per device on the rest.

use std::net::IpAddr;
use std::num::NonZeroU32;

use governor::clock::{Clock as _, DefaultClock};
use governor::{DefaultKeyedRateLimiter, Quota};
use oxisoft_drive_proto::DeviceId;

use super::wire::ApiError;

/// Requests allowed per client address (or per device) and period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimits {
    /// `GET /v1/info`, per minute.
    pub info_per_minute: u32,
    /// Sign-in and pairing state requests, per minute.
    pub auth_per_minute: u32,
    /// New pairings, per minute.
    pub pairings_per_minute: u32,
    /// New accounts, per minute.
    pub accounts_per_minute: u32,
    /// Recovery envelope requests, per hour.
    pub recovery_per_hour: u32,
    /// Requests of one signed-in device, per minute.
    pub device_per_minute: u32,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            info_per_minute: 60,
            auth_per_minute: 30,
            pairings_per_minute: 10,
            accounts_per_minute: 5,
            recovery_per_hour: 5,
            device_per_minute: 600,
        }
    }
}

/// Which limit a request counts against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    Info,
    Auth,
    Pairings,
    Accounts,
    Recovery,
}

#[derive(Debug)]
pub(crate) struct Limiters {
    info: DefaultKeyedRateLimiter<IpAddr>,
    auth: DefaultKeyedRateLimiter<IpAddr>,
    pairings: DefaultKeyedRateLimiter<IpAddr>,
    accounts: DefaultKeyedRateLimiter<IpAddr>,
    recovery: DefaultKeyedRateLimiter<IpAddr>,
    devices: DefaultKeyedRateLimiter<DeviceId>,
}

fn at_least_one(count: u32) -> NonZeroU32 {
    NonZeroU32::new(count).unwrap_or(NonZeroU32::MIN)
}

impl Limiters {
    pub(crate) fn new(limits: &RateLimits) -> Self {
        let per_minute =
            |count| DefaultKeyedRateLimiter::keyed(Quota::per_minute(at_least_one(count)));
        Self {
            info: per_minute(limits.info_per_minute),
            auth: per_minute(limits.auth_per_minute),
            pairings: per_minute(limits.pairings_per_minute),
            accounts: per_minute(limits.accounts_per_minute),
            recovery: DefaultKeyedRateLimiter::keyed(Quota::per_hour(at_least_one(
                limits.recovery_per_hour,
            ))),
            devices: DefaultKeyedRateLimiter::keyed(Quota::per_minute(at_least_one(
                limits.device_per_minute,
            ))),
        }
    }

    /// Counts a request from `client` against `class`.
    pub(crate) fn check(&self, class: Class, client: IpAddr) -> Result<(), ApiError> {
        let limiter = match class {
            Class::Info => &self.info,
            Class::Auth => &self.auth,
            Class::Pairings => &self.pairings,
            Class::Accounts => &self.accounts,
            Class::Recovery => &self.recovery,
        };
        limiter.check_key(&client).map_err(|not_until| {
            let wait = not_until.wait_time_from(DefaultClock::default().now());
            ApiError::rate_limited(wait.as_secs() + 1)
        })
    }

    /// Counts a request from a signed-in `device`.
    pub(crate) fn check_device(&self, device: DeviceId) -> Result<(), ApiError> {
        self.devices.check_key(&device).map_err(|not_until| {
            let wait = not_until.wait_time_from(DefaultClock::default().now());
            ApiError::rate_limited(wait.as_secs() + 1)
        })
    }

    /// Drops the state of clients whose limits have fully recovered.
    pub(crate) fn forget_idle(&self) {
        self.info.retain_recent();
        self.auth.retain_recent();
        self.pairings.retain_recent();
        self.accounts.retain_recent();
        self.recovery.retain_recent();
        self.devices.retain_recent();
    }
}
