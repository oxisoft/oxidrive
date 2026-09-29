-- oxidrive server metadata for the HTTP API (server HTTP §7), PostgreSQL. Keep in step with the
-- SQLite migration of the same number.

ALTER TABLE accounts ADD COLUMN kem_key BYTEA NOT NULL DEFAULT ''::BYTEA;
ALTER TABLE collections ADD COLUMN deleted_ms BIGINT;
ALTER TABLE collections ADD COLUMN purged BIGINT NOT NULL DEFAULT 0;

CREATE INDEX device_certificates_by_device ON device_certificates (device);

CREATE TABLE invites (
    hash BYTEA PRIMARY KEY,
    expires_ms BIGINT NOT NULL,
    used_ms BIGINT
);

CREATE TABLE challenges (
    device BYTEA PRIMARY KEY,
    nonce BYTEA NOT NULL,
    expires_ms BIGINT NOT NULL
);

CREATE TABLE sessions (
    hash BYTEA PRIMARY KEY,
    account BYTEA NOT NULL REFERENCES accounts (id),
    device BYTEA NOT NULL,
    expires_ms BIGINT NOT NULL
);

CREATE INDEX sessions_by_device ON sessions (account, device);

-- Absent device or collection is the empty value, so they can be part of the key.
CREATE TABLE envelopes (
    account BYTEA NOT NULL REFERENCES accounts (id),
    kind BIGINT NOT NULL,
    epoch BIGINT NOT NULL,
    device BYTEA NOT NULL,
    collection BYTEA NOT NULL,
    encoded BYTEA NOT NULL,
    PRIMARY KEY (account, kind, epoch, device, collection)
);

CREATE TABLE pairings (
    id BYTEA PRIMARY KEY,
    request BYTEA NOT NULL,
    expires_ms BIGINT NOT NULL,
    approval BYTEA
);

CREATE TABLE attestations (
    collection BYTEA NOT NULL REFERENCES collections (id),
    device BYTEA NOT NULL,
    signed BYTEA NOT NULL,
    PRIMARY KEY (collection, device)
);
