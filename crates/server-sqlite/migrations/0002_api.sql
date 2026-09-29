-- oxidrive server metadata for the HTTP API (server HTTP §7), SQLite. Keep in step with the
-- PostgreSQL migration of the same number.

ALTER TABLE accounts ADD COLUMN kem_key BLOB NOT NULL DEFAULT x'';
ALTER TABLE collections ADD COLUMN deleted_ms INTEGER;
ALTER TABLE collections ADD COLUMN purged INTEGER NOT NULL DEFAULT 0;

CREATE INDEX device_certificates_by_device ON device_certificates (device);

CREATE TABLE invites (
    hash BLOB PRIMARY KEY NOT NULL,
    expires_ms INTEGER NOT NULL,
    used_ms INTEGER
) STRICT;

CREATE TABLE challenges (
    device BLOB PRIMARY KEY NOT NULL,
    nonce BLOB NOT NULL,
    expires_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE sessions (
    hash BLOB PRIMARY KEY NOT NULL,
    account BLOB NOT NULL REFERENCES accounts (id),
    device BLOB NOT NULL,
    expires_ms INTEGER NOT NULL
) STRICT;

CREATE INDEX sessions_by_device ON sessions (account, device);

-- Absent device or collection is the empty value, so they can be part of the key.
CREATE TABLE envelopes (
    account BLOB NOT NULL REFERENCES accounts (id),
    kind INTEGER NOT NULL,
    epoch INTEGER NOT NULL,
    device BLOB NOT NULL,
    collection BLOB NOT NULL,
    encoded BLOB NOT NULL,
    PRIMARY KEY (account, kind, epoch, device, collection)
) STRICT;

CREATE TABLE pairings (
    id BLOB PRIMARY KEY NOT NULL,
    request BLOB NOT NULL,
    expires_ms INTEGER NOT NULL,
    approval BLOB
) STRICT;

CREATE TABLE attestations (
    collection BLOB NOT NULL REFERENCES collections (id),
    device BLOB NOT NULL,
    signed BLOB NOT NULL,
    PRIMARY KEY (collection, device)
) STRICT;
