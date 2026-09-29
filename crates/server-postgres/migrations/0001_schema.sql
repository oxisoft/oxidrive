-- oxidrive server metadata, PostgreSQL (server storage §2). Keep in step with the SQLite
-- schema: the same tables and columns.

CREATE TABLE accounts (
    id BYTEA PRIMARY KEY,
    signing_key BYTEA NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    quota_bytes BIGINT NOT NULL,
    used_bytes BIGINT NOT NULL,
    created_ms BIGINT NOT NULL
);

CREATE TABLE device_lists (
    account BYTEA PRIMARY KEY REFERENCES accounts (id),
    version BIGINT NOT NULL,
    signed BYTEA NOT NULL
);

CREATE TABLE device_certificates (
    account BYTEA NOT NULL REFERENCES accounts (id),
    device BYTEA NOT NULL,
    signed BYTEA NOT NULL,
    PRIMARY KEY (account, device)
);

CREATE TABLE collections (
    id BYTEA PRIMARY KEY,
    account BYTEA NOT NULL REFERENCES accounts (id),
    config BYTEA NOT NULL,
    retention_days BIGINT NOT NULL,
    created_ms BIGINT NOT NULL
);

CREATE TABLE commits (
    collection BYTEA NOT NULL REFERENCES collections (id),
    seq BIGINT NOT NULL,
    hash BYTEA NOT NULL,
    header BYTEA NOT NULL,
    device BYTEA NOT NULL,
    received_ms BIGINT NOT NULL,
    PRIMARY KEY (collection, seq)
);

CREATE TABLE records (
    collection BYTEA NOT NULL,
    seq BIGINT NOT NULL,
    idx BIGINT NOT NULL,
    node BYTEA NOT NULL,
    hash BYTEA NOT NULL,
    -- NULL once pruned.
    body BYTEA,
    superseded_ms BIGINT,
    PRIMARY KEY (collection, seq, idx),
    FOREIGN KEY (collection, seq) REFERENCES commits (collection, seq)
);

CREATE INDEX records_by_node ON records (collection, node);
CREATE INDEX records_prunable ON records (superseded_ms) WHERE body IS NOT NULL;

-- References of unpruned records only.
CREATE TABLE record_chunks (
    collection BYTEA NOT NULL,
    seq BIGINT NOT NULL,
    idx BIGINT NOT NULL,
    chunk BYTEA NOT NULL,
    PRIMARY KEY (collection, seq, idx, chunk),
    FOREIGN KEY (collection, seq, idx) REFERENCES records (collection, seq, idx)
);

CREATE INDEX record_chunks_by_chunk ON record_chunks (collection, chunk);

CREATE TABLE chunks (
    collection BYTEA NOT NULL REFERENCES collections (id),
    chunk BYTEA NOT NULL,
    size BIGINT NOT NULL,
    stored_ms BIGINT NOT NULL,
    PRIMARY KEY (collection, chunk)
);

CREATE TABLE leases (
    id BYTEA PRIMARY KEY,
    collection BYTEA NOT NULL REFERENCES collections (id),
    expires_ms BIGINT NOT NULL
);

CREATE TABLE lease_chunks (
    lease BYTEA NOT NULL REFERENCES leases (id) ON DELETE CASCADE,
    chunk BYTEA NOT NULL,
    PRIMARY KEY (lease, chunk)
);

CREATE INDEX lease_chunks_by_chunk ON lease_chunks (chunk);
