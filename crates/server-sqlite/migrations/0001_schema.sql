-- oxidrive server metadata, SQLite (server storage §2). Keep in step with the PostgreSQL
-- schema: the same tables and columns.

CREATE TABLE accounts (
    id BLOB PRIMARY KEY NOT NULL,
    signing_key BLOB NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    quota_bytes INTEGER NOT NULL,
    used_bytes INTEGER NOT NULL,
    created_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE device_lists (
    account BLOB PRIMARY KEY NOT NULL REFERENCES accounts (id),
    version INTEGER NOT NULL,
    signed BLOB NOT NULL
) STRICT;

CREATE TABLE device_certificates (
    account BLOB NOT NULL REFERENCES accounts (id),
    device BLOB NOT NULL,
    signed BLOB NOT NULL,
    PRIMARY KEY (account, device)
) STRICT;

CREATE TABLE collections (
    id BLOB PRIMARY KEY NOT NULL,
    account BLOB NOT NULL REFERENCES accounts (id),
    config BLOB NOT NULL,
    retention_days INTEGER NOT NULL,
    created_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE commits (
    collection BLOB NOT NULL REFERENCES collections (id),
    seq INTEGER NOT NULL,
    hash BLOB NOT NULL,
    header BLOB NOT NULL,
    device BLOB NOT NULL,
    received_ms INTEGER NOT NULL,
    PRIMARY KEY (collection, seq)
) STRICT;

CREATE TABLE records (
    collection BLOB NOT NULL,
    seq INTEGER NOT NULL,
    idx INTEGER NOT NULL,
    node BLOB NOT NULL,
    hash BLOB NOT NULL,
    -- NULL once pruned.
    body BLOB,
    superseded_ms INTEGER,
    PRIMARY KEY (collection, seq, idx),
    FOREIGN KEY (collection, seq) REFERENCES commits (collection, seq)
) STRICT;

CREATE INDEX records_by_node ON records (collection, node);
CREATE INDEX records_prunable ON records (superseded_ms) WHERE body IS NOT NULL;

-- References of unpruned records only.
CREATE TABLE record_chunks (
    collection BLOB NOT NULL,
    seq INTEGER NOT NULL,
    idx INTEGER NOT NULL,
    chunk BLOB NOT NULL,
    PRIMARY KEY (collection, seq, idx, chunk),
    FOREIGN KEY (collection, seq, idx) REFERENCES records (collection, seq, idx)
) STRICT;

CREATE INDEX record_chunks_by_chunk ON record_chunks (collection, chunk);

CREATE TABLE chunks (
    collection BLOB NOT NULL REFERENCES collections (id),
    chunk BLOB NOT NULL,
    size INTEGER NOT NULL,
    stored_ms INTEGER NOT NULL,
    PRIMARY KEY (collection, chunk)
) STRICT;

CREATE TABLE leases (
    id BLOB PRIMARY KEY NOT NULL,
    collection BLOB NOT NULL REFERENCES collections (id),
    expires_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE lease_chunks (
    lease BLOB NOT NULL REFERENCES leases (id) ON DELETE CASCADE,
    chunk BLOB NOT NULL,
    PRIMARY KEY (lease, chunk)
) STRICT;

CREATE INDEX lease_chunks_by_chunk ON lease_chunks (chunk);
