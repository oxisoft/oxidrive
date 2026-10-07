-- A device's index of one collection (client foundation §3): what it last synced (base),
-- the replayed remote state, the newest verified head and its version counter. Entries are
-- CBOR, encoded by the client; `format` names their encoding.

CREATE TABLE state (
    one INTEGER PRIMARY KEY NOT NULL CHECK (one = 1),
    format INTEGER NOT NULL,
    head_seq INTEGER,
    head_hash BLOB,
    counter INTEGER NOT NULL
) STRICT;

INSERT INTO state (one, format, head_seq, head_hash, counter) VALUES (1, 1, NULL, NULL, 0);

CREATE TABLE base (
    node BLOB PRIMARY KEY NOT NULL,
    entry BLOB NOT NULL
) STRICT;

CREATE TABLE remote (
    node BLOB PRIMARY KEY NOT NULL,
    entry BLOB NOT NULL
) STRICT;
