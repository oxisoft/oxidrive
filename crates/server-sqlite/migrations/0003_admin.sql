-- oxidrive server metadata for the binary and admin CLI (server binary §4, §5), SQLite. Keep
-- in step with the PostgreSQL migration of the same number.

ALTER TABLE accounts ADD COLUMN label TEXT NOT NULL DEFAULT '';
-- Set once the admin deleted the account; its status stays 'disabled'.
ALTER TABLE accounts ADD COLUMN deleted_ms INTEGER;
ALTER TABLE invites ADD COLUMN label TEXT NOT NULL DEFAULT '';

-- When garbage collection found the chunk unused; NULL while it is in use (J1).
ALTER TABLE chunks ADD COLUMN garbage_ms INTEGER;
CREATE INDEX chunks_marked ON chunks (garbage_ms) WHERE garbage_ms IS NOT NULL;

CREATE TABLE heartbeats (
    name TEXT PRIMARY KEY NOT NULL,
    beat_ms INTEGER NOT NULL
) STRICT;
