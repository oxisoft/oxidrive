# Running an oxidrive server

`oxidrive-server` is one program: it serves the sync API and is also its own admin tool.
It stores only encrypted data. It can't read file contents, file names or the folder
structure, and it holds no keys.

**Status: early development.** Nothing is usable yet: there is no client to connect.

## Build

```sh
cargo build --release --locked -p oxisoft-drive-server
# the program: target/release/oxidrive-server
```

## Configure

One TOML file, by default `/etc/oxidrive/server.toml` (`--config` names another):

```toml
[server]
listen = ["127.0.0.1:8080"]            # one or more addresses
origin = "https://drive.example.com"   # the public URL, exactly as devices reach it
trusted_proxies = ["127.0.0.1"]        # whose X-Forwarded-For names the client

[storage]
data_dir = "/var/lib/oxidrive"         # objects/ and, with SQLite, meta.sqlite
database = "sqlite"                    # or a postgres:// URL

[accounts]
default_quota = "unlimited"            # or a size, like "500 GB"
default_retention_days = 30            # how long old file versions and the trash stay

[maintenance]
interval = "1h"                        # how often old records and unused data are cleaned up
garbage_grace = "1d"                   # how long unused data waits before it is deleted

[log]
level = "info"                         # or a filter, like "oxisoft_drive_server=debug,info"
```

`oxidrive-server config check` loads the file, opens the database and prints the settings.
A mistake stops the server at start, naming the file, the line and the reason.

### TLS

Either the server terminates TLS itself:

```toml
[tls]
certificate = "/etc/oxidrive/fullchain.pem"   # chain, server certificate first
key = "/etc/oxidrive/privkey.pem"
```

TLS 1.3 only. A renewed certificate (Let's Encrypt, say) is picked up on `SIGHUP`, and on
its own within 10 minutes of the files changing. If a renewed file doesn't load, the server
keeps the old certificate and logs an error.

Or it listens on plain HTTP on localhost, behind a reverse proxy that terminates TLS and
sets `X-Forwarded-For`. List the proxy's address in `trusted_proxies`.

Plain HTTP on any other address is refused, since all traffic must be encrypted. On a
private network that encrypts by itself (Tailscale, WireGuard), allow it explicitly:

```toml
[server]
allow_plain_http = true
```

### PostgreSQL

```toml
[storage]
database = "postgres://oxidrive@db.internal/oxidrive"
```

Keep the password out of the file: the environment variable `OXIDRIVE_DATABASE_URL`, if
set, replaces `database` (for example through systemd's `LoadCredential` or a container
secret). The database and its user must exist; the server creates its tables.

Backups use `pg_dump` and `pg_restore`, which must be installed at the server's version or
newer. If they aren't on `PATH`, or should run another way, name the commands:

```toml
[backup]
pg_dump = ["/usr/pgsql-18/bin/pg_dump"]
pg_restore = ["/usr/pgsql-18/bin/pg_restore"]
```

The database password reaches them through `PGPASSWORD`, never on the command line.

### Limits

Rate limits and session lengths have tested defaults. Change them only for a reason:

```toml
[rates]                    # requests per client address (per device when signed in)
info_per_minute = 60
auth_per_minute = 30
pairings_per_minute = 10
accounts_per_minute = 5
recovery_per_hour = 5
device_per_minute = 600

[limits]
lease = "24h"              # how long an upload may take
session = "1h"
challenge = "60s"
pairing = "10m"
```

## Run

```sh
oxidrive-server serve
```

It logs to stderr, one line per request: method, route, status and time. It never logs
tokens, bodies or file paths. `SIGTERM` or `SIGINT` stops it: running requests get up to
30 seconds to finish. Database migrations run on their own when a newer version starts.

Every `interval` it removes old file versions past their retention, empties the trash, and
marks data nothing uses any more. Marked data is deleted one `garbage_grace` later (see
[Backup](#backup)). `oxidrive-server gc` runs one such round at once.

## Accounts

There is no web admin interface: accounts are managed with the command line, on the server
itself. Every command opens the database directly and works while the server runs.

```sh
oxidrive-server invite create --label "Alice" --expires 7d   # prints a one-time code
oxidrive-server user list                                    # --json for scripts
oxidrive-server user quota 3f2a "500 GB"                     # or "unlimited"
oxidrive-server user disable 3f2a                            # signs its devices out at once
oxidrive-server user enable 3f2a
oxidrive-server user delete 3f2a                             # only a disabled account
```

Accounts have no names on the server, only IDs. The label is your own note, given with the
invite. An account ID can be shortened to any unique start, as with git.

Deleting moves all of the account's data to the trash with no retention, so the next
maintenance rounds free it. The ID can never be used again. Deleting asks first;
`--yes` skips the question.

## Check

```sh
oxidrive-server fsck          # --json for scripts; exit code 1 if anything is wrong
```

It compares the database with the stored objects:

- **missing object:** the database lists data that isn't on disk. Restore from a backup.
- **wrong size:** an object on disk was changed or damaged. Restore from a backup.
- **orphan object:** an object the database doesn't list, left by an upload that was
  interrupted. This is harmless; `fsck --remove-orphans` deletes them, but only while the
  server is stopped.

## Backup

```sh
oxidrive-server backup /backups/oxidrive
```

It works while the server runs. The directory must be empty, or hold an earlier backup of
the same server. An earlier backup is brought up to date: only new objects are copied, and
objects the server no longer has are removed, so a nightly backup of a large server copies
only what changed.

```
/backups/oxidrive/
├── manifest.toml      written last: what the backup holds
├── meta.sqlite        the database (SQLite), or meta.pgdump (PostgreSQL)
└── objects/           the encrypted data
```

The backup holds the same encrypted data as the server, so it can be stored anywhere. It
holds no keys: users still need their devices or their recovery key.

**The backup must finish within `garbage_grace`** (one day by default). The server deletes
unused data only after that time, so everything the database snapshot needs is still there
until the backup is done. A backup that takes longer fails, writes no manifest, and can't
be restored. If backups take longer, raise `garbage_grace`; the cost is that freed space
(and freed quota) comes back later.

An interrupted backup has no manifest either. Run the backup again.

A schedule, for example a systemd timer or cron:

```sh
0 3 * * *  oxidrive-server backup /backups/oxidrive && rsync -a --delete /backups/oxidrive/ offsite:/oxidrive/
```

## Restore

Restore into an **empty** server: an empty data directory, and with PostgreSQL an empty
database. Stop the server first.

1. Stop the server.
2. Move the old data directory away (or drop and recreate the PostgreSQL database), so the
   target is empty. Keep the old data until the restore is checked.
3. Restore:

   ```sh
   oxidrive-server restore /backups/oxidrive
   ```

   It checks the manifest (complete, the same database kind, not from a newer server
   version), loads the database, copies the objects, runs the migrations, then checks the
   result. Objects uploaded after the snapshot are removed, and data that was already
   unused at the snapshot and deleted since is forgotten. It ends with `fsck: clean`, or
   lists what is missing and exits with code 1.
4. Start the server.

**After a restore the server is older than the devices.** Everything since the backup is
gone from the server. A device that has seen a newer state treats the server as rolled back:
that is how an attack would look. How devices recover from a legitimate restore will come
with the client. Until then, a new device starts from the restored state.
