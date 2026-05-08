-- Canonical, fully-migrated schema. sqlc reads this for type inference; the
-- runtime applies it on every boot via internal/store/sqlite.go (every CREATE
-- uses IF NOT EXISTS so re-applying is idempotent). Existing v1 deployments
-- additionally run the probe-and-ALTER deltas in internal/store/migrations.go
-- to add columns added by add-developer-accounts to pre-existing tables.

CREATE TABLE IF NOT EXISTS events (
  source              TEXT    NOT NULL,
  sequence            INTEGER NOT NULL,
  delivery_id         TEXT    NOT NULL,
  provider_timestamp  INTEGER NOT NULL,
  received_at         INTEGER NOT NULL,
  headers_json        TEXT    NOT NULL,
  body                BLOB    NOT NULL,
  body_sha256         TEXT    NOT NULL,
  PRIMARY KEY (source, sequence)
);

CREATE INDEX IF NOT EXISTS idx_events_dedupe   ON events(source, delivery_id);
CREATE INDEX IF NOT EXISTS idx_events_received ON events(received_at);

CREATE TABLE IF NOT EXISTS users (
  id              TEXT    PRIMARY KEY,
  email           TEXT    NOT NULL,
  name            TEXT    NOT NULL,
  role            TEXT    NOT NULL CHECK (role IN ('admin','user')),
  password_hash   TEXT    NOT NULL,
  default_scopes  TEXT    NOT NULL DEFAULT '[]',
  created_at      INTEGER NOT NULL,
  deactivated_at  INTEGER,
  external_id     TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_nocase ON users(email COLLATE NOCASE);

CREATE TABLE IF NOT EXISTS user_sessions (
  id            TEXT    PRIMARY KEY,
  user_id       TEXT    NOT NULL REFERENCES users(id),
  secret_hash   TEXT    NOT NULL,
  created_at    INTEGER NOT NULL,
  last_used_at  INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  user_agent    TEXT    NOT NULL DEFAULT '',
  ip            TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);

CREATE TABLE IF NOT EXISTS invites (
  code                  TEXT    PRIMARY KEY,
  role                  TEXT    NOT NULL CHECK (role IN ('admin','user')),
  default_scopes        TEXT    NOT NULL DEFAULT '[]',
  created_by_user_id    TEXT    REFERENCES users(id),
  bootstrap             INTEGER NOT NULL DEFAULT 0,
  created_at            INTEGER NOT NULL,
  expires_at            INTEGER,
  consumed_at           INTEGER,
  consumed_by_user_id   TEXT    REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_invites_consumed_at ON invites(consumed_at);

CREATE TABLE IF NOT EXISTS device_pairings (
  device_code             TEXT    PRIMARY KEY,
  user_code               TEXT    NOT NULL UNIQUE,
  status                  TEXT    NOT NULL CHECK (status IN ('pending','approved_unfetched','done','denied','expired')),
  created_at              INTEGER NOT NULL,
  expires_at              INTEGER NOT NULL,
  user_id                 TEXT    REFERENCES users(id),
  requesting_ip           TEXT    NOT NULL DEFAULT '',
  requesting_user_agent   TEXT    NOT NULL DEFAULT '',
  requested_scopes        TEXT    NOT NULL DEFAULT '[]',
  plaintext_token         TEXT,
  token_id                TEXT    REFERENCES listener_tokens(id)
);

CREATE INDEX IF NOT EXISTS idx_device_pairings_expires_at ON device_pairings(expires_at);

CREATE TABLE IF NOT EXISTS listener_tokens (
  id              TEXT    PRIMARY KEY,
  name            TEXT    NOT NULL,
  scopes          TEXT    NOT NULL,
  secret_hash     TEXT    NOT NULL,
  created_at      INTEGER NOT NULL,
  last_used_at    INTEGER,
  revoked_at      INTEGER,
  owner_user_id   TEXT    REFERENCES users(id),
  kind            TEXT    NOT NULL DEFAULT 'listener' CHECK (kind IN ('pat','listener')),
  ephemeral       INTEGER NOT NULL DEFAULT 0,
  expires_at      INTEGER
);

CREATE INDEX IF NOT EXISTS idx_listener_tokens_owner_user_id ON listener_tokens(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_listener_tokens_kind         ON listener_tokens(kind);
CREATE INDEX IF NOT EXISTS idx_listener_tokens_expires_at   ON listener_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_listener_tokens_ephemeral_last_used_at
    ON listener_tokens(last_used_at) WHERE ephemeral=1;

CREATE TABLE IF NOT EXISTS push_subscriptions (
  id                    TEXT    PRIMARY KEY,
  source                TEXT    NOT NULL,
  target_url            TEXT    NOT NULL,
  signing_secret_hash   TEXT    NOT NULL,
  name                  TEXT    NOT NULL DEFAULT '',
  cursor                INTEGER NOT NULL DEFAULT 0,
  paused_at             INTEGER,
  created_at            INTEGER NOT NULL,
  last_attempt_at       INTEGER,
  last_success_at       INTEGER,
  last_error            TEXT    NOT NULL DEFAULT '',
  consecutive_failures  INTEGER NOT NULL DEFAULT 0,
  owner_user_id         TEXT    REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_push_source                ON push_subscriptions(source);
CREATE INDEX IF NOT EXISTS idx_push_subscriptions_owner_user_id ON push_subscriptions(owner_user_id);

CREATE TABLE IF NOT EXISTS audit_events (
  id                TEXT    PRIMARY KEY,
  at                INTEGER NOT NULL,
  actor_user_id     TEXT    REFERENCES users(id),
  actor_token_id    TEXT    REFERENCES listener_tokens(id),
  action            TEXT    NOT NULL,
  target_type       TEXT    NOT NULL,
  target_id         TEXT    NOT NULL,
  metadata          TEXT    NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_audit_events_at              ON audit_events(at);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor_user_id   ON audit_events(actor_user_id);
