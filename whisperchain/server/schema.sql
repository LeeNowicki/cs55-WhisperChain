-- WhisperChain+ database schema.
--
-- Privacy rule for this schema: the `issued` table (who got a token) and the
-- `messages` table (what was sent) share ONLY the `round` column. There is
-- no foreign key between them and neither stores a fine-grained timestamp,
-- so the database itself cannot link a sender to a message.

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,                 -- argon2 hash, never the password
    active        INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_at    TEXT NOT NULL
);

-- An account holds a SET of roles: one row per (user, role).
CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER NOT NULL REFERENCES users(id),
    role    TEXT NOT NULL CHECK (role IN ('Sender', 'Recipient', 'Moderator', 'Admin')),
    PRIMARY KEY (user_id, role)
);

-- Only the SHA-256 of the invite code is stored, so a database leak does
-- not reveal usable invite codes.
CREATE TABLE IF NOT EXISTS invites (
    id         INTEGER PRIMARY KEY,
    code_hash  TEXT NOT NULL UNIQUE,
    roles      TEXT NOT NULL,                    -- JSON list of role names
    expires_at TEXT NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0 CHECK (used IN (0, 1))
);

-- key_id and status exist so key rotation could be added later.
CREATE TABLE IF NOT EXISTS public_keys (
    key_id      TEXT PRIMARY KEY,                -- UUID string
    user_id     INTEGER NOT NULL REFERENCES users(id),
    public_key  BLOB NOT NULL,                   -- SPKI DER bytes
    fingerprint TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('active', 'retired', 'revoked')),
    created_at  TEXT NOT NULL
);

-- token_n / token_e are the round's public token-signing key (base64 ints).
-- The private key lives in keys/round_<n>.pem, not in the database.
CREATE TABLE IF NOT EXISTS rounds (
    round   INTEGER PRIMARY KEY,
    status  TEXT NOT NULL CHECK (status IN ('open', 'closed')),
    token_n TEXT NOT NULL,
    token_e TEXT NOT NULL
);

-- One token per user per round. NO timestamps on purpose (unlinkability).
CREATE TABLE IF NOT EXISTS issued (
    round   INTEGER NOT NULL REFERENCES rounds(round),
    user_id INTEGER NOT NULL REFERENCES users(id),
    blinded TEXT NOT NULL,                       -- the blinded value only
    PRIMARY KEY (round, user_id)
);

-- NO timestamps on purpose. UNIQUE token_hash is the spent-token registry:
-- a second insert with the same token is impossible.
CREATE TABLE IF NOT EXISTS messages (
    id            TEXT PRIMARY KEY,              -- uuid4
    recipient_id  INTEGER NOT NULL REFERENCES users(id),
    key_id        TEXT NOT NULL REFERENCES public_keys(key_id),
    round         INTEGER NOT NULL REFERENCES rounds(round),
    envelope      BLOB NOT NULL,
    envelope_hash TEXT NOT NULL,
    token_hash    TEXT NOT NULL UNIQUE,
    status        TEXT NOT NULL DEFAULT 'delivered'
);

CREATE TABLE IF NOT EXISTS flags (
    id         TEXT PRIMARY KEY,                 -- uuid4
    message_id TEXT NOT NULL UNIQUE REFERENCES messages(id),
    reason     TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL CHECK (status IN ('open', 'dismissed', 'actioned')),
    created_at TEXT NOT NULL
);

-- The message content key, wrapped (RSA-OAEP) to each moderator's public key.
CREATE TABLE IF NOT EXISTS flag_keys (
    flag_id          TEXT NOT NULL REFERENCES flags(id),
    moderator_key_id TEXT NOT NULL REFERENCES public_keys(key_id),
    wrapped_key      BLOB NOT NULL,
    PRIMARY KEY (flag_id, moderator_key_id)
);

CREATE TABLE IF NOT EXISTS frozen_tokens (
    token_hash TEXT PRIMARY KEY,
    flag_id    TEXT NOT NULL REFERENCES flags(id),
    frozen_at  TEXT NOT NULL
);

-- Remembers which alerts already fired so each fires once per scope.
CREATE TABLE IF NOT EXISTS alert_state (
    rule  TEXT NOT NULL,
    scope TEXT NOT NULL,
    PRIMARY KEY (rule, scope)
);

-- Tamper-evident audit log: hash chain + Ed25519 signature per entry.
CREATE TABLE IF NOT EXISTS audit_log (
    seq        INTEGER PRIMARY KEY,              -- UNIQUE: backstop against forks
    timestamp  TEXT NOT NULL,
    action     TEXT NOT NULL,
    role       TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    prev_hash  TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    signature  TEXT NOT NULL
);

-- The audit log is append-only: the database itself refuses edits/deletes.
CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;
