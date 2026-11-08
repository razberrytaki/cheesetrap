-- +goose Up
-- API owns admin/session/settings transactions; settings changes and audit
-- insertion commit together. Lock settings before audit insertion. Password
-- hashing and any external I/O happen before the transaction, never inside it.
CREATE TABLE cheesetrap.admins (
    admin_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    singleton boolean NOT NULL DEFAULT true UNIQUE CHECK (singleton),
    username text NOT NULL UNIQUE CHECK (length(username) > 0),
    password_hash text NOT NULL CHECK (length(password_hash) > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE cheesetrap.sessions (
    session_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash text NOT NULL UNIQUE CHECK (token_hash ~ '^[a-f0-9]{64}$'),
    admin_id uuid NOT NULL REFERENCES cheesetrap.admins(admin_id),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    CHECK (expires_at > created_at),
    CHECK (last_seen_at >= created_at AND last_seen_at < expires_at)
);
CREATE INDEX sessions_expiry_idx ON cheesetrap.sessions(expires_at);
CREATE INDEX sessions_admin_idx ON cheesetrap.sessions(admin_id);
CREATE TABLE cheesetrap.settings (
    key text PRIMARY KEY CHECK (length(key) > 0),
    version bigint NOT NULL CHECK (version > 0),
    value jsonb NOT NULL CHECK (jsonb_typeof(value) = 'object'),
    updated_at timestamptz NOT NULL DEFAULT now()
);
COMMENT ON COLUMN cheesetrap.settings.value IS 'Versioned nonsecret settings only. SMTP credentials and other secrets remain outside the database.';
CREATE TABLE cheesetrap.audit (
    audit_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id uuid REFERENCES cheesetrap.admins(admin_id),
    action text NOT NULL CHECK (length(action) > 0),
    details jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(details) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_created_idx ON cheesetrap.audit(created_at, audit_id);
CREATE INDEX audit_admin_idx ON cheesetrap.audit(admin_id, created_at);
COMMENT ON TABLE cheesetrap.audit IS 'Append-only for runtime accounts; sanitized action metadata without credentials or raw evidence.';
GRANT SELECT, INSERT, UPDATE ON cheesetrap.admins, cheesetrap.settings TO cheesetrap_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON cheesetrap.sessions TO cheesetrap_api;
GRANT SELECT, INSERT ON cheesetrap.audit TO cheesetrap_api;

-- +goose Down
DROP TABLE cheesetrap.audit;
DROP TABLE cheesetrap.settings;
DROP TABLE cheesetrap.sessions;
DROP TABLE cheesetrap.admins;
