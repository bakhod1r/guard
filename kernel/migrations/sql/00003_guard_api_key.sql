-- +goose Up
-- =============================================================
-- API keys. A key acts as its owner, narrowed by "scopes":
-- effective access = owner's RBAC/ABAC decision AND scope match.
-- Only the SHA-256 of the token is stored; the token is shown once.
-- Revocation is a timestamp, never a delete, so the audit trail keeps the key id.
-- =============================================================

CREATE TABLE IF NOT EXISTS guard_api_key (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES guard_user (id) ON DELETE CASCADE,
    name          VARCHAR(100)  NOT NULL,
    -- First characters of the token, safe to display ("gk_AbCdEfGh").
    prefix        VARCHAR(16)   NOT NULL,
    hash          CHAR(64)      NOT NULL,
    -- resource.action, resource.* or *
    scopes        VARCHAR(129)[] NOT NULL,
    expires_at    TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ,
    last_used_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ   NOT NULL DEFAULT now(),

    CONSTRAINT guard_api_key_scopes_not_empty CHECK (array_length(scopes, 1) >= 1),
    CONSTRAINT guard_api_key_expiry_after_create CHECK (expires_at IS NULL OR expires_at > created_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS guard_uq_api_key_hash ON guard_api_key (hash);
CREATE INDEX IF NOT EXISTS guard_idx_api_key_user ON guard_api_key (user_id, created_at DESC);

INSERT INTO guard_permission (resource, action, description)
VALUES
    ('apikey', 'read',   'List any user''s API keys'),
    ('apikey', 'revoke', 'Revoke any user''s API keys')
ON CONFLICT (code) DO NOTHING;


-- +goose Down
DELETE FROM guard_permission WHERE code IN ('apikey.read', 'apikey.revoke');
DROP TABLE IF EXISTS guard_api_key;
