-- +goose Up
-- =============================================================
-- Guard schema. All tables carry the "guard_" prefix so they coexist with
-- the host application's own tables.
--
-- Identity model:
--   guard_user      = who someone is (email, status, ABAC attributes)
--   guard_identity  = how they authenticate (password hash, lockout counters)
--   sessions        = Redis, not PostgreSQL (see session/infrastructure)
--
-- Security model:
--   guard_role -> guard_role_permission -> guard_permission          (RBAC)
--   guard_user_role (optionally time-bound)
--   guard_policy -> guard_policy_condition_group -> guard_policy_condition  (ABAC tree)
--   guard_audit_event                                                (append-only log)
--
-- ABAC conflict resolution (application-enforced, fail-closed):
--   1. collect enabled policies matching (resource, action) or '*'
--   2. evaluate each condition tree
--   3. strongest priority tier (lowest number) decides; DENY wins inside a tier
--   4. no policy matched -> RBAC (wildcard role or granted permission)
--   5. otherwise deny
-- Requires PostgreSQL 13+ (gen_random_uuid built in). IDs are UUIDv7 set by the app.
-- =============================================================

CREATE TABLE IF NOT EXISTS guard_user (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email          VARCHAR(255) NOT NULL,
    status         VARCHAR(16)  NOT NULL DEFAULT 'active',
    attributes     JSONB        NOT NULL DEFAULT '{}'::jsonb,
    last_login_at  TIMESTAMPTZ,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT guard_user_status_valid CHECK (status IN ('pending', 'active', 'banned', 'suspended')),
    CONSTRAINT guard_user_email_lower  CHECK (email = lower(email)),
    CONSTRAINT guard_user_attributes_object CHECK (jsonb_typeof(attributes) = 'object')
);

CREATE UNIQUE INDEX IF NOT EXISTS guard_uq_user_email ON guard_user (email);
CREATE INDEX IF NOT EXISTS guard_idx_user_status ON guard_user (status);


-- One row per authentication method. Only 'password' is implemented today;
-- the column exists so oauth / passkey can be added without a table rewrite.
CREATE TABLE IF NOT EXISTS guard_identity (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID NOT NULL REFERENCES guard_user (id) ON DELETE CASCADE,
    kind             VARCHAR(16)   NOT NULL DEFAULT 'password',
    secret           VARCHAR(1000) NOT NULL,
    failed_attempts  INTEGER       NOT NULL DEFAULT 0,
    last_failed_at   TIMESTAMPTZ,
    created_at       TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ   NOT NULL DEFAULT now(),

    CONSTRAINT guard_identity_kind_valid CHECK (kind IN ('password', 'oauth', 'passkey')),
    CONSTRAINT guard_identity_failed_attempts_non_negative CHECK (failed_attempts >= 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS guard_uq_identity_user_kind ON guard_identity (user_id, kind);


CREATE TABLE IF NOT EXISTS guard_role (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         VARCHAR(64)   NOT NULL,
    title        VARCHAR(255)  NOT NULL,
    description  VARCHAR(1000),
    -- System roles are code constants: they cannot be deleted through the API.
    is_system    BOOLEAN       NOT NULL DEFAULT FALSE,
    -- A wildcard role passes every RBAC check without explicit grants.
    wildcard     BOOLEAN       NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ   NOT NULL DEFAULT now(),

    CONSTRAINT guard_role_name_format CHECK (name ~ '^[a-z0-9_-]{2,64}$')
);

CREATE UNIQUE INDEX IF NOT EXISTS guard_uq_role_name ON guard_role (name);


CREATE TABLE IF NOT EXISTS guard_permission (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource     VARCHAR(64)  NOT NULL,
    action       VARCHAR(64)  NOT NULL,
    code         VARCHAR(129) GENERATED ALWAYS AS (resource || '.' || action) STORED,
    description  VARCHAR(1000),
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT guard_permission_part_format CHECK (resource ~ '^[a-z0-9_-]{1,64}$' AND action ~ '^[a-z0-9_-]{1,64}$')
);

CREATE UNIQUE INDEX IF NOT EXISTS guard_uq_permission_code ON guard_permission (code);


CREATE TABLE IF NOT EXISTS guard_role_permission (
    role_id        UUID NOT NULL REFERENCES guard_role (id) ON DELETE CASCADE,
    permission_id  UUID NOT NULL REFERENCES guard_permission (id) ON DELETE CASCADE,
    granted_by     UUID REFERENCES guard_user (id) ON DELETE SET NULL,
    granted_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX IF NOT EXISTS guard_idx_role_permission_permission ON guard_role_permission (permission_id);


CREATE TABLE IF NOT EXISTS guard_user_role (
    user_id     UUID NOT NULL REFERENCES guard_user (id) ON DELETE CASCADE,
    role_id     UUID NOT NULL REFERENCES guard_role (id) ON DELETE CASCADE,
    granted_by  UUID REFERENCES guard_user (id) ON DELETE SET NULL,
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- NULL = permanent. Expired rows are ignored by the evaluator, never auto-deleted.
    expires_at  TIMESTAMPTZ,
    PRIMARY KEY (user_id, role_id),

    CONSTRAINT guard_user_role_expiry_after_grant CHECK (expires_at IS NULL OR expires_at > granted_at)
);

CREATE INDEX IF NOT EXISTS guard_idx_user_role_role ON guard_user_role (role_id);


CREATE TABLE IF NOT EXISTS guard_policy (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(255) NOT NULL,
    resource    VARCHAR(64)  NOT NULL,
    action      VARCHAR(64)  NOT NULL,
    effect      VARCHAR(8)   NOT NULL,
    -- Lower number = evaluated first and wins over weaker tiers.
    priority    INTEGER      NOT NULL DEFAULT 100,
    enabled     BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT guard_policy_effect_valid CHECK (effect IN ('allow', 'deny'))
);

CREATE UNIQUE INDEX IF NOT EXISTS guard_uq_policy_name ON guard_policy (name);
CREATE INDEX IF NOT EXISTS guard_idx_policy_target ON guard_policy (resource, action) WHERE enabled;


-- Condition tree node. A policy has at most one root (parent_group_id IS NULL).
-- The composite FK keeps every child inside the same policy as its parent.
CREATE TABLE IF NOT EXISTS guard_policy_condition_group (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id         UUID NOT NULL REFERENCES guard_policy (id) ON DELETE CASCADE,
    parent_group_id   UUID,
    logical_operator  VARCHAR(3) NOT NULL DEFAULT 'and',
    negate            BOOLEAN    NOT NULL DEFAULT FALSE,
    position          INTEGER    NOT NULL DEFAULT 0,

    CONSTRAINT guard_pcg_operator_valid CHECK (logical_operator IN ('and', 'or')),
    CONSTRAINT guard_pcg_not_own_parent CHECK (parent_group_id <> id),
    CONSTRAINT guard_uq_pcg_id_policy UNIQUE (id, policy_id),
    CONSTRAINT guard_fk_pcg_parent_same_policy
        FOREIGN KEY (parent_group_id, policy_id)
        REFERENCES guard_policy_condition_group (id, policy_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS guard_uq_pcg_policy_root
    ON guard_policy_condition_group (policy_id) WHERE parent_group_id IS NULL;
CREATE INDEX IF NOT EXISTS guard_idx_pcg_parent
    ON guard_policy_condition_group (parent_group_id) WHERE parent_group_id IS NOT NULL;


CREATE TABLE IF NOT EXISTS guard_policy_condition (
    id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id  UUID NOT NULL REFERENCES guard_policy_condition_group (id) ON DELETE CASCADE,
    field     VARCHAR(128)   NOT NULL,
    operator  VARCHAR(16)    NOT NULL,
    -- A value starting with '$' is an attribute reference, e.g. '$user.id'.
    value     VARCHAR(500)[] NOT NULL,
    position  INTEGER        NOT NULL DEFAULT 0,

    CONSTRAINT guard_pc_operator_valid CHECK (operator IN ('eq', 'ne', 'gt', 'lt', 'gte', 'lte', 'in', 'not_in', 'contains')),
    CONSTRAINT guard_pc_value_not_empty CHECK (array_length(value, 1) >= 1),
    CONSTRAINT guard_pc_scalar_arity CHECK (operator IN ('in', 'not_in') OR array_length(value, 1) = 1)
);

CREATE INDEX IF NOT EXISTS guard_idx_pc_group ON guard_policy_condition (group_id);


-- Append-only. Revoke UPDATE/DELETE from the application role in production.
CREATE TABLE IF NOT EXISTS guard_audit_event (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    actor_id     UUID,
    action       VARCHAR(64)  NOT NULL,
    target       VARCHAR(255),
    success      BOOLEAN      NOT NULL,
    ip           VARCHAR(64),
    user_agent   VARCHAR(512),
    metadata     JSONB        NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS guard_idx_audit_occurred ON guard_audit_event (occurred_at DESC);
CREATE INDEX IF NOT EXISTS guard_idx_audit_actor ON guard_audit_event (actor_id, occurred_at DESC) WHERE actor_id IS NOT NULL;


-- +goose Down
DROP TABLE IF EXISTS guard_audit_event;
DROP TABLE IF EXISTS guard_policy_condition;
DROP TABLE IF EXISTS guard_policy_condition_group;
DROP TABLE IF EXISTS guard_policy;
DROP TABLE IF EXISTS guard_user_role;
DROP TABLE IF EXISTS guard_role_permission;
DROP TABLE IF EXISTS guard_permission;
DROP TABLE IF EXISTS guard_role;
DROP TABLE IF EXISTS guard_identity;
DROP TABLE IF EXISTS guard_user;
