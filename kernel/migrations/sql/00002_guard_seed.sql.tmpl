-- +goose Up
-- =============================================================
-- Baseline data: system roles, the permission catalogue Guard's own admin
-- API checks, and two ABAC policies. Host apps add their own permissions
-- through the API or their own migrations.
-- =============================================================

INSERT INTO guard_role (name, title, description, is_system, wildcard)
VALUES
    ('admin', 'Administrator', 'Full access to every resource', TRUE, TRUE),
    ('user',  'User',          'Default role for registered accounts', TRUE, FALSE)
ON CONFLICT (name) DO NOTHING;

INSERT INTO guard_permission (resource, action, description)
VALUES
    ('user',       'read',   'List and view users'),
    ('user',       'write',  'Update users, status and attributes'),
    ('role',       'read',   'List and view roles'),
    ('role',       'write',  'Create, delete roles and grant permissions'),
    ('role',       'assign', 'Assign roles to users'),
    ('permission', 'read',   'List permissions'),
    ('permission', 'write',  'Create permissions'),
    ('policy',     'read',   'List and view ABAC policies'),
    ('policy',     'write',  'Create, update and delete ABAC policies'),
    ('session',    'read',   'List any user''s sessions'),
    ('session',    'revoke', 'Revoke any user''s sessions'),
    ('audit',      'read',   'Read the audit log')
ON CONFLICT (code) DO NOTHING;


-- Self-service: a caller reads their own user record without user.read.
-- +goose StatementBegin
WITH p AS (
    INSERT INTO guard_policy (name, resource, action, effect, priority)
    VALUES ('self-service user read', 'user', 'read', 'allow', 100)
    ON CONFLICT (name) DO NOTHING
    RETURNING id
), g AS (
    INSERT INTO guard_policy_condition_group (policy_id, logical_operator)
    SELECT id, 'and' FROM p
    RETURNING id
)
INSERT INTO guard_policy_condition (group_id, field, operator, value)
SELECT id, 'resource.id', 'eq', ARRAY['$user.id'] FROM g;
-- +goose StatementEnd


-- Self-service: a caller sees which roles they hold without role.read.
-- +goose StatementBegin
WITH p AS (
    INSERT INTO guard_policy (name, resource, action, effect, priority)
    VALUES ('self-service role read', 'role', 'read', 'allow', 100)
    ON CONFLICT (name) DO NOTHING
    RETURNING id
), g AS (
    INSERT INTO guard_policy_condition_group (policy_id, logical_operator)
    SELECT id, 'and' FROM p
    RETURNING id
)
INSERT INTO guard_policy_condition (group_id, field, operator, value)
SELECT id, 'resource.owner_id', 'eq', ARRAY['$user.id'] FROM g;
-- +goose StatementEnd


-- Blocked accounts keep their roles, so RBAC alone would still let a banned
-- admin act on a live session. Priority 10 beats every default allow.
-- +goose StatementBegin
WITH p AS (
    INSERT INTO guard_policy (name, resource, action, effect, priority)
    VALUES ('blocked user denied', '*', '*', 'deny', 10)
    ON CONFLICT (name) DO NOTHING
    RETURNING id
), g AS (
    INSERT INTO guard_policy_condition_group (policy_id, logical_operator)
    SELECT id, 'and' FROM p
    RETURNING id
)
INSERT INTO guard_policy_condition (group_id, field, operator, value)
SELECT id, 'user.status', 'in', ARRAY['banned', 'suspended'] FROM g;
-- +goose StatementEnd


-- +goose Down
DELETE FROM guard_policy WHERE name IN ('self-service user read', 'self-service role read', 'blocked user denied');
DELETE FROM guard_permission WHERE code IN (
    'user.read', 'user.write', 'role.read', 'role.write', 'role.assign',
    'permission.read', 'permission.write', 'policy.read', 'policy.write',
    'session.read', 'session.revoke', 'audit.read'
);
DELETE FROM guard_role WHERE name IN ('admin', 'user');
