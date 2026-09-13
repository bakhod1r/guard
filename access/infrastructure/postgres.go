// Package infrastructure stores roles, permissions and policies in PostgreSQL.
package infrastructure

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bakhod1r/guard/access/domain"
	"github.com/bakhod1r/guard/kernel/pgerr"
)

type Postgres struct{ db *pgxpool.Pool }

func NewPostgres(db *pgxpool.Pool) *Postgres { return &Postgres{db: db} }

// validUUID guards Guard-owned ids (policies) that are always UUID columns.
func validUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

// nullableUserID maps an empty host user id to SQL NULL. Non-empty ids are sent as
// text; PostgreSQL coerces them to the host id type (bigint, uuid, text, ...).
func nullableUserID(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ---------- roles ----------

func (r *Postgres) CreateRole(ctx context.Context, role *domain.Role) error {
	_, err := r.db.Exec(ctx, `INSERT INTO guard_role (id, name, title, description, is_system, wildcard) VALUES ($1,$2,$3,$4,$5,$6)`,
		uuid.Must(uuid.NewV7()).String(), role.Name, role.Title, role.Description, role.IsSystem, role.Wildcard)
	if pgerr.IsUniqueViolation(err) {
		return domain.ErrRoleExists
	}
	return err
}

func (r *Postgres) DeleteRole(ctx context.Context, name string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM guard_role WHERE name=$1`, name)
	if err == nil && tag.RowsAffected() == 0 {
		return domain.ErrRoleNotFound
	}
	return err
}

const roleSelect = `SELECT r.name, r.title, COALESCE(r.description,''), r.is_system, r.wildcard,
	COALESCE(array_agg(p.resource ORDER BY p.code) FILTER (WHERE p.id IS NOT NULL), '{}'),
	COALESCE(array_agg(p.action   ORDER BY p.code) FILTER (WHERE p.id IS NOT NULL), '{}')
	FROM guard_role r
	LEFT JOIN guard_role_permission rp ON rp.role_id = r.id
	LEFT JOIN guard_permission p ON p.id = rp.permission_id`

func scanRole(row pgx.Row, extra ...any) (domain.Role, error) {
	var role domain.Role
	var res, act []string
	dest := append([]any{&role.Name, &role.Title, &role.Description, &role.IsSystem, &role.Wildcard, &res, &act}, extra...)
	if err := row.Scan(dest...); err != nil {
		return role, err
	}
	role.Permissions = make([]domain.Permission, len(res))
	for i := range res {
		role.Permissions[i] = domain.Permission{Resource: res[i], Action: act[i]}
	}
	return role, nil
}

func (r *Postgres) Role(ctx context.Context, name string) (*domain.Role, error) {
	role, err := scanRole(r.db.QueryRow(ctx, roleSelect+` WHERE r.name=$1 GROUP BY r.id`, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrRoleNotFound
	}
	if err != nil {
		return nil, err
	}
	return &role, nil
}

func (r *Postgres) ListRoles(ctx context.Context) ([]domain.Role, error) {
	rows, err := r.db.Query(ctx, roleSelect+` GROUP BY r.id ORDER BY r.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Role{}
	for rows.Next() {
		role, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, role)
	}
	return out, rows.Err()
}

func (r *Postgres) GrantsOf(ctx context.Context, userID string) ([]domain.RoleGrant, error) {
	if userID == "" {
		return []domain.RoleGrant{}, nil
	}
	rows, err := r.db.Query(ctx, `SELECT r.name, r.title, COALESCE(r.description,''), r.is_system, r.wildcard,
		COALESCE(array_agg(p.resource ORDER BY p.code) FILTER (WHERE p.id IS NOT NULL), '{}'),
		COALESCE(array_agg(p.action   ORDER BY p.code) FILTER (WHERE p.id IS NOT NULL), '{}'),
		ur.granted_at, ur.expires_at
		FROM guard_user_role ur
		JOIN guard_role r ON r.id = ur.role_id
		LEFT JOIN guard_role_permission rp ON rp.role_id = r.id
		LEFT JOIN guard_permission p ON p.id = rp.permission_id
		WHERE ur.user_id = $1
		GROUP BY r.id, ur.granted_at, ur.expires_at
		ORDER BY r.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.RoleGrant{}
	for rows.Next() {
		var g domain.RoleGrant
		role, err := scanRole(rows, &g.GrantedAt, &g.ExpiresAt)
		if err != nil {
			return nil, err
		}
		g.Role = role
		out = append(out, g)
	}
	// A non-coercible id (e.g. "abc" for bigint) is reported by the server while reading rows.
	if err := rows.Err(); pgerr.IsInvalidText(err) {
		return []domain.RoleGrant{}, nil
	} else if err != nil {
		return nil, err
	}
	return out, nil
}

// ---------- permissions ----------

func (r *Postgres) CreatePermission(ctx context.Context, p domain.Permission) error {
	_, err := r.db.Exec(ctx, `INSERT INTO guard_permission (id, resource, action, description) VALUES ($1,$2,$3,NULLIF($4,''))
		ON CONFLICT (code) DO UPDATE SET description = COALESCE(EXCLUDED.description, guard_permission.description)`,
		uuid.Must(uuid.NewV7()).String(), p.Resource, p.Action, p.Description)
	return err
}

func (r *Postgres) ListPermissions(ctx context.Context) ([]domain.Permission, error) {
	rows, err := r.db.Query(ctx, `SELECT resource, action, COALESCE(description,'') FROM guard_permission ORDER BY code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Permission{}
	for rows.Next() {
		var p domain.Permission
		if err := rows.Scan(&p.Resource, &p.Action, &p.Description); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (r *Postgres) GrantPermission(ctx context.Context, role string, p domain.Permission, grantedBy string) error {
	// VALUES (not INSERT ... SELECT) so PostgreSQL infers $3 as the host user id type;
	// in a SELECT list an untyped parameter resolves to text and cannot be assigned to bigint/uuid.
	tag, err := r.db.Exec(ctx, `INSERT INTO guard_role_permission (role_id, permission_id, granted_by)
		VALUES ((SELECT id FROM guard_role WHERE name=$1), (SELECT id FROM guard_permission WHERE code=$2), $3)
		ON CONFLICT DO NOTHING`, role, p.Code(), nullableUserID(grantedBy))
	if pgerr.IsNotNullViolation(err) {
		return r.explainMissing(ctx, role, p)
	}
	if pgerr.IsInvalidText(err) || pgerr.IsForeignKeyViolation(err) {
		return domain.ErrSubjectNotFound
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return r.explainMissing(ctx, role, p)
	}
	return nil
}

// explainMissing distinguishes "already granted" from a missing role or permission.
func (r *Postgres) explainMissing(ctx context.Context, role string, p domain.Permission) error {
	var hasRole, hasPerm bool
	if err := r.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM guard_role WHERE name=$1), EXISTS(SELECT 1 FROM guard_permission WHERE code=$2)`,
		role, p.Code()).Scan(&hasRole, &hasPerm); err != nil {
		return err
	}
	if !hasRole {
		return domain.ErrRoleNotFound
	}
	if !hasPerm {
		return domain.ErrPermissionNotFound
	}
	return nil
}

func (r *Postgres) RevokePermission(ctx context.Context, role string, p domain.Permission) error {
	_, err := r.db.Exec(ctx, `DELETE FROM guard_role_permission rp USING guard_role r, guard_permission p
		WHERE rp.role_id=r.id AND rp.permission_id=p.id AND r.name=$1 AND p.code=$2`, role, p.Code())
	return err
}

func (r *Postgres) AssignRole(ctx context.Context, userID, role, grantedBy string, expiresAt *time.Time) error {
	if userID == "" {
		return domain.ErrSubjectNotFound
	}
	// VALUES so $1/$3 take the host user id type; a missing role yields role_id NULL (23502).
	_, err := r.db.Exec(ctx, `INSERT INTO guard_user_role (user_id, role_id, granted_by, expires_at)
		VALUES ($1, (SELECT id FROM guard_role WHERE name=$2), $3, $4)
		ON CONFLICT (user_id, role_id) DO UPDATE SET granted_by=EXCLUDED.granted_by, granted_at=now(), expires_at=EXCLUDED.expires_at`,
		userID, role, nullableUserID(grantedBy), expiresAt)
	switch {
	case pgerr.IsNotNullViolation(err):
		return domain.ErrRoleNotFound
	case pgerr.IsForeignKeyViolation(err), pgerr.IsInvalidText(err):
		return domain.ErrSubjectNotFound
	}
	return err
}

func (r *Postgres) UnassignRole(ctx context.Context, userID, role string) error {
	if userID == "" {
		return nil
	}
	_, err := r.db.Exec(ctx, `DELETE FROM guard_user_role ur USING guard_role r WHERE ur.role_id=r.id AND ur.user_id=$1 AND r.name=$2`, userID, role)
	if pgerr.IsInvalidText(err) {
		return nil
	}
	return err
}

// ---------- policies ----------

func (r *Postgres) SavePolicy(ctx context.Context, p *domain.Policy) error {
	return pgx.BeginFunc(ctx, r.db, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO guard_policy (id, name, resource, action, effect, priority, enabled)
			VALUES ($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, resource=EXCLUDED.resource, action=EXCLUDED.action,
				effect=EXCLUDED.effect, priority=EXCLUDED.priority, enabled=EXCLUDED.enabled, updated_at=now()`,
			p.ID, p.Name, p.Resource, p.Action, string(p.Effect), p.Priority, p.Enabled)
		if pgerr.IsUniqueViolation(err) {
			return domain.ErrPolicyNameTaken
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM guard_policy_condition_group WHERE policy_id=$1`, p.ID); err != nil {
			return err
		}
		if p.Root == nil {
			return nil
		}
		return insertGroup(ctx, tx, p.ID, nil, 0, p.Root)
	})
}

func insertGroup(ctx context.Context, tx pgx.Tx, policyID string, parent *string, pos int, g *domain.ConditionGroup) error {
	id := uuid.Must(uuid.NewV7()).String()
	op := g.Operator
	if op == "" {
		op = domain.And
	}
	if _, err := tx.Exec(ctx, `INSERT INTO guard_policy_condition_group (id, policy_id, parent_group_id, logical_operator, negate, position)
		VALUES ($1,$2,$3,$4,$5,$6)`, id, policyID, parent, string(op), g.Negate, pos); err != nil {
		return err
	}
	for i, c := range g.Conditions {
		if _, err := tx.Exec(ctx, `INSERT INTO guard_policy_condition (group_id, field, operator, value, position) VALUES ($1,$2,$3,$4,$5)`,
			id, c.Field, string(c.Operator), c.Value, i); err != nil {
			return err
		}
	}
	for i := range g.Groups {
		if err := insertGroup(ctx, tx, policyID, &id, i, &g.Groups[i]); err != nil {
			return err
		}
	}
	return nil
}

func (r *Postgres) DeletePolicy(ctx context.Context, id string) error {
	if !validUUID(id) {
		return domain.ErrPolicyNotFound
	}
	tag, err := r.db.Exec(ctx, `DELETE FROM guard_policy WHERE id=$1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return domain.ErrPolicyNotFound
	}
	return err
}

func (r *Postgres) Policy(ctx context.Context, id string) (*domain.Policy, error) {
	if !validUUID(id) {
		return nil, domain.ErrPolicyNotFound
	}
	list, err := r.loadPolicies(ctx, `WHERE id=$1`, id)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, domain.ErrPolicyNotFound
	}
	return &list[0], nil
}

func (r *Postgres) ListPolicies(ctx context.Context) ([]domain.Policy, error) {
	return r.loadPolicies(ctx, ``)
}

func (r *Postgres) ApplicablePolicies(ctx context.Context, resource, action string) ([]domain.Policy, error) {
	return r.loadPolicies(ctx, `WHERE enabled AND resource IN ($1,'*') AND action IN ($2,'*')`, resource, action)
}

func (r *Postgres) loadPolicies(ctx context.Context, where string, args ...any) ([]domain.Policy, error) {
	rows, err := r.db.Query(ctx, `SELECT id::text, name, resource, action, effect, priority, enabled FROM guard_policy `+where+` ORDER BY priority, name`, args...)
	if err != nil {
		return nil, err
	}
	policies := []domain.Policy{}
	index := map[string]int{}
	for rows.Next() {
		var p domain.Policy
		var effect string
		if err := rows.Scan(&p.ID, &p.Name, &p.Resource, &p.Action, &effect, &p.Priority, &p.Enabled); err != nil {
			rows.Close()
			return nil, err
		}
		p.Effect = domain.Effect(effect)
		index[p.ID] = len(policies)
		policies = append(policies, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(policies) == 0 {
		return policies, err
	}
	ids := make([]string, 0, len(policies))
	for id := range index {
		ids = append(ids, id)
	}

	type node struct {
		policyID, parent string
		group            *domain.ConditionGroup
	}
	nodes := map[string]*node{}
	order := []string{}
	grows, err := r.db.Query(ctx, `SELECT id::text, policy_id::text, COALESCE(parent_group_id::text,''), logical_operator, negate
		FROM guard_policy_condition_group WHERE policy_id = ANY($1::uuid[]) ORDER BY position, id`, ids)
	if err != nil {
		return nil, err
	}
	for grows.Next() {
		var id, op string
		n := &node{group: &domain.ConditionGroup{Conditions: []domain.Condition{}, Groups: []domain.ConditionGroup{}}}
		if err := grows.Scan(&id, &n.policyID, &n.parent, &op, &n.group.Negate); err != nil {
			grows.Close()
			return nil, err
		}
		n.group.Operator = domain.LogicalOperator(op)
		nodes[id] = n
		order = append(order, id)
	}
	grows.Close()
	if err := grows.Err(); err != nil {
		return nil, err
	}

	crows, err := r.db.Query(ctx, `SELECT c.group_id::text, c.field, c.operator, c.value
		FROM guard_policy_condition c JOIN guard_policy_condition_group g ON g.id = c.group_id
		WHERE g.policy_id = ANY($1::uuid[]) ORDER BY c.position, c.id`, ids)
	if err != nil {
		return nil, err
	}
	for crows.Next() {
		var gid, op string
		var c domain.Condition
		if err := crows.Scan(&gid, &c.Field, &op, &c.Value); err != nil {
			crows.Close()
			return nil, err
		}
		c.Operator = domain.Operator(op)
		if n := nodes[gid]; n != nil {
			n.group.Conditions = append(n.group.Conditions, c)
		}
	}
	crows.Close()
	if err := crows.Err(); err != nil {
		return nil, err
	}

	// Attach children bottom-up so value copies carry their full subtree.
	children := map[string][]string{}
	for _, id := range order {
		if p := nodes[id].parent; p != "" {
			children[p] = append(children[p], id)
		}
	}
	var build func(id string, depth int) domain.ConditionGroup
	build = func(id string, depth int) domain.ConditionGroup {
		g := *nodes[id].group
		if depth >= domain.MaxConditionDepth {
			return g
		}
		for _, c := range children[id] {
			g.Groups = append(g.Groups, build(c, depth+1))
		}
		return g
	}
	for _, id := range order {
		n := nodes[id]
		if n.parent == "" {
			root := build(id, 1)
			policies[index[n.policyID]].Root = &root
		}
	}
	return policies, nil
}
