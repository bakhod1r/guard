// Package domain holds authorization rules: RBAC roles/permissions and ABAC policies.
//
// Decision algorithm (fail-closed):
//  1. Enabled policies matching (resource, action) whose condition tree holds
//     are sorted by priority ASC (lower number = stronger).
//  2. The strongest priority tier decides; inside a tier DENY overrides ALLOW.
//  3. No policy matched: RBAC decides — a wildcard role or a granted
//     permission allows.
//  4. Otherwise deny.
package domain

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	ErrRoleNotFound       = errors.New("access: role not found")
	ErrRoleExists         = errors.New("access: role already exists")
	ErrSystemRole         = errors.New("access: system role cannot be deleted")
	ErrPermissionNotFound = errors.New("access: permission not found")
	ErrPolicyNotFound     = errors.New("access: policy not found")
	ErrPolicyNameTaken    = errors.New("access: policy name already exists")
	ErrSubjectNotFound    = errors.New("access: user not found")
	ErrInvalidName        = errors.New("access: name must match [a-z0-9_-]{2,64}")
	ErrInvalidPermission  = errors.New("access: permission code must be resource.action")
	ErrInvalidPolicy      = errors.New("access: invalid policy")
)

// MaxConditionDepth bounds the condition tree. Deeper trees evaluate to false.
const MaxConditionDepth = 8

var nameRe = regexp.MustCompile(`^[a-z0-9_\-]{2,64}$`)
var partRe = regexp.MustCompile(`^[a-z0-9_\-]{1,64}$`)

// Permission is identified by code "resource.action".
type Permission struct {
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description,omitempty"`
}

func ParsePermission(code string) (Permission, error) {
	res, act, ok := strings.Cut(strings.TrimSpace(code), ".")
	if !ok || !partRe.MatchString(res) || !partRe.MatchString(act) {
		return Permission{}, ErrInvalidPermission
	}
	return Permission{Resource: res, Action: act}, nil
}

func (p Permission) Code() string { return p.Resource + "." + p.Action }

func (p Permission) Allows(resource, action string) bool {
	return p.Resource == resource && p.Action == action
}

type Role struct {
	Name        string       `json:"name"`
	Title       string       `json:"title"`
	Description string       `json:"description,omitempty"`
	IsSystem    bool         `json:"is_system"`
	Wildcard    bool         `json:"wildcard"`
	Permissions []Permission `json:"permissions"`
}

func NewRole(name, title, description string, wildcard bool) (*Role, error) {
	if !nameRe.MatchString(name) {
		return nil, ErrInvalidName
	}
	if strings.TrimSpace(title) == "" {
		title = name
	}
	return &Role{Name: name, Title: title, Description: description, Wildcard: wildcard, Permissions: []Permission{}}, nil
}

func (r Role) Allows(resource, action string) bool {
	if r.Wildcard {
		return true
	}
	for _, p := range r.Permissions {
		if p.Allows(resource, action) {
			return true
		}
	}
	return false
}

// RoleGrant is a role held by a user, optionally time-bound.
type RoleGrant struct {
	Role      Role       `json:"role"`
	GrantedAt time.Time  `json:"granted_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func (g RoleGrant) Active(now time.Time) bool { return g.ExpiresAt == nil || now.Before(*g.ExpiresAt) }

type Effect string

const (
	Allow Effect = "allow"
	Deny  Effect = "deny"
)

type Operator string

const (
	OpEq       Operator = "eq"
	OpNe       Operator = "ne"
	OpGt       Operator = "gt"
	OpLt       Operator = "lt"
	OpGte      Operator = "gte"
	OpLte      Operator = "lte"
	OpIn       Operator = "in"
	OpNotIn    Operator = "not_in"
	OpContains Operator = "contains"
)

var operators = map[Operator]bool{OpEq: true, OpNe: true, OpGt: true, OpLt: true, OpGte: true, OpLte: true, OpIn: true, OpNotIn: true, OpContains: true}

type LogicalOperator string

const (
	And LogicalOperator = "and"
	Or  LogicalOperator = "or"
)

// Condition compares Field (user.*, subject.*, resource.*, env.*) against Value.
// A value starting with "$" is an attribute reference, e.g. "$user.id".
// Scalar operators use Value[0]; in/not_in use every element.
type Condition struct {
	Field    string   `json:"field"`
	Operator Operator `json:"operator"`
	Value    []string `json:"value"`
}

// ConditionGroup is a node of the condition tree.
type ConditionGroup struct {
	Operator   LogicalOperator  `json:"operator"`
	Negate     bool             `json:"negate"`
	Conditions []Condition      `json:"conditions"`
	Groups     []ConditionGroup `json:"groups"`
}

type Policy struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Resource string          `json:"resource"`
	Action   string          `json:"action"`
	Effect   Effect          `json:"effect"`
	Priority int             `json:"priority"`
	Enabled  bool            `json:"enabled"`
	Root     *ConditionGroup `json:"root,omitempty"`
}

func (p *Policy) Validate() error {
	if p.Effect != Allow && p.Effect != Deny {
		return fmt.Errorf("%w: effect must be allow or deny", ErrInvalidPolicy)
	}
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidPolicy)
	}
	if !validTarget(p.Resource) || !validTarget(p.Action) {
		return fmt.Errorf("%w: resource and action must be a name or *", ErrInvalidPolicy)
	}
	if p.Root != nil {
		return p.Root.validate(1)
	}
	return nil
}

func validTarget(s string) bool { return s == "*" || partRe.MatchString(s) }

func (g *ConditionGroup) validate(depth int) error {
	if depth > MaxConditionDepth {
		return fmt.Errorf("%w: condition tree deeper than %d", ErrInvalidPolicy, MaxConditionDepth)
	}
	if g.Operator == "" {
		g.Operator = And
	}
	if g.Operator != And && g.Operator != Or {
		return fmt.Errorf("%w: group operator must be and/or", ErrInvalidPolicy)
	}
	for _, c := range g.Conditions {
		if !operators[c.Operator] {
			return fmt.Errorf("%w: unknown operator %q", ErrInvalidPolicy, c.Operator)
		}
		if !validPath(c.Field) {
			return fmt.Errorf("%w: field %q must start with user., subject., resource. or env.", ErrInvalidPolicy, c.Field)
		}
		if len(c.Value) == 0 {
			return fmt.Errorf("%w: condition %q needs a value", ErrInvalidPolicy, c.Field)
		}
		if c.Operator != OpIn && c.Operator != OpNotIn && len(c.Value) != 1 {
			return fmt.Errorf("%w: operator %q takes exactly one value", ErrInvalidPolicy, c.Operator)
		}
	}
	for i := range g.Groups {
		if err := g.Groups[i].validate(depth + 1); err != nil {
			return err
		}
	}
	return nil
}

func validPath(p string) bool {
	for _, prefix := range []string{"user.", "subject.", "resource.", "env."} {
		if strings.HasPrefix(p, prefix) && len(p) > len(prefix) {
			return true
		}
	}
	return false
}

type Subject struct {
	ID         string
	Roles      []Role
	Attributes map[string]any
}

type Resource struct {
	Type       string
	ID         string
	Attributes map[string]any
}

type Request struct {
	Subject     Subject
	Action      string
	Resource    Resource
	Environment map[string]any
}

type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

func (p *Policy) Matches(r Request) bool {
	if !p.Enabled {
		return false
	}
	if (p.Resource != "*" && p.Resource != r.Resource.Type) || (p.Action != "*" && p.Action != r.Action) {
		return false
	}
	return p.Root == nil || p.Root.holds(r, 1)
}

// Decide evaluates ABAC policies by priority, then falls back to RBAC.
func Decide(r Request, policies []Policy) Decision {
	matched := make([]Policy, 0, len(policies))
	for _, p := range policies {
		if p.Matches(r) {
			matched = append(matched, p)
		}
	}
	if len(matched) > 0 {
		sort.SliceStable(matched, func(i, j int) bool { return matched[i].Priority < matched[j].Priority })
		top := matched[0].Priority
		for _, p := range matched {
			if p.Priority != top {
				break
			}
			if p.Effect == Deny {
				return Decision{Allowed: false, Reason: "denied by policy " + p.Name}
			}
		}
		return Decision{Allowed: true, Reason: "allowed by policy " + matched[0].Name}
	}
	for _, role := range r.Subject.Roles {
		if role.Allows(r.Resource.Type, r.Action) {
			return Decision{Allowed: true, Reason: "granted by role " + role.Name}
		}
	}
	return Decision{Allowed: false, Reason: "no matching permission or policy"}
}

type RoleRepository interface {
	CreateRole(ctx context.Context, r *Role) error
	DeleteRole(ctx context.Context, name string) error
	Role(ctx context.Context, name string) (*Role, error)
	ListRoles(ctx context.Context) ([]Role, error)
	CreatePermission(ctx context.Context, p Permission) error
	ListPermissions(ctx context.Context) ([]Permission, error)
	GrantPermission(ctx context.Context, role string, p Permission, grantedBy string) error
	RevokePermission(ctx context.Context, role string, p Permission) error
	AssignRole(ctx context.Context, userID, role, grantedBy string, expiresAt *time.Time) error
	UnassignRole(ctx context.Context, userID, role string) error
	GrantsOf(ctx context.Context, userID string) ([]RoleGrant, error)
}

type PolicyRepository interface {
	SavePolicy(ctx context.Context, p *Policy) error
	DeletePolicy(ctx context.Context, id string) error
	Policy(ctx context.Context, id string) (*Policy, error)
	ListPolicies(ctx context.Context) ([]Policy, error)
	// ApplicablePolicies returns enabled policies targeting resource/action (or *).
	ApplicablePolicies(ctx context.Context, resource, action string) ([]Policy, error)
}
