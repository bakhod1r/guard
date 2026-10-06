package domain

// LiftRoleConditions rewrites the legacy role-gate shape into Policy.Roles:
//
//	root = AND{conditions: [], groups: [OR{user.roles contains r…}, body?]}
//
// where the OR group holds only single-value "user.roles contains" conditions,
// with no negate and no subgroups. Roles receives those roles and Root becomes
// body (nil without one). Any other shape, or a policy already bound to roles,
// is left untouched. It reports whether p changed.
func LiftRoleConditions(p *Policy) bool {
	root := p.Root
	if len(p.Roles) > 0 || root == nil || root.Negate || root.Operator != And ||
		len(root.Conditions) != 0 || len(root.Groups) == 0 || len(root.Groups) > 2 {
		return false
	}
	gate := root.Groups[0]
	if gate.Negate || gate.Operator != Or || len(gate.Groups) != 0 || len(gate.Conditions) == 0 {
		return false
	}
	roles := make([]string, 0, len(gate.Conditions))
	for _, c := range gate.Conditions {
		if c.Field != "user.roles" || c.Operator != OpContains ||
			len(c.Value) != 1 || !nameRe.MatchString(c.Value[0]) {
			return false
		}
		roles = append(roles, c.Value[0])
	}
	p.Roles = roles
	if len(root.Groups) == 2 {
		body := root.Groups[1]
		p.Root = &body
	} else {
		p.Root = nil
	}
	_ = p.normalizeRoles() // every role already matched nameRe
	return true
}
