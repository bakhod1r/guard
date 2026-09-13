package adminui

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	apikeydomain "github.com/bakhod1r/guard/apikey/domain"
	identitydomain "github.com/bakhod1r/guard/identity/domain"
	sessiondomain "github.com/bakhod1r/guard/session/domain"
)

// registerSecurity mounts the self-service page: the signed-in user's own
// sessions, API keys and password. No permission is required because every
// operation is scoped to ginPrincipal(c).User.
func (a *app) registerSecurity(r *gin.RouterGroup) {
	r.GET("/security", a.securityPage)
	r.POST("/security/sessions/revoke-others", a.securityRevokeOthers)
	r.POST("/security/sessions/:id/revoke", a.securityRevokeSession)
	r.POST("/security/api-keys", a.securityIssueKey)
	r.POST("/security/api-keys/:id/revoke", a.securityRevokeKey)
	r.POST("/security/password", a.securityChangePassword)
}

type securitySession struct {
	*sessiondomain.Session
	Current bool
}

type securityKey struct {
	ID, Name, Prefix, Status string
	Scopes                   []string
	CreatedAt                time.Time
	LastUsedAt, ExpiresAt    *time.Time
}

func (a *app) securityPage(c *gin.Context) {
	p := ginPrincipal(c)
	ctx := c.Request.Context()
	sessions, err := a.g.Sessions.List(ctx, string(p.User.ID))
	var keys []apikeydomain.Key
	if err == nil {
		keys, err = a.g.APIKeys.List(ctx, string(p.User.ID))
	}
	if err != nil {
		_ = c.Error(err)
		a.render(c, http.StatusInternalServerError, "error", "Error", "security", map[string]string{"Message": "internal error"})
		return
	}

	now := time.Now()
	data := struct {
		Sessions []securitySession
		Keys     []securityKey
	}{}
	for _, s := range sessions {
		data.Sessions = append(data.Sessions, securitySession{Session: s, Current: s.ID == p.Session.ID})
	}
	for i := range keys {
		k := &keys[i]
		status := "active"
		switch {
		case k.RevokedAt != nil:
			status = "revoked"
		case k.Usable(now) != nil:
			status = "expired"
		}
		data.Keys = append(data.Keys, securityKey{ID: k.ID, Name: k.Name, Prefix: k.Prefix, Status: status,
			Scopes: k.Scopes, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt, ExpiresAt: k.ExpiresAt})
	}
	a.render(c, http.StatusOK, "security", "My sessions & API keys", "security", data)
}

func (a *app) securityRevokeSession(c *gin.Context) {
	id := sessiondomain.ID(c.Param("id"))
	if err := a.securityRevokeOwn(c, id); err != nil {
		a.fail(c, "/security", err)
		return
	}
	a.audit(c, "session.revoke", string(id), nil)
	a.redirect(c, "/security", "Session revoked")
}

// securityRevokeOwn revokes id only if it is one of the caller's sessions
// and not the one making the request.
func (a *app) securityRevokeOwn(c *gin.Context, id sessiondomain.ID) error {
	p := ginPrincipal(c)
	if id == p.Session.ID {
		return fmt.Errorf("%w: this is your current session, use sign out", errBadInput)
	}
	sessions, err := a.g.Sessions.List(c.Request.Context(), string(p.User.ID))
	if err != nil {
		return err
	}
	for _, s := range sessions {
		if s.ID == id {
			return a.g.Sessions.Revoke(c.Request.Context(), id)
		}
	}
	return sessiondomain.ErrSessionNotFound
}

// securityRevokeOthersFor revokes every session of the caller except the current one.
func (a *app) securityRevokeOthersFor(c *gin.Context) (int, error) {
	p := ginPrincipal(c)
	sessions, err := a.g.Sessions.List(c.Request.Context(), string(p.User.ID))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, s := range sessions {
		if s.ID == p.Session.ID {
			continue
		}
		if err := a.g.Sessions.Revoke(c.Request.Context(), s.ID); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (a *app) securityRevokeOthers(c *gin.Context) {
	n, err := a.securityRevokeOthersFor(c)
	if err != nil {
		a.fail(c, "/security", err)
		return
	}
	a.audit(c, "session.revoke_others", string(ginPrincipal(c).User.ID), map[string]any{"revoked": n})
	a.redirect(c, "/security", fmt.Sprintf("Signed out %d other session(s)", n))
}

// securityScopes splits on newlines and commas, dropping blanks.
func securityScopes(raw string) []string {
	var out []string
	for _, s := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (a *app) securityIssueKey(c *gin.Context) {
	var expires *time.Time
	if raw := strings.TrimSpace(c.PostForm("expires_at")); raw != "" {
		t, err := time.ParseInLocation("2006-01-02T15:04", raw, time.Local)
		if err != nil {
			a.fail(c, "/security", fmt.Errorf("%w: expires_at must be a date and time", errBadInput))
			return
		}
		expires = &t
	}
	k, tok, err := a.g.IssueAPIKey(c.Request.Context(), ginPrincipal(c), c.PostForm("name"),
		securityScopes(c.PostForm("scopes")), expires, a.meta(c))
	if err != nil {
		a.fail(c, "/security", err)
		return
	}
	// Rendered directly (no redirect) so the secret never lands in a URL,
	// access log or browser history. Cache-Control: no-store is set by Mount.
	a.render(c, http.StatusCreated, "security_key_created", "API key created", "security", map[string]any{
		"Key": k, "Token": string(tok),
	})
}

func (a *app) securityRevokeKey(c *gin.Context) {
	id := c.Param("id")
	if err := a.g.APIKeys.Revoke(c.Request.Context(), string(ginPrincipal(c).User.ID), id); err != nil {
		a.fail(c, "/security", err)
		return
	}
	a.audit(c, "apikey.revoke", id, nil)
	a.redirect(c, "/security", "API key revoked")
}

func (a *app) securityChangePassword(c *gin.Context) {
	p := ginPrincipal(c)
	err := fmt.Errorf("%w: new password and confirmation do not match", errBadInput)
	n := 0
	if c.PostForm("new_password") == c.PostForm("confirm_password") {
		err = a.g.Identity.ChangePassword(c.Request.Context(), identitydomain.UserID(p.User.ID), c.PostForm("old_password"), c.PostForm("new_password"))
		if err == nil {
			n, err = a.securityRevokeOthersFor(c)
		}
	}
	if err != nil {
		a.fail(c, "/security", err)
		return
	}
	a.audit(c, "account.password_change", string(p.User.ID), map[string]any{"sessions_revoked": n})
	a.redirect(c, "/security", "Password changed; other sessions signed out")
}
