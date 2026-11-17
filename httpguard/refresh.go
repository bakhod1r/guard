package httpguard

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/bakhod1r/guard"
	sessiondomain "github.com/bakhod1r/guard/session/domain"
)

// Access and refresh tokens (guard.Config.AccessToken).
//
// The access token travels in the JSON body and as Authorization: Bearer.
// The refresh token (the session token) lives only in an HttpOnly,
// SameSite=Strict cookie scoped to RefreshCookiePath, so scripts cannot read
// it and the browser sends it to the auth routes alone.

// TokenResponse is the body of login and refresh with access tokens enabled.
type TokenResponse struct {
	AccessToken      guard.AccessToken `json:"access_token"`
	TokenType        string            `json:"token_type"`
	ExpiresAt        time.Time         `json:"expires_at"`
	ExpiresIn        int               `json:"expires_in"`
	RefreshExpiresAt time.Time         `json:"refresh_expires_at"`
}

// NewTokenResponse describes an access token and the session it derives from.
func NewTokenResponse(access guard.AccessToken, claims guard.AccessClaims, s *guard.Session) TokenResponse {
	return TokenResponse{AccessToken: access, TokenType: "Bearer", ExpiresAt: claims.ExpiresAt,
		ExpiresIn: int(time.Until(claims.ExpiresAt).Seconds()), RefreshExpiresAt: s.ExpiresAt}
}

func (o Options) refreshCookie(value string, maxAge int) *http.Cookie {
	//nolint:gosec // G124: HttpOnly and SameSite=Strict are set; Secure unless InsecureCookie (local HTTP only).
	return &http.Cookie{
		Name: o.RefreshCookieName, Value: value, Path: o.RefreshCookiePath, Domain: o.CookieDomain,
		MaxAge: maxAge, Secure: !o.InsecureCookie, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	}
}

// SetRefreshCookie stores the refresh token until the session's absolute expiry.
func SetRefreshCookie(w http.ResponseWriter, opts Options, tok guard.SessionToken, s *guard.Session) {
	o := opts.withDefaults()
	maxAge := max(int(time.Until(s.ExpiresAt).Seconds()), 1)
	http.SetCookie(w, o.refreshCookie(string(tok), maxAge))
}

// ClearRefreshCookie deletes the refresh cookie.
func ClearRefreshCookie(w http.ResponseWriter, opts Options) {
	http.SetCookie(w, opts.withDefaults().refreshCookie("", -1))
}

// RefreshTokenFrom reads the refresh token: the cookie, or for non-browser
// clients Authorization: Bearer <refresh token>. fromCookie is true for the
// cookie, which then needs CSRFOK on unsafe methods.
func RefreshTokenFrom(r *http.Request, opts Options) (tok string, fromCookie bool) {
	o := opts.withDefaults()
	if c, err := r.Cookie(o.RefreshCookieName); err == nil && c.Value != "" {
		return c.Value, true
	}
	if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:]), false
	}
	return "", false
}

// CSRFOK applies the cookie CSRF rule (Origin/Referer against TrustedOrigins,
// or the X-Guard-CSRF: 1 header) to r.
func CSRFOK(r *http.Request, opts Options) bool { return csrfOK(r, opts.withDefaults()) }

// refresh rotates the refresh token and issues a new access token.
func (h *handlers) refresh(w http.ResponseWriter, r *http.Request) {
	tok, cookie := RefreshTokenFrom(r, h.o)
	if tok == "" {
		abort(w, r, http.StatusUnauthorized, "unauthenticated", "refresh token required")
		return
	}
	if cookie && !csrfOK(r, h.o) {
		abort(w, r, http.StatusForbidden, "csrf", "cross-site request refused")
		return
	}
	s, next, err := h.g.RotateSession(r.Context(), guard.SessionToken(tok))
	if err != nil {
		if errors.Is(err, sessiondomain.ErrSessionNotFound) || errors.Is(err, sessiondomain.ErrSessionExpired) {
			if cookie {
				ClearRefreshCookie(w, h.o)
			}
			abort(w, r, http.StatusUnauthorized, "unauthenticated", "refresh token expired or revoked")
			return
		}
		fail(w, r, err) // storage outage: keep the cookie, the client retries
		return
	}
	access, claims, _ := h.g.IssueAccess(s)
	SetRefreshCookie(w, h.o, next, s)
	writeJSON(w, r, http.StatusOK, NewTokenResponse(access, claims, s))
}
