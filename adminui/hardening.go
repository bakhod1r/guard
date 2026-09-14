package adminui

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// DefaultMaxBodyBytes caps form bodies (1 MiB).
const DefaultMaxBodyBytes int64 = 1 << 20

const nonceKey = "adminui.nonce"

// DefaultErrorLogger logs internal errors through slog.Default.
func DefaultErrorLogger(c *gin.Context, err error) {
	slog.Default().Error("adminui: internal error", "method", c.Request.Method, "path", c.Request.URL.Path, "error", err)
}

// logError records err on the context and hands it to the configured logger.
func (a *app) logError(c *gin.Context, err error) {
	_ = c.Error(err)
	if a.o.ErrorLogger != nil {
		a.o.ErrorLogger(c, err)
		return
	}
	DefaultErrorLogger(c, err)
}

// noStore sets caching, framing, indexing and a per-request nonce CSP: only
// the page's own nonce'd <style>/<script> run, so injected markup cannot
// execute script, restyle the page, or post forms elsewhere.
func (a *app) noStore(c *gin.Context) {
	b := make([]byte, 18)
	_, _ = rand.Read(b)                              // never fails since Go 1.24 (crashes the process instead)
	nonce := base64.RawURLEncoding.EncodeToString(b) // URL alphabet: html/template escapes "+"
	c.Set(nonceKey, nonce)
	h := c.Writer.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Robots-Tag", "noindex, nofollow")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+"'; "+
		"img-src 'self' data:; object-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	c.Next()
}

// limitBody caps request bodies and parses forms eagerly so an oversized or
// malformed body is rejected before any handler reads a truncated form.
func (a *app) limitBody(c *gin.Context) {
	if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead {
		c.Next()
		return
	}
	if c.Request.ContentLength > a.o.MaxBodyBytes {
		a.bodyError(c, http.StatusRequestEntityTooLarge)
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, a.o.MaxBodyBytes)
	if err := c.Request.ParseForm(); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			a.bodyError(c, http.StatusRequestEntityTooLarge)
			return
		}
		a.bodyError(c, http.StatusBadRequest)
		return
	}
	c.Next()
}

func (a *app) bodyError(c *gin.Context, status int) {
	msg := "The submitted form is too large."
	if status == http.StatusBadRequest {
		msg = "The submitted form could not be read."
	}
	a.render(c, status, "error", "Bad request", "", map[string]string{"Message": msg})
	c.Abort()
}

// limitLogin throttles sign-in attempts per client IP. Limiter failures fail
// open (logged) so a Redis outage does not lock administrators out.
func (a *app) limitLogin(c *gin.Context) {
	rule := a.o.LoginRateLimit
	if rule.Limit < 0 || a.g.Limiter == nil {
		c.Next()
		return
	}
	res, err := a.g.Limiter.Allow(c.Request.Context(), "adminui-login:ip:"+c.ClientIP(), rule)
	if err != nil {
		a.logError(c, err)
		c.Next()
		return
	}
	if !res.Allowed {
		c.Header("Retry-After", strconv.Itoa(int(math.Ceil(res.RetryAfter.Seconds()))))
		a.render(c, http.StatusTooManyRequests, "error", "Too many attempts", "", map[string]string{
			"Message": "Too many sign-in attempts. Try again later.",
		})
		c.Abort()
		return
	}
	c.Next()
}

// revokeCookieSession ends the session the login request already carried so a
// planted or stale session cookie cannot survive a fresh sign-in.
func (a *app) revokeCookieSession(c *gin.Context) {
	old, err := c.Cookie(a.o.CookieName)
	if err != nil || old == "" {
		return
	}
	ctx := c.Request.Context()
	p, err := a.g.Authenticate(ctx, old)
	if err != nil || p.Session == nil {
		return
	}
	if err := a.g.Sessions.Revoke(ctx, p.Session.ID); err != nil {
		a.logError(c, err)
	}
}
