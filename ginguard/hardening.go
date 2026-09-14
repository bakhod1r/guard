package ginguard

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

// DefaultMaxBodyBytes caps request bodies on Guard routes (1 MiB).
const DefaultMaxBodyBytes int64 = 1 << 20

// CSRFHeader lets non-browser clients that authenticate with the session
// cookie opt out of the Origin check. Browsers cannot set it cross-site
// without a CORS preflight.
const CSRFHeader = "X-Guard-CSRF"

const errorLoggerKey = "guard.error_logger"

// DefaultErrorLogger logs internal errors through slog.Default.
func DefaultErrorLogger(c *gin.Context, err error) {
	slog.Default().Error("guard: internal error", "method", c.Request.Method, "path", c.Request.URL.Path, "error", err)
}

// ErrorLogging makes fn receive internal errors and limiter failures raised
// by Guard middleware further down the chain (e.g. a standalone RateLimit).
// Mount installs it automatically with Options.ErrorLogger.
func ErrorLogging(fn func(*gin.Context, error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(errorLoggerKey, fn)
		c.Next()
	}
}

// logError records err on the context and hands it to the configured logger.
// Error details never reach the response body.
func logError(c *gin.Context, err error) {
	_ = c.Error(err)
	if fn, ok := c.Get(errorLoggerKey); ok {
		fn.(func(*gin.Context, error))(c, err)
		return
	}
	DefaultErrorLogger(c, err)
}

// SecurityHeaders sets nosniff, same-origin referrer, frame denial and, when the
// request arrived over TLS or Options.HSTS is true, Strict-Transport-Security.
func SecurityHeaders(opts ...Options) gin.HandlerFunc {
	hsts := false
	for _, o := range opts {
		hsts = hsts || o.HSTS
	}
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		if hsts || c.Request.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=63072000")
		}
		c.Next()
	}
}

// limitBody rejects bodies over limit with 413 and caps streamed bodies so
// binding fails once the limit is crossed.
func limitBody(limit int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > limit {
			abort(c, http.StatusRequestEntityTooLarge, "body_too_large", "request body too large")
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		c.Next()
	}
}

func isTooLarge(err error) bool {
	var mbe *http.MaxBytesError
	return errors.As(err, &mbe)
}

func unsafeMethod(m string) bool {
	return m != http.MethodGet && m != http.MethodHead && m != http.MethodOptions && m != http.MethodTrace
}

// csrfOK reports whether a cookie-authenticated request may proceed: safe
// methods always; unsafe ones need X-Guard-CSRF: 1 or a trusted Origin/Referer.
func csrfOK(c *gin.Context, o Options) bool {
	if !unsafeMethod(c.Request.Method) || c.GetHeader(CSRFHeader) == "1" {
		return true
	}
	src := c.GetHeader("Origin")
	if src == "" {
		src = c.GetHeader("Referer")
	}
	u, err := url.Parse(src)
	if src == "" || err != nil || u.Host == "" {
		return false
	}
	if len(o.TrustedOrigins) == 0 {
		return strings.EqualFold(u.Host, c.Request.Host)
	}
	for _, t := range o.TrustedOrigins {
		if strings.EqualFold(u.Host, originHost(t)) {
			return true
		}
	}
	return false
}

// originHost accepts "https://app.example.com" or "app.example.com".
func originHost(s string) string {
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		return u.Host
	}
	return s
}
