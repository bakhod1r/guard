package httpguard

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// DefaultMaxBodyBytes caps request bodies on Guard routes (1 MiB).
const DefaultMaxBodyBytes int64 = 1 << 20

// CSRFHeader lets non-browser clients that authenticate with the session
// cookie opt out of the Origin check. Browsers cannot set it cross-site
// without a CORS preflight.
const CSRFHeader = "X-Guard-CSRF"

// DefaultErrorLogger logs internal errors through slog.Default.
func DefaultErrorLogger(r *http.Request, err error) {
	slog.Default().Error("guard: internal error", "method", r.Method, "path", r.URL.Path, "error", err)
}

// ErrorLogging makes fn receive internal errors and limiter failures raised by
// Guard middleware further down the chain (e.g. a standalone RateLimit).
// Mount installs it automatically with Options.ErrorLogger.
func ErrorLogging(fn func(*http.Request, error)) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, withErrorLogger(r, fn))
		})
	}
}

// withErrorLogger installs fn unless an outer layer already did.
func withErrorLogger(r *http.Request, fn func(*http.Request, error)) *http.Request {
	if _, ok := r.Context().Value(errorLoggerKey).(func(*http.Request, error)); ok {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), errorLoggerKey, fn))
}

// logError hands err to the configured logger. Error details never reach the
// response body.
func logError(r *http.Request, err error) {
	if fn, ok := r.Context().Value(errorLoggerKey).(func(*http.Request, error)); ok {
		fn(r, err)
		return
	}
	DefaultErrorLogger(r, err)
}

// SecurityHeaders sets nosniff, same-origin referrer, frame denial and, when the
// request arrived over TLS or Options.HSTS is true, Strict-Transport-Security.
func SecurityHeaders(opts ...Options) Middleware {
	hsts := false
	for _, o := range opts {
		hsts = hsts || o.HSTS
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "same-origin")
			h.Set("X-Frame-Options", "DENY")
			if hsts || r.TLS != nil {
				h.Set("Strict-Transport-Security", "max-age=63072000")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// LimitBody rejects bodies over limit with 413 and caps streamed bodies so
// decoding fails once the limit is crossed. limit <= 0 uses DefaultMaxBodyBytes.
func LimitBody(limit int64) Middleware {
	if limit <= 0 {
		limit = DefaultMaxBodyBytes
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > limit {
				abort(w, r, http.StatusRequestEntityTooLarge, "body_too_large", "request body too large")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
			next.ServeHTTP(w, r)
		})
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
func csrfOK(r *http.Request, o Options) bool {
	if !unsafeMethod(r.Method) || r.Header.Get(CSRFHeader) == "1" {
		return true
	}
	src := r.Header.Get("Origin")
	if src == "" {
		src = r.Header.Get("Referer")
	}
	u, err := url.Parse(src)
	if src == "" || err != nil || u.Host == "" {
		return false
	}
	if len(o.TrustedOrigins) == 0 {
		return strings.EqualFold(u.Host, r.Host)
	}
	for _, t := range o.TrustedOrigins {
		scheme, host := originParts(t)
		if strings.EqualFold(u.Host, host) && (scheme == "" || strings.EqualFold(u.Scheme, scheme)) {
			return true
		}
	}
	return false
}

// originParts accepts "https://app.example.com" (scheme enforced, so a
// plain-HTTP origin on the same host is not trusted) or "app.example.com"
// (any scheme).
func originParts(s string) (scheme, host string) {
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		return u.Scheme, u.Host
	}
	return "", s
}

// chain applies middleware left to right: chain(h, a, b) runs a, then b, then h.
func chain(h http.Handler, mw ...Middleware) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}
