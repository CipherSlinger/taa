package mock

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"math"
	"net"
	"net/http"
	"time"
)

// consoleLoginAttempt tracks the failures seen from one source address. The
// counter is per address, not per account, because the console has exactly one
// account: keying it on the name would make every client share one lockout.
type consoleLoginAttempt struct {
	Failures    int
	LockedUntil time.Time
}

// consoleSession is one signed-in browser. The map key is the opaque cookie
// value, so a session is revoked by deleting it; there is no server-side
// identity the client could reconstruct from the token.
type consoleSession struct {
	User        string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	RefreshedAt time.Time
}

type consoleUserInfo struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

type consoleLoginResponse struct {
	OK        bool             `json:"ok"`
	User      *consoleUserInfo `json:"user,omitempty"`
	ExpiresAt string           `json:"expiresAt,omitempty"`
}

// consoleLoginFailure carries both optional fields; only the one that applies
// is set, and a zero attemptsLeft is still meaningful, hence the pointers.
type consoleLoginFailure struct {
	OK                bool   `json:"ok"`
	Error             string `json:"error"`
	AttemptsLeft      *int   `json:"attemptsLeft,omitempty"`
	RetryAfterSeconds *int   `json:"retryAfterSeconds,omitempty"`
}

type consoleSessionResponse struct {
	Authenticated bool             `json:"authenticated"`
	User          *consoleUserInfo `json:"user,omitempty"`
	ExpiresAt     string           `json:"expiresAt,omitempty"`
}

type consoleOKResponse struct {
	OK bool `json:"ok"`
}

// newSessionToken mints the cookie value. A read failure is fatal for the
// login rather than a fallback to a predictable token; the caller turns the
// empty string into a 500.
func newSessionToken() string {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(raw[:])
}

// credentialsMatch compares both fields in constant time. The two comparisons
// are evaluated before they are combined so a mismatched user name does not
// short-circuit the password comparison and reveal which half was wrong.
func credentialsMatch(gotUser, gotPass, wantUser, wantPass string) bool {
	userOK := subtle.ConstantTimeCompare([]byte(gotUser), []byte(wantUser)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(gotPass), []byte(wantPass)) == 1
	return userOK && passOK
}

// consoleClientIP is the lockout key. X-Forwarded-For is deliberately ignored:
// it is client-controlled, so honouring it would let an attacker pick a fresh
// identity per attempt and never trip the lockout.
func consoleClientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func (c *llmConsole) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !consoleRequireMethod(w, r, http.MethodPost) {
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, consoleLoginFailure{Error: "登录请求格式错误"})
		return
	}

	ip := consoleClientIP(r)
	now := c.now()

	c.mu.Lock()
	if att := c.attempts[ip]; att != nil && !att.LockedUntil.IsZero() {
		if now.Before(att.LockedUntil) {
			seconds := int(math.Ceil(att.LockedUntil.Sub(now).Seconds()))
			if seconds < 1 {
				seconds = 1
			}
			c.mu.Unlock()
			writeJSON(w, http.StatusTooManyRequests, consoleLoginFailure{
				Error:             "尝试次数过多，请稍后再试",
				RetryAfterSeconds: &seconds,
			})
			return
		}
		// The lockout has elapsed: start a fresh window.
		att.LockedUntil = time.Time{}
		att.Failures = 0
	}
	c.mu.Unlock()

	if !credentialsMatch(body.Username, body.Password, c.user, c.password) {
		c.mu.Lock()
		att := c.attempts[ip]
		if att == nil {
			att = &consoleLoginAttempt{}
			c.attempts[ip] = att
		}
		att.Failures++
		if att.Failures >= consoleMaxLoginFailures {
			// The lock is the response to the fifth failure, so the caller is told
			// how long to wait now instead of being sent back for one more try.
			att.Failures = 0
			att.LockedUntil = now.Add(consoleLockoutDuration)
			seconds := int(consoleLockoutDuration.Seconds())
			c.mu.Unlock()
			writeJSON(w, http.StatusTooManyRequests, consoleLoginFailure{
				Error:             "尝试次数过多，请稍后再试",
				RetryAfterSeconds: &seconds,
			})
			return
		}
		remaining := consoleMaxLoginFailures - att.Failures
		c.mu.Unlock()
		writeJSON(w, http.StatusUnauthorized, consoleLoginFailure{
			Error:        "用户名或口令错误",
			AttemptsLeft: &remaining,
		})
		return
	}

	c.mu.Lock()
	delete(c.attempts, ip)
	c.pruneSessionsLocked(now)
	token := newSessionToken()
	if token == "" {
		c.mu.Unlock()
		writeJSON(w, http.StatusInternalServerError, consoleLoginFailure{Error: "生成会话失败"})
		return
	}
	sess := &consoleSession{
		User:        c.user,
		CreatedAt:   now,
		ExpiresAt:   now.Add(consoleSessionTTL),
		RefreshedAt: now,
	}
	c.sessions[token] = sess
	expiresAt := sess.ExpiresAt
	c.mu.Unlock()

	c.setSessionCookie(w, token, expiresAt)
	writeJSON(w, http.StatusOK, consoleLoginResponse{
		OK:        true,
		User:      &consoleUserInfo{Name: c.user, Role: consoleUserRole},
		ExpiresAt: expiresAt.Format(time.RFC3339),
	})
}

func (c *llmConsole) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !consoleRequireMethod(w, r, http.MethodPost) {
		return
	}
	if cookie, err := r.Cookie(consoleCookieName); err == nil {
		c.mu.Lock()
		delete(c.sessions, cookie.Value)
		c.mu.Unlock()
	}
	// Clearing the cookie is unconditional: logging out of a session the server
	// already forgot must still leave the browser without one.
	c.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, consoleOKResponse{OK: true})
}

func (c *llmConsole) handleSession(w http.ResponseWriter, r *http.Request) {
	if !consoleRequireMethod(w, r, http.MethodGet) {
		return
	}
	sess, ok := c.authenticateRequest(w, r)
	if !ok {
		writeJSON(w, http.StatusOK, consoleSessionResponse{Authenticated: false})
		return
	}
	writeJSON(w, http.StatusOK, consoleSessionResponse{
		Authenticated: true,
		User:          &consoleUserInfo{Name: sess.User, Role: consoleUserRole},
		ExpiresAt:     sess.ExpiresAt.Format(time.RFC3339),
	})
}

// requireSession guards one handler. The 401 body is the exact string the
// console's fetch wrapper looks for to bounce the operator back to the login
// view, so it is a contract value.
func (c *llmConsole) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := c.authenticateRequest(w, r); !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "未登录或会话已过期"})
			return
		}
		next(w, r)
	}
}

// authenticateRequest resolves the cookie and slides the session. The cookie is
// only rewritten once half the TTL has passed: the console polls every five
// seconds, and re-sending Set-Cookie on every poll would make the response
// headers the largest part of each tick.
func (c *llmConsole) authenticateRequest(w http.ResponseWriter, r *http.Request) (consoleSession, bool) {
	cookie, err := r.Cookie(consoleCookieName)
	if err != nil || cookie.Value == "" {
		return consoleSession{}, false
	}
	now := c.now()

	c.mu.Lock()
	sess := c.sessions[cookie.Value]
	if sess == nil {
		c.mu.Unlock()
		return consoleSession{}, false
	}
	if !now.Before(sess.ExpiresAt) {
		delete(c.sessions, cookie.Value)
		c.mu.Unlock()
		return consoleSession{}, false
	}
	sess.ExpiresAt = now.Add(consoleSessionTTL)
	refreshCookie := now.Sub(sess.RefreshedAt) >= consoleSessionTTL/2
	if refreshCookie {
		sess.RefreshedAt = now
	}
	snapshot := *sess
	c.mu.Unlock()

	if refreshCookie {
		c.setSessionCookie(w, cookie.Value, snapshot.ExpiresAt)
	}
	return snapshot, true
}

func (c *llmConsole) pruneSessionsLocked(now time.Time) {
	for token, sess := range c.sessions {
		if !now.Before(sess.ExpiresAt) {
			delete(c.sessions, token)
		}
	}
}

func (c *llmConsole) setSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     consoleCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(consoleSessionTTL.Seconds()),
		Expires:  expiresAt,
	})
}

func (c *llmConsole) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     consoleCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}
