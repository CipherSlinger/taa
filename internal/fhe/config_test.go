package fhe

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"taa/internal/config"
)

func validConfig() Config {
	return Config{
		Endpoint:              "http://127.0.0.1:58996",
		DataDir:               "/opt/fhe-data",
		KeyCacheDir:           "/root/taa/fhe-keys",
		CallbackBaseURL:       "http://172.16.10.130:6001",
		CallbackToken:         "s3cret",
		MaxEvalKeyBytes:       DefaultMaxEvalKeyBytes,
		PollInterval:          DefaultPollInterval,
		RequestTimeout:        DefaultRequestTimeout,
		TaskTimeout:           DefaultTaskTimeout,
		ActivateModelOnImport: true,
	}
}

func TestConfigValidateAcceptsCompleteConfig(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestConfigValidateRejectsMissingRequiredFields(t *testing.T) {
	mutators := map[string]func(*Config){
		"endpoint":        func(c *Config) { c.Endpoint = "" },
		"dataDir":         func(c *Config) { c.DataDir = "  " },
		"keyCacheDir":     func(c *Config) { c.KeyCacheDir = "" },
		"callbackBaseUrl": func(c *Config) { c.CallbackBaseURL = "" },
		"callbackToken":   func(c *Config) { c.CallbackToken = "" },
	}
	for name, mutate := range mutators {
		c := validConfig()
		mutate(&c)
		err := c.Validate()
		if err == nil {
			t.Errorf("missing %s: Validate() = nil, want error", name)
			continue
		}
		if !strings.Contains(err.Error(), name) {
			t.Errorf("missing %s: error %q does not name the field", name, err)
		}
	}
}

func TestConfigValidateRejectsBadBounds(t *testing.T) {
	negative := validConfig()
	negative.MaxEvalKeyBytes = 0
	if err := negative.Validate(); err == nil {
		t.Error("maxEvalKeyBytes=0 accepted, want error")
	}

	badPoll := validConfig()
	badPoll.PollInterval = 0
	if err := badPoll.Validate(); err == nil {
		t.Error("pollInterval=0 accepted, want error")
	}

	badTimeout := validConfig()
	badTimeout.TaskTimeout = 0
	if err := badTimeout.Validate(); err == nil {
		t.Error("taskTimeout=0 accepted, want error")
	}
}

// TestConfigValidateRejectsBadEndpointShape pins the exact message of every
// shape check on endpoint. The messages must be exact, not "some error": the
// value "127.0.0.1:58996" already fails inside url.Parse, so a bare "err != nil"
// is satisfied by the parse branch and never reaches the scheme or host check -
// deleting either of those would leave such a test green.
func TestConfigValidateRejectsBadEndpointShape(t *testing.T) {
	tests := []struct {
		endpoint string
		want     string
	}{
		{
			endpoint: "127.0.0.1:58996",
			want:     `fhe.endpoint "127.0.0.1:58996" is not a valid URL: parse "127.0.0.1:58996": first path segment in URL cannot contain colon`,
		},
		{
			endpoint: "ftp://host",
			want:     `fhe.endpoint "ftp://host" must use the http or https scheme`,
		},
		{
			endpoint: "http://",
			want:     `fhe.endpoint "http://" has no host`,
		},
		{
			// Host is non-empty (":1") but there is no host name at all; the
			// startup-config layer rejects this shape too, and the two gates must
			// not disagree on what an absolute URL is.
			endpoint: "http://:1",
			want:     `fhe.endpoint "http://:1" has no host name`,
		},
	}
	for _, tc := range tests {
		c := validConfig()
		c.Endpoint = tc.endpoint
		err := c.Validate()
		if err == nil {
			t.Errorf("endpoint %q accepted, want error", tc.endpoint)
			continue
		}
		if err.Error() != tc.want {
			t.Errorf("endpoint %q:\n got %q\nwant %q", tc.endpoint, err, tc.want)
		}
	}
}

// TestConfigValidateRejectsBadCallbackBaseURL pins the same shape checks for the
// callback base URL, which callers append a path and "?token=" to. A base URL
// that is not absolute, or that already carries a query or a fragment, then
// produces a URL the FHE service cannot POST to - and the failure is silent,
// because the callback is the primary terminal-state channel and only the poll
// fallback notices.
func TestConfigValidateRejectsBadCallbackBaseURL(t *testing.T) {
	tests := []struct {
		base string
		want string
	}{
		{
			base: "127.0.0.1:6001",
			want: `fhe.callbackBaseUrl "127.0.0.1:6001" is not a valid URL: parse "127.0.0.1:6001": first path segment in URL cannot contain colon`,
		},
		{
			base: "/",
			want: `fhe.callbackBaseUrl "/" must use the http or https scheme`,
		},
		{
			base: "ftp://host",
			want: `fhe.callbackBaseUrl "ftp://host" must use the http or https scheme`,
		},
		{
			base: "http://",
			want: `fhe.callbackBaseUrl "http://" has no host`,
		},
		{
			base: "http://:1",
			want: `fhe.callbackBaseUrl "http://:1" has no host name`,
		},
		{
			// A fragment swallows the appended path *and* the token, so the
			// service posts to "/" with no token and our endpoint 404s.
			base: "http://172.16.10.130:6001/#frag",
			want: `fhe.callbackBaseUrl "http://172.16.10.130:6001/#frag" must not contain a query or a fragment`,
		},
		{
			// A whole callback URL pasted in by mistake yields
			// "token=old/v1/taa/fheCallback?token=s3cret".
			base: "http://172.16.10.130:6001/v1/taa/fheCallback?token=old",
			want: `fhe.callbackBaseUrl "http://172.16.10.130:6001/v1/taa/fheCallback?token=old" must not contain a query or a fragment`,
		},
	}
	for _, tc := range tests {
		c := validConfig()
		c.CallbackBaseURL = tc.base
		err := c.Validate()
		if err == nil {
			t.Errorf("callbackBaseUrl %q accepted, want error", tc.base)
			continue
		}
		if err.Error() != tc.want {
			t.Errorf("callbackBaseUrl %q:\n got %q\nwant %q", tc.base, err, tc.want)
		}
	}
}

// TestConfigValidateDurationErrorsPrintMilliseconds checks the unit in the
// duration messages. The keys are named ...Ms, so a value printed as a
// time.Duration ("got -1ns") reports a unit the operator cannot find in the
// startup config. The values below are whole milliseconds because that is what
// the JSON layer ever produces - fhe.pollIntervalMs is an integer count of
// milliseconds, so pollIntervalMs=-1 arrives here as -1ms.
func TestConfigValidateDurationErrorsPrintMilliseconds(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"pollIntervalMs", func(c *Config) { c.PollInterval = -1 * time.Millisecond }, "fhe.pollIntervalMs must be positive, got -1"},
		{"requestTimeoutMs", func(c *Config) { c.RequestTimeout = 0 }, "fhe.requestTimeoutMs must be positive, got 0"},
		{"taskTimeoutMs", func(c *Config) { c.TaskTimeout = -1500 * time.Millisecond }, "fhe.taskTimeoutMs must be positive, got -1500"},
	}
	for _, tc := range tests {
		c := validConfig()
		tc.mutate(&c)
		err := c.Validate()
		if err == nil {
			t.Errorf("%s: Validate() = nil, want error", tc.name)
			continue
		}
		if err.Error() != tc.want {
			t.Errorf("%s: err = %q, want %q", tc.name, err, tc.want)
		}
	}
}

func TestConfigTokenMatches(t *testing.T) {
	c := validConfig()
	if !c.TokenMatches("s3cret") {
		t.Error("TokenMatches(exact) = false, want true")
	}
	for _, bad := range []string{"", "s3cre", "s3cret ", "S3CRET", "s3cretx"} {
		if c.TokenMatches(bad) {
			t.Errorf("TokenMatches(%q) = true, want false", bad)
		}
	}
	empty := validConfig()
	empty.CallbackToken = ""
	if empty.TokenMatches("") {
		t.Error("an unset token must not match an empty presented token")
	}
}

func TestConfigCallbackURL(t *testing.T) {
	c := validConfig()
	got := c.CallbackURL()
	want := "http://172.16.10.130:6001/v1/taa/fheCallback?token=s3cret"
	if got != want {
		t.Errorf("CallbackURL() = %q, want %q", got, want)
	}

	c.CallbackBaseURL = "http://172.16.10.130:6001/"
	if got := c.CallbackURL(); got != want {
		t.Errorf("CallbackURL() with a trailing slash = %q, want %q", got, want)
	}
}

// TestConfigCallbackURLEscapesTheToken round-trips a token that carries every
// character the query syntax reserves. The escaping is correct today; this test
// exists because dropping url.QueryEscape would otherwise leave the suite green
// while breaking every token containing '&', '#', '=', '+' or a space.
func TestConfigCallbackURLEscapesTheToken(t *testing.T) {
	for _, token := range []string{"s3cret", "tok&x=1#frag", "a b+c=d", "tok?/frag", "令牌+值"} {
		c := validConfig()
		c.CallbackToken = token
		raw := c.CallbackURL()
		u, err := url.Parse(raw)
		if err != nil {
			t.Errorf("token %q: CallbackURL() = %q does not parse: %v", token, raw, err)
			continue
		}
		if u.Path != "/v1/taa/fheCallback" {
			t.Errorf("token %q: path = %q, want /v1/taa/fheCallback", token, u.Path)
		}
		if u.Fragment != "" {
			t.Errorf("token %q: CallbackURL() = %q carries a fragment %q, which would swallow the token", token, raw, u.Fragment)
		}
		if got := u.Query().Get("token"); got != c.CallbackToken {
			t.Errorf("token %q: the service would present %q, want %q", token, got, c.CallbackToken)
		}
	}
}

func TestConfigDefaults(t *testing.T) {
	// The default must stay above the measured eval_context.bin (3,329,929,205 B)
	// and must not be confused with codeAudit.resultCheck.maxFileBytes (3 GiB),
	// which is 103.7 MiB too small to download a real key.
	if DefaultMaxEvalKeyBytes <= 3329929205 {
		t.Errorf("DefaultMaxEvalKeyBytes = %d, must exceed the measured key size 3329929205", DefaultMaxEvalKeyBytes)
	}
	if DefaultPollInterval != 5*time.Second {
		t.Errorf("DefaultPollInterval = %s, want 5s", DefaultPollInterval)
	}
	if DefaultRequestTimeout != 30*time.Second {
		t.Errorf("DefaultRequestTimeout = %s, want 30s", DefaultRequestTimeout)
	}
	if DefaultTaskTimeout != 30*time.Minute {
		t.Errorf("DefaultTaskTimeout = %s, want 30m", DefaultTaskTimeout)
	}
	// One HTTP call is bounded by the request timeout and the whole wait by the
	// task timeout; a request timeout that reached the task timeout would leave
	// no room for a second poll.
	if DefaultRequestTimeout >= DefaultTaskTimeout {
		t.Errorf("DefaultRequestTimeout %s must stay below DefaultTaskTimeout %s",
			DefaultRequestTimeout, DefaultTaskTimeout)
	}
	if DefaultPollInterval >= DefaultTaskTimeout {
		t.Errorf("DefaultPollInterval %s must stay below DefaultTaskTimeout %s",
			DefaultPollInterval, DefaultTaskTimeout)
	}
}

// TestDefaultsMatchTheStartupConfigDefaults binds this package's four constants to
// the config package's, which are the ones production actually uses.
//
// The same four numbers are spelled twice: internal/config defines DefaultFHE*, and
// applyFHEDefaults fills a template that omitted one with them, while the constants
// below are what this package's own tests build a Config from. Nothing made the two
// agree, so raising a default on the production side alone would have left every
// test here green against a number no deployment uses - and this package's tests
// are the evidence that the timeout, poll and key-cap agree with each other.
func TestDefaultsMatchTheStartupConfigDefaults(t *testing.T) {
	if DefaultMaxEvalKeyBytes != config.DefaultFHEMaxEvalKeyBytes {
		t.Errorf("DefaultMaxEvalKeyBytes = %d, but the startup config defaults to %d",
			DefaultMaxEvalKeyBytes, config.DefaultFHEMaxEvalKeyBytes)
	}
	if got, want := DefaultPollInterval, time.Duration(config.DefaultFHEPollIntervalMs)*time.Millisecond; got != want {
		t.Errorf("DefaultPollInterval = %s, but the startup config defaults to %s", got, want)
	}
	if got, want := DefaultRequestTimeout, time.Duration(config.DefaultFHERequestTimeoutMs)*time.Millisecond; got != want {
		t.Errorf("DefaultRequestTimeout = %s, but the startup config defaults to %s", got, want)
	}
	if got, want := DefaultTaskTimeout, time.Duration(config.DefaultFHETaskTimeoutMs)*time.Millisecond; got != want {
		t.Errorf("DefaultTaskTimeout = %s, but the startup config defaults to %s", got, want)
	}
}
