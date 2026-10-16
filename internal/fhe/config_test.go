package fhe

import (
	"strings"
	"testing"
	"time"
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

	badEndpoint := validConfig()
	badEndpoint.Endpoint = "127.0.0.1:58996"
	if err := badEndpoint.Validate(); err == nil {
		t.Error("endpoint without a scheme accepted, want error")
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

func TestConfigDefaults(t *testing.T) {
	if DefaultMaxEvalKeyBytes != int64(6)<<30 {
		t.Errorf("DefaultMaxEvalKeyBytes = %d, want %d", DefaultMaxEvalKeyBytes, int64(6)<<30)
	}
	// The default must stay above the measured eval_context.bin (3,329,929,205 B)
	// and must not be confused with codeAudit.resultCheck.maxFileBytes (3 GiB),
	// which is 103.7 MiB too small to download a real key.
	if DefaultMaxEvalKeyBytes <= 3329929205 {
		t.Errorf("DefaultMaxEvalKeyBytes = %d, must exceed the measured key size 3329929205", DefaultMaxEvalKeyBytes)
	}
	if DefaultPollInterval != 5*time.Second || DefaultTaskTimeout != 30*time.Minute {
		t.Errorf("unexpected defaults: poll=%s task=%s", DefaultPollInterval, DefaultTaskTimeout)
	}
}
