package config

import (
	"path/filepath"
	"testing"
)

// TestLoadStartupConfigPlatformPublicKeyPrecedence pins the one platform field
// whose precedence is the reverse of the others.
//
// platform.ip, platform.dockerID and platform.contract are seeded from the
// environment and then overridden by the file on a tee instance. The public key
// deliberately does the opposite: PLATFORM_PUBLIC_KEY always wins, because an
// operator setting it is rotating credentials, and a key baked into the image
// shadowing that rotation would leave the instance using a key the operator
// believes they retired.
func TestLoadStartupConfigPlatformPublicKeyPrecedence(t *testing.T) {
	const (
		envKey  = "04aabbccdd"
		fileKey = "0411223344"
	)
	cases := []struct {
		name string
		env  string
		file string
		want string
	}{
		{name: "environment only", env: envKey, file: "", want: envKey},
		{name: "file fills an empty environment", env: "", file: fileKey, want: fileKey},
		{name: "environment wins over the file", env: envKey, file: fileKey, want: envKey},
		{name: "neither source", env: "", file: "", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PLATFORM_PUBLIC_KEY", tc.env)

			body := `{"server":{"type":"tee"}}`
			if tc.file != "" {
				body = `{"platform":{"publicKey":"` + tc.file + `"}}`
			}
			path := filepath.Join(t.TempDir(), DefaultFileName)
			writeTestConfig(t, path, body)

			cfg, err := LoadStartupConfig(path)
			if err != nil {
				t.Fatalf("LoadStartupConfig() error = %v", err)
			}
			if cfg.PlatformPublicKey != tc.want {
				t.Fatalf("PlatformPublicKey = %q, want %q", cfg.PlatformPublicKey, tc.want)
			}
		})
	}
}

// TestLoadStartupConfigPlatformSM2IDIsEnvironmentOnly pins that the identity
// string cannot be set from the file. Two sources for a value that must match
// byte for byte on both ends is one source too many: a stale key in a packaged
// image would drift silently, and the only symptom is that the platform rejects
// our signatures.
func TestLoadStartupConfigPlatformSM2IDIsEnvironmentOnly(t *testing.T) {
	t.Setenv("PLATFORM_SM2_ID", "")
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{"platform":{"publicKey":"04aabbccdd"}}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}
	if cfg.PlatformSM2ID != "" {
		t.Fatalf("PlatformSM2ID = %q, want empty: the fake key in the file must not be picked up", cfg.PlatformSM2ID)
	}

	t.Setenv("PLATFORM_SM2_ID", "platform-identity")
	cfg, err = LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}
	if cfg.PlatformSM2ID != "platform-identity" {
		t.Fatalf("PlatformSM2ID = %q, want %q", cfg.PlatformSM2ID, "platform-identity")
	}
}
