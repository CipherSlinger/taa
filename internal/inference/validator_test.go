package inference_test

import (
	"testing"

	"taa/internal/inference"
)

func TestValidateEndpoint_Allowed(t *testing.T) {
	t.Run("StandardAllowed", func(t *testing.T) {
		allowedList := []string{"127.0.0.1", "localhost", "inference-service"}
		v := inference.NewEndpointValidator(allowedList, false)

		validEndpoints := []string{
			"http://127.0.0.1:11434",
			"http://localhost:11434",
			"http://inference-service:8080/v1/generate",
			"https://inference-service:8443/v1/generate",
			"unix:///run/taa/ipc/inference.sock",
		}

		for _, ep := range validEndpoints {
			if err := v.Validate(ep); err != nil {
				t.Errorf("expected endpoint %q to be valid, got: %v", ep, err)
			}
		}
	})

	t.Run("UnixSocketVariations", func(t *testing.T) {
		v := inference.NewEndpointValidator(nil, false)
		validUnixEndpoints := []string{
			"unix:///run/taa/ipc/inference.sock",
			"UNIX:///run/taa/ipc/test.sock",
		}
		for _, ep := range validUnixEndpoints {
			if err := v.Validate(ep); err != nil {
				t.Errorf("expected unix endpoint %q to be valid, got: %v", ep, err)
			}
		}
	})

	t.Run("AllowedHostsNormalization", func(t *testing.T) {
		// Host entries with ports or brackets should be normalized to host-only entries.
		allowedList := []string{"inference-service:8080", "[::1]:11434"}
		v := inference.NewEndpointValidator(allowedList, false)

		validEndpoints := []string{
			"http://inference-service:8080/v1",
			"http://inference-service:9090/v1",
			"http://[::1]:11434/v1",
		}
		for _, ep := range validEndpoints {
			if err := v.Validate(ep); err != nil {
				t.Errorf("expected endpoint %q to be valid after host normalization, got: %v", ep, err)
			}
		}
	})
}

func TestValidateEndpoint_Blocked(t *testing.T) {
	t.Run("RestrictedMetadataAndAnyAddresses", func(t *testing.T) {
		// Even if restricted addresses are configured in allowed hosts, they must be rejected.
		allowedList := []string{"169.254.169.254", "::ffff:169.254.169.254", "0.0.0.0", "::", "0:0:0:0:0:0:0:0"}
		v := inference.NewEndpointValidator(allowedList, false)

		blocked := []string{
			"http://169.254.169.254/latest/meta-data", // Cloud metadata IPv4
			"http://[::ffff:169.254.169.254]",         // Cloud metadata IPv4-mapped IPv6
			"http://0.0.0.0:11434",                     // Any address IPv4
			"http://[::]:11434",                        // Any address IPv6
			"http://[0:0:0:0:0:0:0:0]:11434",          // Expanded IPv6 unspecified
		}

		for _, ep := range blocked {
			if err := v.Validate(ep); err == nil {
				t.Errorf("expected endpoint %q to be blocked, but passed", ep)
			}
		}
	})

	t.Run("InvalidSchemesAndEndpoints", func(t *testing.T) {
		v := inference.NewEndpointValidator([]string{"127.0.0.1", "localhost"}, false)

		blocked := []string{
			"ftp://127.0.0.1:21",     // Invalid scheme
			"gopher://127.0.0.1:70",  // Dangerous scheme
			"file:///etc/passwd",     // File scheme
			"http://evil.com:11434",  // Unlisted domain
			"",                       // Empty endpoint
		}

		for _, ep := range blocked {
			if err := v.Validate(ep); err == nil {
				t.Errorf("expected endpoint %q to be blocked, but passed", ep)
			}
		}
	})

	t.Run("UnixSocketVariations", func(t *testing.T) {
		v := inference.NewEndpointValidator(nil, false)

		blockedUnix := []string{
			"unix://",    // Empty unix path
			"unix://   ", // Whitespace only unix path
			"unix:///",   // Root unix path
		}

		for _, ep := range blockedUnix {
			if err := v.Validate(ep); err == nil {
				t.Errorf("expected unix endpoint %q to be rejected, but passed", ep)
			}
		}
	})

	t.Run("InvalidPorts", func(t *testing.T) {
		v := inference.NewEndpointValidator([]string{"localhost"}, false)

		invalidPortEndpoints := []string{
			"http://localhost:0",
			"http://localhost:70000",
			"http://localhost:abc",
		}

		for _, ep := range invalidPortEndpoints {
			if err := v.Validate(ep); err == nil {
				t.Errorf("expected invalid port endpoint %q to be rejected, but passed", ep)
			}
		}
	})
}

func TestValidateEndpoint_BlockPrivateIPs(t *testing.T) {
	t.Run("IPv4LoopbackAndPrivate", func(t *testing.T) {
		v := inference.NewEndpointValidator([]string{"127.0.0.1", "10.0.0.1"}, true)

		if err := v.Validate("http://127.0.0.1:11434"); err == nil {
			t.Errorf("expected loopback 127.0.0.1 to be blocked when blockPrivateIPs=true")
		}
		if err := v.Validate("http://10.0.0.1:11434"); err == nil {
			t.Errorf("expected private IP 10.0.0.1 to be blocked when blockPrivateIPs=true")
		}
	})

	t.Run("IPv6LoopbackAndMapped", func(t *testing.T) {
		v := inference.NewEndpointValidator([]string{"::1", "::ffff:127.0.0.1"}, true)

		blocked := []string{
			"http://[::1]:11434",
			"http://[::ffff:127.0.0.1]:11434",
		}

		for _, ep := range blocked {
			if err := v.Validate(ep); err == nil {
				t.Errorf("expected loopback %q to be blocked when blockPrivateIPs=true", ep)
			}
		}
	})
}
