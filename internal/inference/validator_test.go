package inference_test

import (
	"testing"

	"taa/internal/inference"
)

func TestValidateEndpoint_Allowed(t *testing.T) {
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
}

func TestValidateEndpoint_Blocked(t *testing.T) {
	allowedList := []string{"127.0.0.1", "localhost"}
	v := inference.NewEndpointValidator(allowedList, false)

	blockedEndpoints := []string{
		"http://169.254.169.254/latest/meta-data", // Cloud metadata
		"http://evil.com:11434",                    // Unlisted domain
		"http://0.0.0.0:11434",                     // Any address IPv4
		"http://[::]:11434",                        // Any address IPv6
		"ftp://127.0.0.1:21",                       // Invalid scheme
		"gopher://127.0.0.1:70",                    // Dangerous scheme
		"file:///etc/passwd",                       // File scheme
		"unix://",                                  // Empty unix path
		"",                                         // Empty endpoint
	}

	for _, ep := range blockedEndpoints {
		if err := v.Validate(ep); err == nil {
			t.Errorf("expected endpoint %q to be rejected, but passed", ep)
		}
	}
}

func TestValidateEndpoint_BlockPrivateIPs(t *testing.T) {
	v := inference.NewEndpointValidator([]string{"127.0.0.1", "10.0.0.1"}, true)

	if err := v.Validate("http://127.0.0.1:11434"); err == nil {
		t.Errorf("expected loopback to be blocked when blockPrivateIPs=true")
	}
	if err := v.Validate("http://10.0.0.1:11434"); err == nil {
		t.Errorf("expected private IP to be blocked when blockPrivateIPs=true")
	}
}
