package inference

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// EndpointValidator enforces SSRF defenses and host whitelisting.
type EndpointValidator struct {
	allowedHosts    map[string]struct{}
	blockPrivateIPs bool
}

// NewEndpointValidator constructs a validator with configured allowed hosts.
func NewEndpointValidator(allowedHosts []string, blockPrivateIPs bool) *EndpointValidator {
	hostMap := make(map[string]struct{}, len(allowedHosts))
	for _, h := range allowedHosts {
		trimmed := strings.ToLower(strings.TrimSpace(h))
		if trimmed != "" {
			hostMap[trimmed] = struct{}{}
		}
	}
	return &EndpointValidator{
		allowedHosts:    hostMap,
		blockPrivateIPs: blockPrivateIPs,
	}
}

// Validate checks whether an endpoint URL is secure and permitted.
func (v *EndpointValidator) Validate(endpoint string) error {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return errors.New("endpoint cannot be empty")
	}

	// Support unix domain sockets directly.
	if strings.HasPrefix(endpoint, "unix://") {
		path := strings.TrimPrefix(endpoint, "unix://")
		if path == "" {
			return errors.New("unix socket path cannot be empty")
		}
		return nil
	}

	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint URL: %w", err)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("unsupported protocol scheme %q: only http, https, and unix are allowed", scheme)
	}

	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return errors.New("endpoint host cannot be empty")
	}

	// Block cloud metadata services and any-addresses unconditionally.
	if hostname == "169.254.169.254" || hostname == "0.0.0.0" || hostname == "::" || hostname == "[::]" {
		return fmt.Errorf("access to restricted address %q is forbidden", hostname)
	}

	// Enforce allowed hosts whitelist if configured.
	if len(v.allowedHosts) > 0 {
		if _, ok := v.allowedHosts[hostname]; !ok {
			return fmt.Errorf("host %q is not in the allowed endpoint whitelist", hostname)
		}
	}

	// Optionally block private/internal IPs if strict external checking is required.
	if v.blockPrivateIPs {
		ip := net.ParseIP(hostname)
		if ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
			return fmt.Errorf("private and loopback IP %q is blocked by security policy", hostname)
		}
	}

	return nil
}
