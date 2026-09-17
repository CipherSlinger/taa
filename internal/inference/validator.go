package inference

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
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
		if trimmed == "" {
			continue
		}
		host, _, err := net.SplitHostPort(trimmed)
		if err != nil {
			host = strings.Trim(trimmed, "[]")
		} else {
			host = strings.Trim(host, "[]")
		}
		if host != "" {
			hostMap[host] = struct{}{}
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
	if strings.HasPrefix(strings.ToLower(endpoint), "unix://") {
		path := strings.TrimSpace(endpoint[len("unix://"):])
		if path == "" || path == "/" {
			return errors.New("unix socket path cannot be empty or root")
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

	hostname := strings.ToLower(strings.Trim(parsed.Hostname(), "[]"))
	if hostname == "" {
		return errors.New("endpoint host cannot be empty")
	}

	if portStr := parsed.Port(); portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			return fmt.Errorf("invalid port %q: must be between 1 and 65535", portStr)
		}
	}

	// Block cloud metadata services and any-addresses unconditionally.
	if hostname == "169.254.169.254" || hostname == "0.0.0.0" || hostname == "::" || hostname == "[::]" {
		return fmt.Errorf("access to restricted address %q is forbidden", hostname)
	}

	ip := net.ParseIP(hostname)
	if ip != nil {
		if ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("access to restricted address %q is forbidden", hostname)
		}
	}

	// Enforce allowed hosts whitelist if configured.
	if len(v.allowedHosts) > 0 {
		if _, ok := v.allowedHosts[hostname]; !ok {
			return fmt.Errorf("host %q is not in the allowed endpoint whitelist", hostname)
		}
	}

	// Optionally block private/internal IPs if strict external checking is required.
	if v.blockPrivateIPs {
		if ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
			return fmt.Errorf("private and loopback IP %q is blocked by security policy", hostname)
		}
	}

	return nil
}
