package mock

import (
	"fmt"
	"log"
	"sort"
	"strings"
)

// instanceTargets is the configured map from dockerId to the address the
// platform should dial for that instance.
//
// It exists because the address derived from a registration is only usable
// when the platform shares a network with the Pod. A registration forwarded
// through a NAT (a Kata Pod dialling another host, a reverse proxy) has its
// source address rewritten, so the derived address names the proxy rather
// than the instance. This map overrides the derivation for exactly those
// instances; an instance without an entry keeps the old behaviour.
//
// The value is "dockerId=URL" pairs, comma separated, e.g.
// "kata-csv2-taa-test-0001=http://172.16.10.178:31001".
func parseInstanceTargets(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	targets := make(map[string]string)
	for _, field := range strings.Split(raw, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		dockerID, target, ok := strings.Cut(field, "=")
		dockerID = strings.TrimSpace(dockerID)
		target = strings.TrimSpace(target)
		if !ok || dockerID == "" || target == "" {
			log.Printf("warning: ignoring instance target %q: it is not dockerId=URL", field)
			continue
		}
		if !strings.Contains(target, "://") {
			log.Printf("warning: ignoring instance target %q: %q is not a URL with a scheme", field, target)
			continue
		}
		if previous, exists := targets[dockerID]; exists && previous != target {
			log.Printf("warning: instance target %q overrides the earlier %q for the same dockerId", field, previous)
		}
		targets[dockerID] = strings.TrimRight(target, "/")
	}
	return targets
}

// configuredTarget returns the configured address for dockerID, if any.
func (m *instanceManager) configuredTarget(dockerID string) string {
	if m == nil || dockerID == "" {
		return ""
	}
	return m.instanceTargets[dockerID]
}

// describeInstanceTargets renders the configured targets for the start log.
func describeInstanceTargets(targets map[string]string) string {
	if len(targets) == 0 {
		return ""
	}
	ids := make([]string, 0, len(targets))
	for dockerID := range targets {
		ids = append(ids, dockerID)
	}
	sort.Strings(ids)
	parts := make([]string, 0, len(ids))
	for _, dockerID := range ids {
		parts = append(parts, fmt.Sprintf("%s=%s", dockerID, targets[dockerID]))
	}
	return strings.Join(parts, ",")
}
