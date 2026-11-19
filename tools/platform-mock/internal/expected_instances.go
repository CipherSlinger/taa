package mock

import (
	"fmt"
	"log"
	"strings"
)

// expectedInstance is one entry of the configured inventory: the type the
// operator says this instance is, and the dockerId it will register with.
//
// The type cannot be derived from the registration (see registrationKind), so
// it has to be configured. The dockerId is what matches an entry to what
// actually registered: TAA reports it in the registration body, and the
// platform keys everything else by it.
type expectedInstance struct {
	Kind     string
	DockerID string
}

// parseExpectedInstances reads the "type:dockerId,type:dockerId" form used by
// -instances / PLATFORM_MOCK_INSTANCES.
//
// An entry whose type is not one of the console's kinds is refused rather than
// guessed: a typo that silently listed the instance under the wrong type would
// put the FHE panels in front of a TEE instance. A malformed entry is logged
// and skipped, in the same spirit as envIntOrDefault — a typo must not keep the
// mock from starting, and the console still lists whatever did register.
func parseExpectedInstances(raw string) []expectedInstance {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	entries := make([]expectedInstance, 0, strings.Count(raw, ",")+1)
	seen := make(map[string]bool)
	for _, field := range strings.Split(raw, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		kind, dockerID, ok := strings.Cut(field, ":")
		kind = strings.TrimSpace(kind)
		dockerID = strings.TrimSpace(dockerID)
		if !ok || kind == "" || dockerID == "" {
			log.Printf("warning: ignoring expected instance %q: it is not type:dockerId", field)
			continue
		}
		if !validInstanceKind(kind) {
			log.Printf("warning: ignoring expected instance %q: unknown type %q (expected %s, %s or %s)",
				field, kind, instanceKindTEE, instanceKindFHE, instanceKindDataAnalysis)
			continue
		}
		if seen[dockerID] {
			log.Printf("warning: ignoring duplicate expected instance %q; dockerId %q is already listed", field, dockerID)
			continue
		}
		seen[dockerID] = true
		entries = append(entries, expectedInstance{Kind: kind, DockerID: dockerID})
	}
	return entries
}

// expectedSummary describes an inventory entry that has not registered. It
// keeps the summary shape the console already renders so the row needs no
// special case: received and accepted are false, and LastReportAt is empty.
func expectedSummary(mgr *instanceManager, e expectedInstance) instanceSummary {
	summary := instanceSummary{DockerID: e.DockerID, Kind: e.Kind, Expected: true}
	if mgr != nil {
		summary.TaaTarget = targetForDisplay(mgr, e.DockerID)
	}
	return summary
}

// mergeExpectedInstances returns the inventory in configured order, with each
// entry that registered replaced by its registration summary and each entry
// that did not kept as an expected-but-unregistered row. Registrations the
// inventory does not name come after it, so a stray instance still shows up.
//
// A registered instance keeps its configured kind even when registrationKind
// would infer another: the inventory is the operator's statement of what the
// instance is, and the inference is only a guess (a TEE instance without
// /dev/csv-guest reports exactly like FHE).
func mergeExpectedInstances(mgr *instanceManager, expected []expectedInstance, registered []instanceSummary) []instanceSummary {
	if len(expected) == 0 {
		return registered
	}
	byID := make(map[string]instanceSummary, len(registered))
	for _, item := range registered {
		byID[item.DockerID] = item
	}
	merged := make([]instanceSummary, 0, len(expected)+len(registered))
	named := make(map[string]bool, len(expected))
	for _, e := range expected {
		named[e.DockerID] = true
		if item, ok := byID[e.DockerID]; ok {
			item.Kind = e.Kind
			item.Expected = true
			merged = append(merged, item)
			continue
		}
		merged = append(merged, expectedSummary(mgr, e))
	}
	for _, item := range registered {
		if !named[item.DockerID] {
			merged = append(merged, item)
		}
	}
	return merged
}

// expectedConfig returns the configured inventory, parsed on each call. The
// list is short and read once per console poll, so caching it would only add a
// second place for the value to be stale.
func (m *instanceManager) expectedConfig() []expectedInstance {
	if m == nil {
		return nil
	}
	return parseExpectedInstances(m.cfg.ExpectedInstances)
}

// describeExpected renders the inventory for the log, so a deployment's start
// line says what the console will list even before anything registers.
func describeExpected(expected []expectedInstance) string {
	if len(expected) == 0 {
		return ""
	}
	parts := make([]string, 0, len(expected))
	for _, e := range expected {
		parts = append(parts, fmt.Sprintf("%s:%s", e.Kind, e.DockerID))
	}
	return strings.Join(parts, ",")
}
