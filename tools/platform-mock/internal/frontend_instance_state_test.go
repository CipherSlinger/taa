package mock

import (
	"strings"
	"testing"
)

// TestFrontendConnectionBadgeHonoursTheHealthCheck pins the row's precedence:
// what the console itself observed (instanceLinks) wins over the registration
// fact, and an accepted registration never earns a connected label on its own.
// A registration is a historical record — the console's periodic checks are
// what turn it into 连通正常 — and a link the checks just lost must read 重连中
// or 断开连接, never 已连接.
//
// This is a source-level assertion because the bundle is plain browser JS; the
// console logic is checked where it lives rather than by standing up a browser.
func TestFrontendConnectionBadgeHonoursTheHealthCheck(t *testing.T) {
	fn := frontendFunction(t, "instanceConnectionState")

	// The link state must be consulted before the registration fact, or a lost
	// link would be shadowed by the accepted registration that preceded it.
	linkIdx := strings.Index(fn, "instanceLinks[item.dockerId]")
	acceptedIdx := strings.Index(fn, "item.accepted")
	if linkIdx == -1 {
		t.Fatal("instanceConnectionState no longer reads the observed link state")
	}
	if acceptedIdx == -1 {
		t.Fatal("instanceConnectionState no longer reads item.accepted")
	}
	if linkIdx > acceptedIdx {
		t.Fatal("the link state is shadowed by the accepted-registration branch")
	}
	linkBranch := fn[linkIdx:acceptedIdx]
	for _, want := range []string{"'重连中'", "'断开连接'", "'连通正常'", "'检查中'"} {
		if !strings.Contains(linkBranch, want) {
			t.Fatalf("the link branch is missing %q", want)
		}
	}
	// An accepted registration whose first check has not landed yet is 已注册:
	// accepted is a fact about the past, and the row must not claim more.
	acceptedBranch := fn[acceptedIdx:]
	if !strings.Contains(acceptedBranch, "'已注册'") {
		t.Fatal("an accepted registration without a finished check should read 已注册")
	}
	if strings.Contains(fn, "'已连接'") {
		t.Fatal("an instance must never be rendered as 已连接; the row reports what the checks observed")
	}
}

// TestFrontendConnectivityIsCheckedOnATimer pins the automatic loop the row
// states depend on: a registration observed in the five-second list poll starts
// a per-instance check, the reply is discarded if a newer registration
// superseded it, and every check is addressed by dockerId so it cannot report
// the selected row's answer under another row's name.
func TestFrontendConnectivityIsCheckedOnATimer(t *testing.T) {
	for _, want := range []string{
		"const instanceLinks = {};",
		"const INSTANCE_HEALTH_INTERVAL_MS = 30 * 1000;",
		"const INSTANCE_DISCONNECT_AFTER_MS = 5 * 60 * 1000;",
		"function syncInstanceConnectivity(list)",
		"syncInstanceConnectivity(list);",
		// A new registration is what starts (or restarts) the checks.
		"link.registrationAt !== at",
		"function runInstanceConnectivityCheck(id)",
		"current.generation !== generation",
		"function scheduleInstanceConnectivity(id)",
		// 断开连接 stops the timer; only a registration starts it again.
		"link.state === 'disconnected'",
		"function probeInstanceHealth(id)",
		"/taa/v1/taa/health?dockerId=",
		"encodeURIComponent(id)",
		// The five-minute rule is a state transition, not a separate timer.
		"downFor >= INSTANCE_DISCONNECT_AFTER_MS",
		"link.state = 'disconnected'",
	} {
		if !strings.Contains(frontendBundle, want) {
			t.Fatalf("frontendBundle missing %q", want)
		}
	}
	// Connectivity is no longer an operator action: the row has no check button.
	if strings.Contains(frontendBundle, `instanceActionButton('检查连通性'`) {
		t.Fatal("the 检查连通性 row action survived; checks are automatic")
	}
	// 查看结果 reads the row's own reply rather than a single global result.
	viewer := frontendFunction(t, "openHealthResult")
	if !strings.Contains(viewer, "instanceHealthPayloads[id]") {
		t.Fatal("openHealthResult does not read the per-instance reply it was opened for")
	}
}

// TestFrontendConnectionSummaryCountsOnlyVerifiedLinks pins the list summary to
// the same rule as the rows: the tally must not say 已连接 for rows the console
// has never verified, or the header would repeat the false claim the badge was
// fixed to stop making.
func TestFrontendConnectionSummaryCountsOnlyVerifiedLinks(t *testing.T) {
	fn := frontendFunction(t, "updateInstanceSummary")
	if !strings.Contains(fn, "instanceConnectionState(item).tone === 'ok'") {
		t.Fatal("the summary must count rows by the connection state, not by item.accepted")
	}
	if strings.Contains(fn, "item.accepted") {
		t.Fatal("the summary counts accepted registrations as connected")
	}
	if !strings.Contains(fn, "个连通正常") {
		t.Fatal("the summary should use the same 连通正常 wording as the verified badge")
	}
}

// TestFrontendHealthBadgeExpires pins that a green badge does not outlive the
// check that produced it: 连通正常 claims a link the console observed recently,
// and a check from ten minutes ago is not that claim.
func TestFrontendHealthBadgeExpires(t *testing.T) {
	for _, want := range []string{
		"const instanceHealthStaleMs =",
		"Date.now() - (slot.checkedAt || 0)",
		"function tickInstanceHealthExpiry()",
		"setInterval(tickInstanceHealthExpiry",
	} {
		if !strings.Contains(frontendBundle, want) {
			t.Fatalf("frontendBundle missing %q", want)
		}
	}
	// The expiry has to fall back to the registration wording, not to a green
	// check result: the whole point is to stop asserting a live connection.
	fn := frontendFunction(t, "instanceConnectionState")
	if !strings.Contains(fn, "'已注册'") {
		t.Fatal("an expired check should fall back to 已注册 (registration only)")
	}
	// The tick only repaints when the stamp changed, so the stamp must depend on
	// freshness. A key built from checkedAt alone is constant as time passes and
	// the badge would stay green past its deadline — which is the whole bug.
	key := frontendFunction(t, "healthStampKey")
	if !strings.Contains(key, "instanceHealthStaleMs") {
		t.Fatal("healthStampKey ignores freshness, so the expiry tick can never fire")
	}
}

// TestFrontendHealthChipExpires pins the other half of the same rule: the 环境
// chip is the row's stored check result, and it must stop saying 连通正常 once
// the check is old. Otherwise the combined badge would fall back to 已注册 while
// a green chip beside it still vouched for a link nobody re-verified.
func TestFrontendHealthChipExpires(t *testing.T) {
	fn := frontendFunction(t, "instanceHealthFor")
	if !strings.Contains(fn, "instanceHealthStaleMs") {
		t.Fatal("instanceHealthFor never expires a green check result")
	}
	if !strings.Contains(fn, "'已过期'") {
		t.Fatal("an expired check should say 已过期 instead of keeping 连通正常")
	}
}

// frontendFunction extracts one top-level function from the served bundle. The
// bundle is plain browser JS, so the console logic is checked where it lives.
func frontendFunction(t *testing.T, name string) string {
	t.Helper()
	start := strings.Index(frontendBundle, "function "+name+"(")
	if start == -1 {
		t.Fatalf("frontendBundle missing %s", name)
	}
	end := strings.Index(frontendBundle[start:], "\n}")
	if end == -1 {
		t.Fatalf("cannot delimit %s", name)
	}
	return frontendBundle[start : start+end]
}

// TestFrontendExplainsWhereTheInstanceNameComesFrom pins the answer to "why is
// the name not the Pod name": the row says the name is the reported dockerId,
// and shows the address the registration actually came from.
func TestFrontendExplainsWhereTheInstanceNameComesFrom(t *testing.T) {
	for _, want := range []string{
		"function instanceNameHint(item)",
		"不是 Pod 名称",
		"注册来源",
		"sourceAddr",
		"function instanceRowTitle(item, state)",
	} {
		if !strings.Contains(frontendBundle, want) {
			t.Fatalf("frontendBundle missing %q", want)
		}
	}
	// 默认 must be explained where it is rendered, and the explanation must say
	// what it actually decides rather than implying a preference.
	if !strings.Contains(frontendBundle, "默认实例：控制台在未选中任何行时") {
		t.Fatal("the 默认 tag has no explanation of what it decides")
	}
}
