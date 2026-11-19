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
	// A row states the check's outcome and nothing else: the reply viewer and
	// the payload it read are gone, so no row action reopens a health reply.
	for _, gone := range []string{
		`instanceActionButton('查看结果'`,
		"openHealthResult(",
		"instanceHealthPayloads",
	} {
		if strings.Contains(frontendBundle, gone) {
			t.Fatalf("frontendBundle still contains %q", gone)
		}
	}
}

// TestFrontendRegistrationHeaderCarriesNoTally pins that the instance list's
// header has no summary sentence: every fact belongs to one instance and is
// stated on that row, where it is refreshed by the row's own check. A tally up
// here would repeat the rows in a place that no check updates.
func TestFrontendRegistrationHeaderCarriesNoTally(t *testing.T) {
	for _, gone := range []string{
		`id="instanceSummary"`,
		"updateInstanceSummary(",
		"个连通正常",
	} {
		if strings.Contains(frontendBundle, gone) {
			t.Fatalf("frontendBundle still contains %q", gone)
		}
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
// TestFrontendLLMAttestationShowsInADrawer pins where the TEE-LLM report is
// read. The panel used to hold a collapsed 远程证明 section that kept the last
// report on screen; the report is a one-off hardware call, so the button now
// opens it in the shared drawer and the panel keeps no copy of its own.
func TestFrontendLLMAttestationShowsInADrawer(t *testing.T) {
	for _, gone := range []string{
		`id="llmAttestationDetails"`,
		`id="llmAttestationBox"`,
		"<summary>远程证明</summary>",
	} {
		if strings.Contains(indexHTML, gone) {
			t.Fatalf("index.html still contains %q", gone)
		}
	}
	js, err := staticFS.ReadFile("static/js/llm.js")
	if err != nil {
		t.Fatalf("cannot read static/js/llm.js: %v", err)
	}
	src := string(js)
	for _, want := range []string{
		"function openLLMAttestation(att)",
		"recordInteraction('llmAttestation'",
		"openInteractionDrawer('llmAttestation'",
		"attestationValues",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("static/js/llm.js missing %q", want)
		}
	}
	if strings.Contains(src, "renderLLMAttestation") {
		t.Fatal("llm.js still renders the report into the panel")
	}
}

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
