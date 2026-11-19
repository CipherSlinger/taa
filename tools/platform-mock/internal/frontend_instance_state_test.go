package mock

import (
	"strings"
	"testing"
)

// TestFrontendConnectionBadgeHonoursTheHealthCheck pins the behaviour the
// console was reported to get wrong: an instance whose registration was
// accepted hours ago still showed 已连接 even though nothing was answering.
// An accepted registration is a historical fact, not evidence of a live link:
// nothing in this mock polls an instance, so the default row must say 已注册 and
// only a fresh passing check may claim connectivity.
//
// A failed check reads 未连接, the same as an inventory entry that never
// registered: the operator appointed the instance, so from the console's side
// both mean "nothing is answering at that identity", and the tooltip carries
// the difference (never registered vs. registered but unreachable).
//
// This is a source-level assertion because the bundle is plain browser JS; the
// console logic is checked where it lives rather than by standing up a browser.
func TestFrontendConnectionBadgeHonoursTheHealthCheck(t *testing.T) {
	fn := frontendFunction(t, "instanceConnectionState")

	// The failure branch must come first and must be reachable before the
	// accepted-registration branch, or a failed check would be shadowed.
	badIdx := strings.Index(fn, "health.tone === 'bad'")
	acceptedIdx := strings.Index(fn, "item.accepted")
	if badIdx == -1 {
		t.Fatal("instanceConnectionState has no failed-check branch")
	}
	if acceptedIdx == -1 {
		t.Fatal("instanceConnectionState no longer reads item.accepted")
	}
	if badIdx > acceptedIdx {
		t.Fatal("the failed-check branch is shadowed by the accepted-registration branch")
	}
	if !strings.Contains(fn[badIdx:acceptedIdx], "'未连接'") {
		t.Fatal("a failed check should read 未连接, the same as an instance that never registered")
	}
	// A passing check is worded apart from the registration badge, so the two
	// facts cannot be read as one.
	if !strings.Contains(fn, "'连通正常'") {
		t.Fatal("a passing check should read 连通正常, not reuse 已连接")
	}
	// The accepted-registration fallback (and everything after it) must not
	// claim a connection. 已注册 says exactly what is known: the instance
	// reported once, and whether it can still be reached is unverified.
	acceptedBranch := fn[acceptedIdx:]
	if !strings.Contains(acceptedBranch, "'已注册'") {
		t.Fatal("an accepted registration without a fresh check should read 已注册")
	}
	if strings.Contains(acceptedBranch, "'已连接'") {
		t.Fatal("an accepted registration must not be rendered as 已连接; nothing polls the instance")
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

// TestFrontendHealthCheckIsSequenced pins the guard against a stale reply: a
// slow earlier check must not overwrite the result of a newer one, and its
// result must land on the row that asked for it.
func TestFrontendHealthCheckIsSequenced(t *testing.T) {
	for _, want := range []string{
		"const instanceConnectionChecks = {};",
		"function runInstanceHealth(id)",
		"instanceConnectionChecks[checkId] === checkSeq",
		"await testHealth({ instanceId: id, seq: seq });",
	} {
		if !strings.Contains(frontendBundle, want) {
			t.Fatalf("frontendBundle missing %q", want)
		}
	}
	// A stale reply returns before touching the shared result, so 查看结果 keeps
	// showing the newest check rather than an older one that arrived late.
	stale := strings.Index(frontendBundle, "if (!isCurrent()) return;")
	if stale == -1 {
		t.Fatal("testHealth does not discard a stale reply")
	}
}

// TestFrontendHealthBadgeExpires pins that a green badge does not outlive the
// check that produced it: nothing observes an instance between checks, so a
// ten-minute-old 连通正常 would be vouching for a link nobody re-verified.
func TestFrontendHealthBadgeExpires(t *testing.T) {
	for _, want := range []string{
		"const instanceHealthStaleMs =",
		"Date.now() - (health.checkedAt || 0)",
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
