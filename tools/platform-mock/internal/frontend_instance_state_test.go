package mock

import (
	"strings"
	"testing"
)

// TestFrontendConnectionBadgeHonoursTheHealthCheck pins the behaviour the
// console was reported to get wrong: after 检查连通性 found the instance
// unreachable, the row still showed 已连接. 已连接 describes the accepted
// registration, which nothing polls, so a failed check must override it.
//
// This is a source-level assertion because the bundle is plain browser JS; the
// console logic is checked where it lives rather than by standing up a browser.
func TestFrontendConnectionBadgeHonoursTheHealthCheck(t *testing.T) {
	start := strings.Index(frontendBundle, "function instanceConnectionState(")
	if start == -1 {
		t.Fatal("frontendBundle missing instanceConnectionState")
	}
	end := strings.Index(frontendBundle[start:], "\n}")
	if end == -1 {
		t.Fatal("cannot delimit instanceConnectionState")
	}
	fn := frontendBundle[start : start+end]

	// The failure branch must come first and must be reachable before the
	// accepted-registration branch, or a failed check would be shadowed.
	badIdx := strings.Index(fn, "'已断开'")
	acceptedIdx := strings.Index(fn, "item.accepted")
	if badIdx == -1 {
		t.Fatal("instanceConnectionState has no 已断开 state for a failed check")
	}
	if acceptedIdx == -1 {
		t.Fatal("instanceConnectionState no longer reads item.accepted")
	}
	if badIdx > acceptedIdx {
		t.Fatal("the failed-check branch is shadowed by the accepted-registration branch")
	}
	// A passing check is worded apart from the registration badge, so the two
	// facts cannot be read as one.
	if !strings.Contains(fn, "'连通正常'") {
		t.Fatal("a passing check should read 连通正常, not reuse 已连接")
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
	start := strings.Index(frontendBundle, "function instanceConnectionState(")
	end := strings.Index(frontendBundle[start:], "\n}")
	fn := frontendBundle[start : start+end]
	if !strings.Contains(fn, "'已连接'") {
		t.Fatal("an expired check should fall back to 已连接 (registration only)")
	}
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
