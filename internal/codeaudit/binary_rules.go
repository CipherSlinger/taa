package codeaudit

import (
	"fmt"
	"regexp"
	"sort"
)

// binaryOnlyRules are the families only a binary can evidence. They carry their
// own severity because there is no source-side rule with the same id to borrow
// it from; every rule id that does exist in DefaultRules() is looked up there
// instead, so the two channels cannot disagree about a shared family's severity.
//
// The severity column is policy, and the policy this table encodes is one
// sentence: a finding may be HIGH only when it is corroborated by structure the
// file cannot produce by accident. A dynamic symbol table entry, a DT_NEEDED
// name, a committed pickle parse and a measured executable-section entropy are
// all produced by the file's own construction. A free string is not: a .so
// contains whatever text its authors embedded, and a .pyc's constants
// concatenate into runs that contain anything, so a string match is evidence for
// a reader and for the Tier-2 model rather than a verdict on its own.
//
// The reason this has to be stated rather than felt is that the severity column
// is the only control that exists downstream. `Passed` is computed as
// `highCount == 0` under the default `assist` policy, and with the medium count
// added under `gate`, both in ComputeConclusionContext. A `Passed` that comes
// out false refuses the import (internal/controller/import_processing.go) and
// reports the package as unsafe; it deletes nothing, because the audit never
// writes to, deletes, or modifies the package it reads. Measured against the
// real files on this machine, the table as first written refused legitimate
// packages: one free-string rule fired on 23 of 28 legitimate shared libraries.
// That is why the four string-evidence families below live under new ids at LOW
// rather than borrowing the source arm's severity - the source arm's rules match
// Python source, where a literal in a call is a different fact from a byte run
// in a binary.
//
// "LOW" is the literal the report path already uses for a non-blocking finding:
// DefaultRules() has no LOW constant, and ClassifyFindingRisk falls through to
// "LOW" for any severity that is neither HIGH nor MEDIUM. A LOW finding still
// reaches the report and still goes to the Tier-2 verifier, which can raise it
// to MALICIOUS on its own evidence; it simply does not block by itself.
var binaryOnlyRules = map[string]Rule{
	"BIN_001": {
		ID:       "BIN_001",
		Category: "加壳载荷",
		// HIGH, not MEDIUM: the reading is a measurement rather than a pattern -
		// an executable section that measures near eight bits per byte has been
		// compressed or encrypted and something must unpack it before it runs -
		// and packing is exactly what this channel exists to catch. The
		// measurement does not misfire on ordinary libraries: across a measured
		// 600 shared objects on the host (538 distinct ELFs, 2027 file entries),
		// none was marked structural, none lacked a section table and none
		// errored, and the highest executable-section entropy was 6.777009
		// bits/byte, on libcrypto.so.3's .text (3347362 bytes, read whole rather
		// than sampled), 0.723 below the 7.5 threshold. libgomp.so's 7.97
		// .gnu_debugdata is not SHF_EXECINSTR so the extractor never measures it.
		Severity:    SeverityHigh,
		Description: "可执行节区熵接近随机 — 代码已被压缩或加密，运行前必须先解包",
	},
	"BIN_002": {
		ID:          "BIN_002",
		Category:    "内存执行",
		Severity:    SeverityHigh,
		Description: "导入 memfd_create/fexecve — 可在内存中落盘并执行载荷，不产生可审计的磁盘文件",
	},
	"PKL_001": {
		ID:          "PKL_001",
		Category:    "反序列化执行",
		Severity:    SeverityHigh,
		Description: "pickle 流要求反序列化器解析具备进程/IO/网络能力的模块属性 — 加载即执行",
	},
	// The four families below carry free-string evidence and are LOW. Their ids
	// are new rather than shared because PER_001 and CMD_001 are HIGH in the
	// source table and FIL_001/ENV_001 are MEDIUM - and MEDIUM is not the safe
	// level either, because under the gate policy it blocks and deletes too.
	// Giving them LOW under a shared id would make the two arms
	// disagree about a shared family's severity, which
	// TestBinaryRulesBorrowSharedFamilies exists to prevent.
	"CMD_002": {
		ID:          "CMD_002",
		Category:    "命令执行（字符串证据）",
		Severity:    "LOW",
		Description: "二进制中的字面量呈现命令行形态 — 需人工确认是配置文本还是执行载荷",
	},
	"PER_002": {
		ID:          "PER_002",
		Category:    "持久化后门（字符串证据）",
		Severity:    "LOW",
		Description: "二进制中的字面量呈现持久化形态 — 需人工确认",
	},
	"FIL_002": {
		ID:          "FIL_002",
		Category:    "敏感文件读取（字符串证据）",
		Severity:    "LOW",
		Description: "二进制中的字面量指向敏感路径 — 需人工确认是读取能力还是日志文本",
	},
	"ENV_002": {
		ID:          "ENV_002",
		Category:    "环境变量（字符串证据）",
		Severity:    "LOW",
		Description: "二进制中的字面量是一个密钥型环境变量名 — 需人工确认",
	},
}

// binaryFamily is the evidence one family can be shown by.
//
// Sources is not an optimisation. Without it a rule written for symbol names
// would fire on a string literal that happened to spell one, and the operator
// would get a HIGH finding for a log line. The restriction states, in the place
// the rule is written, what kind of fact the rule is about.
type binaryFamily struct {
	ID       string
	Sources  []EvidenceSource
	Patterns []*regexp.Regexp
}

// binaryFamilies is the table, in match-precedence order. The order is the
// precedence: one evidence line produces at most one finding, so the first rule
// that matches owns the line, and a line two families could describe would be
// counted once rather than double-weighted in the statistics. No two families
// in the table as written actually overlap (see Match), so that rule is held for
// the first overlap rather than exercised today.
//
// The claim sets are narrower than the source arm's on purpose, and the
// narrowing is the fix for the false positives this table was measured to have.
// A rule whose claim is a bare identifier or a substring catches every
// legitimate file that happens to contain it - which for a model package means
// a deleted package, not a noisy report.
var binaryFamilies = []binaryFamily{
	{
		// memfd_create and fexecve lead the table so that, if the general
		// command family's claim is ever widened to cover them, the more
		// specific family is the one that names the finding. Today CMD_001's
		// list is anchored and names neither, so the pair does not overlap and
		// the position is held for that widening rather than exercised now.
		ID:       "BIN_002",
		Sources:  []EvidenceSource{SourceDynsym},
		Patterns: compilePatterns(`^(memfd_create|fexecve)$`),
	},
	{
		// The symbol half of command execution, and the half that is structural:
		// a dynamic symbol table entry is written by the linker, so a binary that
		// imports system() has the capability. Only SourceDynsym - the string
		// half lives in CMD_002 below, because the same word in a literal is not
		// a capability.
		//
		// The same corpus run that produced the NET_002 measurement puts this
		// family on a legitimate library too: `nm -D` shows
		// libggml-base.so.0.20.2 importing `execlp`, so CMD_001 reports HIGH on
		// ggml's own backend loader. That is the same undecided posture the
		// NET_002 note records, left undecided here for the same reason.
		ID:      "CMD_001",
		Sources: []EvidenceSource{SourceDynsym},
		Patterns: compilePatterns(
			`^(system|execve|execv|execvp|execl|execlp|execle|popen|posix_spawn|posix_spawnp|forkpty|WinExec|ShellExecuteA|ShellExecuteW|CreateProcessA|CreateProcessW)$`,
		),
	},
	{
		// The client half of raw network use. The set was narrowed to the
		// outbound-client shape out of the measurement below, and the narrowing
		// did not achieve what it was for.
		//
		// Measured with the wide symbol readers (`nm -D`, or `readelf -sW
		// --dyn-syms`; plain `readelf --dyn-syms` replaces the symbol name with
		// `[...]` but keeps the `@GLIBC_x.y` version suffix and index, and the
		// elision tracks the rendered entry width rather than the name alone, so
		// even short names like `socket` and `connect` disappear) against the 28
		// top-level `.so*` entries of this machine's ollama bundle - 22
		// regular files plus 6 symlinks. The recursive count of regular `.so*`
		// files is 52, a different set: do not read 52 against 28 as a
		// regression. The generic and server-side symbols - `bind`, `send`,
		// `recv` - are imported by libllama-common.so, a legitimate library, so
		// dropping them did remove that match. But the client symbols were kept,
		// and they sit in the same
		// libraries: libllama-common.so.0.1.2 and libllama-server-impl.so both
		// import `socket`, `connect` and `getaddrinfo` alongside
		// `bind`/`send`/`recv`, and the CUDA runtime libraries under
		// cuda_v12/cuda_v13 import `bind`/`connect`/`socket`.
		//
		// So on this machine's bundle NET_002 reports HIGH on legitimate
		// libraries, and under the default `assist` policy, where `Passed` is
		// `highCount == 0`, that means passed=false for a package that holds one
		// of them. The "or needs libcurl" half of the original claim does hold:
		// no library in the bundle carries a curl or ssl DT_NEEDED.
		//
		// This is not a mis-written comment; it is a rule posture that was never
		// decided. Narrowing the pattern set further, dropping the family to
		// MEDIUM, and requiring it to co-occur with another family are all open,
		// and this task chooses none of them - it records the measurement and
		// leaves the decision unmade. The shared id and its severity are the
		// source arm's, so as written this family stays HIGH.
		ID:      "NET_002",
		Sources: []EvidenceSource{SourceDynsym, SourceNeeded},
		Patterns: compilePatterns(
			`^(socket|connect|getaddrinfo|gethostbyname|gethostbyaddr|inet_addr|inet_pton|WSAStartup|WSASocketA|WSASocketW)$`,
			`^libcurl\.so`,
			`^libssl\.so`,
		),
	},
	{
		// MEDIUM, borrowed from the shared table. It stays: dlopen is ordinary in
		// legitimate shared objects, but the evidence is structural - the symbol
		// table says the library declares the capability - and the shared
		// severity is the source arm's to set.
		ID:       "DYN_001",
		Sources:  []EvidenceSource{SourceDynsym},
		Patterns: compilePatterns(`^(dlopen|dlmopen|dlsym)$`),
	},
	{
		ID:      "PKL_001",
		Sources: []EvidenceSource{SourcePickle},
		Patterns: compilePatterns(
			// Process execution. The module list is a deny list of capabilities,
			// not an allow list of libraries: an allow list would have to name
			// every legitimate rebuilder torch has ever shipped, and would fail
			// open on the first one it had not heard of.
			`^(?:posix|nt|os)\.(?:system|popen|exec[a-z]*|spawn[a-z]*|fork|forkpty|kill|killpg|setuid|setreuid|seteuid|dup2)$`,
			`^(?:subprocess|pty|commands|runpy|importlib)\.\w+$`,
			`^(?:builtins|__builtin__)\.(?:eval|exec|compile|__import__|open)$`,
			`^(?:ctypes|socket|webbrowser)\.\w+$`,
		),
	},
	{
		// The string half of command execution, at LOW. Only genuine command-line
		// shapes survive here: a bare symbol name in a literal is what
		// TestSymbolRulesDoNotMatchStringLiterals refuses, and an unanchored
		// substring catches a fragment of a concatenated constant pool.
		ID:      "CMD_002",
		Sources: []EvidenceSource{SourceStrings},
		Patterns: compilePatterns(
			`^/bin/(sh|bash|dash|zsh)$`,
			`^(bash|sh) -c\b`,
			`\b(curl|wget)\s+.*https?://`,
		),
	},
	{
		// Token-anchored at both ends. The previous patterns fired on
		// `'crontabz'` and on `'.profilez\t/etc/cron)'`, both fragments of a
		// concatenated .pyc constant pool, where a mid-run path always matches an
		// unanchored pattern. A boundary on the token, not the fragment, is the
		// fix; raising the severity would not have been.
		//
		// The two fragments come from different files, which an earlier version
		// of this note got wrong by attaching both to one of them.
		// `'.profilez\t/etc/cron)'` (a TAB, not a space) is the single occurrence
		// in models/audit/tools/cpg/__pycache__/taint_engine.cpython-312.pyc,
		// which contains no `crontab` substring at all. `'crontabz'` is in
		// models/examples/__pycache__/code_security_analyzer.cpython-312.pyc,
		// where the source literal `r"crontab"` in
		// models/examples/code_security_analyzer.py has picked up the trailing
		// `z` from the concatenation - the fragment is real, only the file was
		// misattributed.
		ID:      "PER_002",
		Sources: []EvidenceSource{SourceStrings},
		Patterns: compilePatterns(
			`^crontab\b`,
			`^/etc/cron[a-z.]*`,
			`(?:^|/)\.bashrc$`,
			`(?:^|/)\.bash_profile$`,
			`^systemctl\s+(enable|start)`,
			`^/etc/systemd/system`,
			`^/etc/init\.d`,
		),
	},
	{
		// Same anchoring requirement, same measurement. `'.aws/credentialsz'`
		// and `'.ssh/id_rsaz'` were the observed fragments; the trailing `z` is
		// proof the match was a fragment of a concatenated run.
		//
		// The `$` alone is not what refuses them. It refuses a *suffixed*
		// neighbour - `'.aws/credentialsz'` stops matching `\.aws/credentials$`
		// because the `$` will not sit at the `z`. It does not refuse an
		// *invented* key name: `id_[a-z]+` consumes `id_rsaz`'s trailing `z`
		// happily, so the `$` is satisfied and the fragment matches anyway. Only
		// a closed key-name list refuses that, which is why the `.ssh`
		// alternation names the four real keys rather than reaching for
		// `id_[a-z]+`.
		ID:      "FIL_002",
		Sources: []EvidenceSource{SourceStrings},
		Patterns: compilePatterns(
			`^/etc/(?:passwd|shadow|sudoers)$`,
			`^(?:.*/)?\.ssh/(?:id_(?:rsa|dsa|ecdsa|ed25519)|authorized_keys|config)$`,
			`^(?:.*/)?\.aws/credentials$`,
			`(?:^|/)\.kube/config$`,
			`^/proc/self/environ$`,
		),
	},
	{
		// Exact case, and no (?i). The source arm's ENV_001 carries (?i) because
		// it matches `os.getenv("AWS_SECRET_ACCESS_KEY")`, an upper-case name by
		// convention; the same flag here made the lower-case identifier
		// `private_key` match `PRIVATE_KEY` in security.cpython-312.pyc. A bare
		// identifier is a name, not a secret read.
		ID:      "ENV_002",
		Sources: []EvidenceSource{SourceStrings},
		Patterns: compilePatterns(
			`^(?:AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|API_KEY|SECRET_KEY|ACCESS_TOKEN|PRIVATE_KEY|GITHUB_TOKEN)$`,
		),
	},
	{
		ID:       "BIN_001",
		Sources:  []EvidenceSource{SourceEntropy},
		Patterns: compilePatterns(`^high-entropy-`),
	},
}

// There is deliberately no OBF_001 family here, and its absence is a decision
// rather than an omission. The source arm keeps OBF_001 for
// `base64.b64decode(...)` and friends, where the evidence is a call. The binary
// arm originally matched `^[A-Za-z0-9+/]{120,}={0,2}$` against SourceStrings,
// and that is where 23 of 28 legitimate shared libraries fired: the pattern
// matches any 120-plus-byte run drawn from the base64 alphabet, which is
// everywhere in binary data and in .pyc string tables - a plain 120-digit
// decimal run in libllama.so.0.1.2 is enough. Tightening the alphabet or raising
// the floor does not help, because the runs are real and long; the honest fix is
// an occupancy guard on a whole unit (the section or member must be
// predominantly the encoded run, not merely contain one), and no producer for
// that unit-level verdict exists in this plan. So the family is dropped here and
// the absence is stated rather than left to be rediscovered.

// BinaryMatcher resolves the binary family table against the shared severity
// table and matches evidence lines against it.
type BinaryMatcher struct {
	rules []Rule
	order []binaryFamily
}

// NewBinaryMatcher builds the matcher, resolving every family id to a Rule.
//
// Resolution happens here, at construction, rather than per finding: a family id
// that is in neither table is a programming error, and a matcher that silently
// skipped it would drop a whole family's findings without a trace. The engine
// selector makes the same choice for the same reason.
func NewBinaryMatcher() (*BinaryMatcher, error) {
	shared := map[string]Rule{}
	for _, r := range DefaultRules() {
		shared[r.ID] = r
	}

	m := &BinaryMatcher{order: binaryFamilies}
	for _, fam := range binaryFamilies {
		var rule Rule
		if r, ok := shared[fam.ID]; ok {
			rule = r
		} else if r, ok := binaryOnlyRules[fam.ID]; ok {
			rule = r
		} else {
			return nil, fmt.Errorf("binary family %s names no rule: it is in neither the shared table nor the binary-only table", fam.ID)
		}
		// The patterns live on the family, not on the Rule: Rule.Patterns is the
		// source arm's matcher, and writing these there would make the regex and
		// semgrep engines carry patterns for text they never read.
		m.rules = append(m.rules, rule)
	}
	return m, nil
}

// Rules returns the resolved rule set, for report metadata and for tests that
// check it against the shared table.
func (m *BinaryMatcher) Rules() []Rule {
	out := make([]Rule, len(m.rules))
	copy(out, m.rules)
	return out
}

// Match returns the first rule the line matches, or nil.
//
// First rather than all: the finding list is what the statistics and the LLM
// quota are computed from, and one evidence line is one observation. A line two
// families could describe is reported once, under the earlier family.
//
// That order is the intended rule, but it is not observable in the table as it
// stands, because no two families overlap: each pair differs in source, in
// pattern text, or in both, so no line is described by more than one and the
// order never decides anything. The pair that looks like the exception is not
// one - BIN_002 claims memfd_create and fexecve while CMD_001's command list is
// anchored and simply does not contain fexecve, so nothing is claimed twice.
// This doc used to cite memfd_create as an overlap the BIN_002-before-CMD_001
// order resolved; that was wrong. The order is a rule held for the first real
// overlap, not one doing work today, and no test asserts it for the same reason:
// with nothing to assert against, the only way to test precedence now would be
// to tilt the table into an overlap it does not have, which pins a fiction
// rather than the code. When a family that genuinely overlaps an earlier one is
// added, that is the moment to add the test and to say here which one wins.
func (m *BinaryMatcher) Match(line EvidenceLine) *Rule {
	for i := range m.order {
		fam := &m.order[i]
		if !fam.appliesTo(line.Source) {
			continue
		}
		for _, pat := range fam.Patterns {
			if pat.MatchString(line.Text) {
				return &m.rules[i]
			}
		}
	}
	return nil
}

// MatchAll returns one rule per matching line, in listing order, with the
// index of the matched line. It is a slice-building convenience over Match so
// that the scanner does not re-implement the precedence loop.
//
// The binary scanner is its caller: binary_scanner.go calls MatchAll rather
// than re-implementing the precedence loop. No test calls it yet, so it is
// exercised only through the scanner.
func (m *BinaryMatcher) MatchAll(lines []EvidenceLine) []binaryMatch {
	var out []binaryMatch
	for i := range lines {
		if rule := m.Match(lines[i]); rule != nil {
			out = append(out, binaryMatch{Index: i, Rule: *rule})
		}
	}
	return out
}

// binaryMatch is one line's rule, with the line's position so the scanner can
// build a context window from the listing around it.
type binaryMatch struct {
	Index int
	Rule  Rule
}

func (f *binaryFamily) appliesTo(src EvidenceSource) bool {
	for _, s := range f.Sources {
		if s == src {
			return true
		}
	}
	return false
}

// BinaryRuleIDs returns every family id in the table, sorted.
//
// It exists so that the completeness test can be written against the table
// rather than against a list someone maintains by hand: a family added here and
// forgotten in ruleSuggestionMap is a finding whose recommendation reads
// "审查该代码片段并确认其安全性" whatever it actually is, and the test that
// catches that has to enumerate the families from their one definition.
func BinaryRuleIDs() []string {
	ids := make([]string, 0, len(binaryFamilies))
	for _, f := range binaryFamilies {
		ids = append(ids, f.ID)
	}
	sort.Strings(ids)
	return ids
}
