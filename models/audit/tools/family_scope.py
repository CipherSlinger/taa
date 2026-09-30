# models/audit/tools/family_scope.py
"""Derive corpus labels from the written semantics of our own rule families.

Why a third instrument exists
-----------------------------
The holdout's labels were not produced from our rule families. The semgrep-rules
arm took its labels from upstream `# ruleid:` / `# ok:<upstream rule>` comments
and mapped them onto our families by substring matching (holdout_corpus.py
FAMILY_LEXEMES), so a label encoded ANOTHER rule's narrower expectation; the
pypi arm was labelled benign merely for being a genuine sdist; the DataDog arm
malicious merely for dataset membership. Measured against those labels the two
Tier 1 engines are being asked "is this code malicious", which is the joint
question of Tier 1 and the LLM arbiter, and Tier 1 alone cannot answer it. What
Tier 1 is specified to do is flag code that contains a construct one of our
families describes, and leave the intent question to Tier 2.

The label this module emits is therefore:

    malicious  iff  the source contains a construct inside some family's
                    "matched object" scope, and is not covered by that family's
                    written benign exemption
    benign     otherwise

Tautology defence, which is the whole point of the module
---------------------------------------------------------
The label must NOT come from either engine's output. If it did, that engine
would be its own ground truth, would score perfectly by construction, and the
comparison would measure nothing. So this is a third implementation: it reads
bytes, parses with `ast`, and resolves imports itself. It shares no code with
the regex arm (models/examples/code_security_analyzer.py SUSPICIOUS_PATTERNS)
or the semgrep arm (models/audit/semgrep/rules/python/rules.yaml).

Being AST-based also makes it the right instrument for a semantic criterion:
a construct named in a comment or a docstring is not code, and does not put a
sample in scope. That matters because four of our families are implemented in
semgrep as `pattern-regex`, which does match comments, while the regex arm
skips comment lines outright.

The written basis, quoted per decision
--------------------------------------
Every scope decision cites:
  SPEC  .claude/specs/2026-09-16-audit-benchmark-design.md section 4.1, the
        13-row table of "matched object and pattern" plus "expected benign
        exemption" (lines 157-175)
  CHECK models/audit/tools/audit_benchmark_eval.py CHECKLIST_RULES_PROMPT
        (lines 58-72), the one-line-per-family English checklist

Sensitivity band
----------------
The written semantics are ambiguous at the margins, and the ambiguity is not
neutral: a generous reading resolves imports, which semgrep does and the regex
arm does not, so it favours semgrep. Rather than pick one reading and hide the
choice, three variants are emitted from one table:

  strict      only the constructs the checklist enumerates, in the exact
              attribute form, with no import resolution
  primary     the generous reading: import resolution, legacy and aliased
              spellings, and the external-interpreter forms (section 2.2)
  permissive  primary widened to any subprocess/socket/open/base64 use

A verdict that flips between these is reported as not established, not as the
variant that happens to pass.

Security
--------
Samples include real malware (the DataDog arm). This module opens files for
their bytes and calls `ast.parse`. It never imports, executes or byte-compiles
a sample, and never runs a sample's own install hooks, which are the malware's
persistence mechanism. Evidence records construct names, not sample text.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

VARIANTS: Tuple[str, ...] = ("strict", "primary", "permissive")

SPEC = "spec:2026-09-16-audit-benchmark-design.md#4.1"
CHECK = "checklist:audit_benchmark_eval.py:58-72"

# The keyword alternation ENV_001 is specified over, verbatim from the rule.
ENV_SENSITIVE = re.compile(
    r"(?i)secret|token|api[_-]?key|access[_-]?key|private[_-]?key|password|"
    r"passwd|pwd|cred|credential|auth|session|cookie|kube|aws|gcp|azure|github|gitlab"
)
# The path fragments FIL_001 is specified over, verbatim from the rule.
FILE_SENSITIVE = re.compile(
    r"(?i)\.ssh|\.env|password|credential|\.aws|\.kube|id_rsa|authorized_keys"
)
# PER_001, verbatim from the rule.
PERSISTENCE = re.compile(
    r"(?i)crontab|\.bashrc|\.bash_profile|\.zshrc|/etc/init\.d|/etc/systemd"
)
PERSISTENCE_CMD = re.compile(r"systemctl\s+(enable|start)")
# The dataset-name stems EMB_003/EMB_004 are specified over.
DATA_NAMES = re.compile(r"(?:raw_|train_|test_)?(?:data|dataset|images|samples|x_train|y_train|batch)\b")
STEGO_NAMES = re.compile(r"(?i)(hidden|secret|payload|stego|embed|hide)")


@dataclass(frozen=True)
class Evidence:
    """One construct that puts a sample in scope, with where and under what."""

    file: str
    line: int
    family: str
    construct: str
    detail: str = ""
    citation: str = ""

    def as_dict(self) -> Dict[str, Any]:
        d = {"file": self.file, "line": self.line, "family": self.family, "construct": self.construct}
        if self.detail:
            d["detail"] = self.detail
        if self.citation:
            d["citation"] = self.citation
        return d


@dataclass
class SampleVerdict:
    sample_id: str
    variant: str
    label: str
    in_scope_families: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    files_scanned: int = 0
    parse_errors: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "variant": self.variant,
            "label": self.label,
            "in_scope_families": self.in_scope_families,
            "files_scanned": self.files_scanned,
            "parse_errors": self.parse_errors,
            "evidence": [e.as_dict() for e in self.evidence],
        }


# --------------------------------------------------------------------------
# Import resolution
# --------------------------------------------------------------------------

def _dotted(node: ast.AST) -> Optional[str]:
    """The dotted spelling of a Name/Attribute chain, or None."""
    parts: List[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _aliases(tree: ast.AST) -> Dict[str, str]:
    """local name -> canonical dotted prefix, from every import in the file.

    Imports are collected file-wide rather than scope by scope. That is a
    deliberate over-approximation: it is the generous reading, and being
    generous here is what keeps the criterion independent of which engine
    happens to resolve names.
    """
    alias: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    alias[a.asname] = a.name
                else:
                    alias[a.name.split(".")[0]] = a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            if not node.module:
                continue
            for a in node.names:
                alias[a.asname or a.name] = f"{node.module}.{a.name}"
    return alias


def _resolve(name: Optional[str], alias: Dict[str, str]) -> Optional[str]:
    if name is None:
        return None
    head, _, rest = name.partition(".")
    base = alias.get(head, head)
    return f"{base}.{rest}" if rest else base


def _literal(node: ast.AST) -> Optional[str]:
    """A string literal, or a concatenation of literals (a static string)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _literal(node.left), _literal(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _is_fully_literal(node: ast.AST) -> bool:
    """True when the expression is built only from literals."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_fully_literal(node.left) and _is_fully_literal(node.right)
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return all(_is_fully_literal(e) for e in node.elts)
    return False


# --------------------------------------------------------------------------
# Per-scope facts
# --------------------------------------------------------------------------

@dataclass
class _Facts:
    """What one lexical scope contains. Co-occurrence families need the scope."""

    calls: List[Tuple[str, int, ast.Call]] = field(default_factory=list)
    strings: List[Tuple[str, int]] = field(default_factory=list)
    opens: List[Tuple[str, int]] = field(default_factory=list)
    env_keys: List[Tuple[str, int]] = field(default_factory=list)
    children: List["_Facts"] = field(default_factory=list)

    def walk(self) -> Iterable["_Facts"]:
        yield self
        for c in self.children:
            yield from c.walk()


class _Collector(ast.NodeVisitor):
    def __init__(self, alias: Dict[str, str], strict: bool):
        self.alias = {} if strict else alias
        self.root = _Facts()
        self.stack: List[_Facts] = [self.root]

    @property
    def cur(self) -> _Facts:
        return self.stack[-1]

    def _scope(self, node: ast.AST) -> None:
        child = _Facts()
        self.cur.children.append(child)
        self.stack.append(child)
        self.generic_visit(node)
        self.stack.pop()

    visit_FunctionDef = _scope
    visit_AsyncFunctionDef = _scope
    visit_ClassDef = _scope
    visit_Lambda = _scope

    def visit_Call(self, node: ast.Call) -> None:
        name = _resolve(_dotted(node.func), self.alias)
        if name:
            self.cur.calls.append((name, node.lineno, node))
        # open(...) with a literal path -- FIL_001 reads the path itself.
        if name in ("open", "io.open"):
            lit = _literal(node.args[0]) if node.args else None
            if lit:
                self.cur.opens.append((lit, node.lineno))
        if name in ("os.environ.get", "os.getenv", "environ.get", "getenv"):
            lit = _literal(node.args[0]) if node.args else None
            if lit:
                self.cur.env_keys.append((lit, node.lineno))
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        name = _resolve(_dotted(node.value), self.alias)
        if name in ("os.environ", "environ"):
            lit = _literal(node.slice)
            if lit:
                self.cur.env_keys.append((lit, node.lineno))
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            self.cur.strings.append((node.value, node.lineno))
        self.generic_visit(node)


# --------------------------------------------------------------------------
# Construct tables
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class CallRule:
    """One call-shaped construct and the variants that count it as in scope."""

    family: str
    construct: str
    pattern: "re.Pattern[str]"
    variants: frozenset
    citation: str
    shell_true_only: bool = False


def _r(pat: str) -> "re.Pattern[str]":
    return re.compile(pat)


# NET_001. SPEC row: "requests.(get|post), urllib.request and similar high-level
# HTTP libraries"; CHECK: "requests, urllib, httpx, aiohttp, http.client".
_NET_HIGH = r"(get|post|put|delete|patch|head|request|Session)"
CALL_RULES: Tuple[CallRule, ...] = (
    CallRule("NET_001", "requests.<method>", _r(rf"^requests\.{_NET_HIGH}$"),
             frozenset({"strict", "primary", "permissive"}), SPEC),
    CallRule("NET_001", "httpx.<method>", _r(rf"^httpx\.{_NET_HIGH}$"),
             frozenset({"strict", "primary", "permissive"}), CHECK),
    CallRule("NET_001", "urllib.request.urlopen", _r(r"^urllib\.request\.urlopen$"),
             frozenset({"strict", "primary", "permissive"}), SPEC),
    CallRule("NET_001", "urllib.request.urlretrieve", _r(r"^urllib\.request\.urlretrieve$"),
             frozenset({"strict", "primary", "permissive"}), CHECK),
    CallRule("NET_001", "urllib.request.build_opener", _r(r"^urllib\.request\.(build_opener|OpenerDirector)$"),
             frozenset({"primary", "permissive"}), CHECK),
    CallRule("NET_001", "urllib.urlopen (legacy)", _r(r"^urllib\.(urlopen|urlretrieve)$"),
             frozenset({"primary", "permissive"}), SPEC),
    CallRule("NET_001", "urllib URLopener (legacy)", _r(r"^urllib\.(URLopener|FancyURLopener)$"),
             frozenset({"primary", "permissive"}), SPEC),
    CallRule("NET_001", "http.client.HTTP(S)Connection", _r(r"^http\.client\.HTTPS?Connection$"),
             frozenset({"strict", "primary", "permissive"}), CHECK),
    CallRule("NET_001", "aiohttp.ClientSession", _r(r"^aiohttp\.ClientSession$"),
             frozenset({"strict", "primary", "permissive"}), CHECK),
    CallRule("NET_001", "httplib2.Http", _r(r"^httplib2\.Http$"),
             frozenset({"strict", "primary", "permissive"}), CHECK),
    CallRule("NET_001", "any .urlopen/.urlretrieve", _r(r"\.(urlopen|urlretrieve)$"),
             frozenset({"permissive"}), CHECK),

    # NET_002. SPEC row: "socket.socket, socket.create_connection"; exemption:
    # none, the row says direct block.
    CallRule("NET_002", "socket.socket", _r(r"^socket\.socket$"),
             frozenset({"strict", "primary", "permissive"}), SPEC),
    CallRule("NET_002", "socket.create_connection", _r(r"^socket\.create_connection$"),
             frozenset({"strict", "primary", "permissive"}), SPEC),
    CallRule("NET_002", "any socket.<constructor>", _r(r"^socket\.[A-Za-z_]+$"),
             frozenset({"permissive"}), SPEC),

    # CMD_001. SPEC row: "os.system, subprocess(shell=True) or an external
    # interpreter invocation"; exemption: strictly parameterised nvidia-smi.
    CallRule("CMD_001", "os.system", _r(r"^os\.system$"),
             frozenset({"strict", "primary", "permissive"}), SPEC),
    CallRule("CMD_001", "os.popen", _r(r"^os\.popen[0-9]?$"),
             frozenset({"strict", "primary", "permissive"}), SPEC),
    CallRule("CMD_001", "os.exec*", _r(r"^os\.exec[a-z]*$"),
             frozenset({"strict", "primary", "permissive"}), SPEC),
    CallRule("CMD_001", "os.spawn*", _r(r"^os\.(spawn[a-z]*|posix_spawn[a-z]*)$"),
             frozenset({"primary", "permissive"}), SPEC),
    CallRule("CMD_001", "commands.getoutput", _r(r"^commands\.(getoutput|getstatusoutput)$"),
             frozenset({"strict", "primary", "permissive"}), SPEC),
    CallRule("CMD_001", "subprocess.<fn>(shell=True)",
             _r(r"^subprocess\.(run|call|Popen|check_output|check_call|getoutput|getstatusoutput)$"),
             frozenset({"strict", "primary", "permissive"}), SPEC, shell_true_only=True),
    CallRule("CMD_001", "pty.spawn", _r(r"^pty\.spawn$"),
             frozenset({"primary", "permissive"}), SPEC),
    CallRule("CMD_001", "paramiko.<fn>", _r(r"^paramiko\."),
             frozenset({"primary", "permissive"}), SPEC),
    CallRule("CMD_001", "pexpect.<fn>", _r(r"^pexpect\."),
             frozenset({"primary", "permissive"}), SPEC),
    CallRule("CMD_001", "fabric.<fn>", _r(r"^fabric\."),
             frozenset({"primary", "permissive"}), SPEC),
    CallRule("CMD_001", "invoke.<fn>", _r(r"^invoke\."),
             frozenset({"primary", "permissive"}), SPEC),
    CallRule("CMD_001", "plumbum.<fn>", _r(r"^plumbum\."),
             frozenset({"primary", "permissive"}), SPEC),
    CallRule("CMD_001", "any subprocess.<fn>", _r(r"^subprocess\.[A-Za-z_]+$"),
             frozenset({"permissive"}), SPEC),

    # OBF_001. SPEC row: "base64.(b64decode|b64encode), pickle.loads, zlib";
    # exemption: in-memory feature extraction and legitimate local thumbnails.
    CallRule("OBF_001", "base64.<codec>", _r(r"^base64\.(b64decode|b64encode|decodebytes|encodebytes|standard_b64decode|standard_b64encode|urlsafe_b64decode|urlsafe_b64encode|b32decode|b32encode|b16decode|b16encode)$"),
             frozenset({"strict", "primary", "permissive"}), SPEC),
    # Deserialisation only. The family is "obfuscation", the rule names
    # pickle.loads, and the other two artefacts are load-shaped; pickle.dump is
    # a writer and is reached through EMB_004 instead, where the rule table puts
    # it. _pickle is listed explicitly because rules.yaml:208-209 names it while
    # internal/codeaudit/rules.go does not -- an asymmetry this table has to
    # rule on rather than inherit. The ruling: _pickle is in scope, because it
    # is the same construct, so the regex arm's miss on it is a real miss.
    CallRule("OBF_001", "pickle.load/<loads>", _r(r"^(pickle|cPickle|_pickle)\.(load|loads|Unpickler)$"),
             frozenset({"primary", "permissive"}), SPEC),
    CallRule("OBF_001", "pickle.load/<loads> (literal spelling)", _r(r"^pickle\.(load|loads)$"),
             frozenset({"strict"}), SPEC),
    CallRule("OBF_001", "marshal.<fn>", _r(r"^marshal\.(load|loads)$"),
             frozenset({"strict", "primary", "permissive"}), SPEC),
    CallRule("OBF_001", "zlib.decompress", _r(r"^zlib\.decompress$"),
             frozenset({"strict", "primary", "permissive"}), SPEC),
    CallRule("OBF_001", "codecs.decode", _r(r"^codecs\.decode$"),
             frozenset({"primary", "permissive"}), SPEC),
    CallRule("OBF_001", "binascii.<codec>", _r(r"^binascii\.(a2b|b2a)"),
             frozenset({"strict", "primary", "permissive"}), SPEC),
    CallRule("OBF_001", "any base64.<fn>", _r(r"^base64\.[A-Za-z_]+$"),
             frozenset({"permissive"}), SPEC),

    # DYN_001. SPEC row: "eval(), exec(), __import__, dynamic module reflection";
    # exemption: whitelist-dict controlled dispatch.
    CallRule("DYN_001", "eval", _r(r"^eval$"),
             frozenset({"strict", "primary", "permissive"}), SPEC),
    CallRule("DYN_001", "exec", _r(r"^exec$"),
             frozenset({"strict", "primary", "permissive"}), SPEC),
    CallRule("DYN_001", "__import__", _r(r"^__import__$"),
             frozenset({"strict", "primary", "permissive"}), SPEC),
    CallRule("DYN_001", "importlib.import_module", _r(r"^importlib\.import_module$"),
             frozenset({"strict", "primary", "permissive"}), SPEC),
    CallRule("DYN_001", "compile(<src>, .., 'exec')", _r(r"^compile$"),
             frozenset({"strict", "primary", "permissive"}), CHECK),
)

_SHELL_BINARY = re.compile(
    r"(?i)^\s*(bash|sh|zsh|fish|echo|curl|wget|rm|ping|cmd\.exe|powershell|pwsh|nvidia-smi)\b"
)
_NVIDIA = re.compile(r"(?i)nvidia-smi")
_LOCAL_HEALTH = re.compile(r"(?i)^https?://(127\.0\.0\.1|localhost)(:\d+)?/health")

# EMB_001/EMB_002/EMB_003/EMB_004 call shapes.
_EMB_SAVE = re.compile(r"^(torch|np|numpy)\.(save|savez|savez_compressed)$")
_EMB_COPY = re.compile(r"^shutil\.(copy|copytree|move)$")
_EMB_LOG = re.compile(r"^(print|sys\.stdout\.write|sys\.stderr\.write)$|^logging\.[A-Za-z_]+$")
_EMB_RENAME = re.compile(r"^os\.rename$")
_EMB_PICKLE_DUMP = re.compile(r"^(pickle|cPickle|_pickle)\.(dump|dumps)$")


def _compute_scope_sha256() -> str:
    data = []
    for r in CALL_RULES:
        data.append(f"{r.family}|{r.construct}|{r.pattern.pattern}|{sorted(r.variants)}|{r.shell_true_only}|{r.citation}")
    data.append(f"ENV_SENSITIVE:{ENV_SENSITIVE.pattern}")
    data.append(f"FILE_SENSITIVE:{FILE_SENSITIVE.pattern}")
    data.append(f"PERSISTENCE:{PERSISTENCE.pattern}")
    data.append(f"PERSISTENCE_CMD:{PERSISTENCE_CMD.pattern}")
    data.append(f"SHELL_BINARY:{_SHELL_BINARY.pattern}")
    raw = "\n".join(data).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


SCOPE_SHA256: str = _compute_scope_sha256()


def _first_arg_name(node: ast.Call) -> Optional[str]:
    """A readable spelling of the first argument, for the EMB data-name tests."""
    if not node.args:
        return None
    a = node.args[0]
    if isinstance(a, ast.Constant) and isinstance(a.value, str):
        return a.value
    return _dotted(a)


def _all_arg_names(node: ast.Call) -> List[str]:
    out: List[str] = []
    for a in node.args:
        if isinstance(a, ast.Constant) and isinstance(a.value, str):
            out.append(a.value)
        else:
            d = _dotted(a)
            if d:
                out.append(d)
    for kw in node.keywords:
        if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            out.append(kw.value.value)
        else:
            d = _dotted(kw.value)
            if d:
                out.append(d)
    return out


# --------------------------------------------------------------------------
# Family evaluation
# --------------------------------------------------------------------------

def _all(facts: _Facts, attr: str) -> List[Any]:
    """Every entry of one fact list, across every scope in the file.

    A construct counts wherever it appears, so the presence families read the
    whole file. Only the co-occurrence families (EXF_001, EMB_004) care which
    scope a construct sits in, and they walk the scopes themselves.
    """
    out: List[Any] = []
    for scope in facts.walk():
        out.extend(getattr(scope, attr))
    return out


def _eval_calls(facts: _Facts, variant: str, relpath: str) -> List[Evidence]:
    out: List[Evidence] = []
    for name, line, node in _all(facts, "calls"):
        for rule in CALL_RULES:
            if variant not in rule.variants:
                continue
            if not rule.pattern.search(name):
                continue
            detail = name

            if rule.construct == "compile(<src>, .., 'exec')":
                # The compile branch is only in scope when it compiles for exec.
                if not any(isinstance(a, ast.Constant) and a.value == "exec" for a in node.args):
                    continue
            if rule.shell_true_only:
                if not any(kw.arg == "shell" and isinstance(kw.value, ast.Constant)
                           and kw.value.value is True for kw in node.keywords):
                    continue
            if rule.family == "CMD_001" and name.startswith("subprocess."):
                # SPEC exemption: a strictly parameterised hardware diagnostic.
                first = _literal(node.args[0]) if node.args else None
                if first and _NVIDIA.search(first) and not any(
                    kw.arg == "shell" and getattr(kw.value, "value", None) is True for kw in node.keywords
                ):
                    continue
            if rule.family == "NET_001":
                # SPEC exemption: an internal health check, and nothing else.
                # The URL has to be a literal for the exemption to be decidable;
                # a computed URL is not exempt, because the exemption names a
                # specific endpoint rather than a class of them.
                lits = [_literal(a) for a in list(node.args) + [k.value for k in node.keywords]]
                if any(l and _LOCAL_HEALTH.search(l) for l in lits):
                    continue
            out.append(Evidence(relpath, line, rule.family, rule.construct, detail, rule.citation))
    return out


def _eval_os_exec_indirect(facts: _Facts, variant: str, relpath: str) -> List[Evidence]:
    """getattr(os, "system")(...) and friends.

    SPEC row CMD_001 names os.system; reaching it through getattr is the same
    construct, so the generous reading counts it. Neither engine sees it.
    """
    if variant == "strict":
        return []
    out: List[Evidence] = []
    for name, line, node in _all(facts, "calls"):
        if name != "getattr":
            continue
        if len(node.args) < 2:
            continue
        target = _dotted(node.args[0])
        attr = _literal(node.args[1])
        if target in ("os", "subprocess") and attr:
            spelling = f"{target}.{attr}"
            for rule in CALL_RULES:
                if rule.family != "CMD_001" or variant not in rule.variants or rule.shell_true_only:
                    continue
                if rule.pattern.search(spelling):
                    out.append(Evidence(relpath, line, "CMD_001", "getattr(<mod>, <cmd fn>)",
                                        spelling, SPEC))
                    break
    return out


def _eval_cmd_shell_binary(facts: _Facts, variant: str, relpath: str) -> List[Evidence]:
    """subprocess with a system binary as the command, per the CHECK wording.

    CHECK CMD_001 says "subprocess with shell or system binaries". A literal
    command naming a binary counts; the strict variant, which reads only the
    enumerated attribute forms, does not.
    """
    if variant == "strict":
        return []
    out: List[Evidence] = []
    for name, line, node in _all(facts, "calls"):
        if not name.startswith("subprocess."):
            continue
        if not node.args:
            continue
        first = _literal(node.args[0])
        if first and _SHELL_BINARY.match(first):
            if _NVIDIA.search(first) and not any(
                kw.arg == "shell" and getattr(kw.value, "value", None) is True for kw in node.keywords
            ):
                continue
            out.append(Evidence(relpath, line, "CMD_001", "subprocess.<fn>(<system binary>)",
                                first.strip(), CHECK))
            continue
        # A list form: subprocess.run(["curl", ...])
        if isinstance(node.args[0], (ast.List, ast.Tuple)) and node.args[0].elts:
            head = _literal(node.args[0].elts[0])
            if head and _SHELL_BINARY.match(head):
                if _NVIDIA.search(head) and not any(
                    kw.arg == "shell" and getattr(kw.value, "value", None) is True for kw in node.keywords
                ):
                    continue
                out.append(Evidence(relpath, line, "CMD_001", "subprocess.<fn>([<system binary>, ..])",
                                    head.strip(), CHECK))
    return out


def _eval_fil(facts: _Facts, variant: str, relpath: str) -> List[Evidence]:
    out: List[Evidence] = []
    for path, line in _all(facts, "opens"):
        if not FILE_SENSITIVE.search(path):
            continue
        # SPEC exemption: reading a local hyper-parameter file.
        if path.endswith("params.json"):
            continue
        out.append(Evidence(relpath, line, "FIL_001", "open(<sensitive path>)", path, SPEC))
    for name, line, node in _all(facts, "calls"):
        if name not in ("Path", "pathlib.Path") or not node.args:
            continue
        lit = _literal(node.args[0])
        if lit and FILE_SENSITIVE.search(lit):
            out.append(Evidence(relpath, line, "FIL_001", "Path(<sensitive path>)", lit, SPEC))
    return out


def _eval_env(facts: _Facts, variant: str, relpath: str) -> List[Evidence]:
    out: List[Evidence] = []
    for key, line in _all(facts, "env_keys"):
        if ENV_SENSITIVE.search(key):
            out.append(Evidence(relpath, line, "ENV_001", "os.environ/getenv(<sensitive key>)", key, SPEC))
    return out


def _eval_per(facts: _Facts, variant: str, relpath: str) -> List[Evidence]:
    out: List[Evidence] = []
    for s, line in _all(facts, "strings"):
        if PERSISTENCE.search(s) or PERSISTENCE_CMD.search(s):
            out.append(Evidence(relpath, line, "PER_001", "persistence path in a string literal",
                                s[:60], SPEC))
    return out


def _eval_exf(facts: _Facts, variant: str, relpath: str) -> List[Evidence]:
    """EXF_001. SPEC row: composite -- "base64+request", "json.dumps+post",
    "encode+send". The written object is a co-occurrence, so it is evaluated
    per scope; the strict variant holds it to one line, as the row's spellings
    suggest, and the generous variants to one function.
    """
    out: List[Evidence] = []
    encode_names = re.compile(r"^(base64\.[A-Za-z_]+|json\.dumps|codecs\.encode|\.encode)$")
    net_names = re.compile(r"^(requests\.|httpx\.|urllib\.|aiohttp\.|socket\.|http\.client\.)")
    for scope in facts.walk():
        enc = [(n, l) for n, l, _ in scope.calls if encode_names.search(n)]
        net = [(n, l) for n, l, _ in scope.calls if net_names.search(n)]
        if not enc or not net:
            continue
        if variant == "strict":
            shared = [(n, l) for n, l in enc if any(l == l2 for _, l2 in net)]
            for n, l in shared:
                out.append(Evidence(relpath, l, "EXF_001", "encode and network on one line", n, SPEC))
        else:
            n, l = enc[0]
            out.append(Evidence(relpath, l, "EXF_001", "encodes then transmits in one scope",
                                f"{n} -> {net[0][0]}", SPEC))
    return out


def _eval_emb(facts: _Facts, variant: str, relpath: str) -> List[Evidence]:
    out: List[Evidence] = []
    for scope in facts.walk():
        for name, line, node in scope.calls:
            args = _all_arg_names(node)
            joined = " ".join(args)
            first = _first_arg_name(node) or ""

            if _EMB_SAVE.search(name) and DATA_NAMES.search(joined):
                # SPEC exemption: a legitimate model checkpoint.
                if "state_dict" in joined:
                    continue
                out.append(Evidence(relpath, line, "EMB_001", "saves a dataset-like object", name, SPEC))
            if _EMB_COPY.search(name) and re.search(r"(?i)data|dataset|train|test|image", joined):
                out.append(Evidence(relpath, line, "EMB_001", "copies a dataset-like path", name, SPEC))
            if _EMB_COPY.search(name) and re.search(r"(?i)output|export|result", joined):
                out.append(Evidence(relpath, line, "EMB_002", "copies into an output/export path", name, SPEC))
            if _EMB_RENAME.search(name) and re.search(r"(?i)data", joined) and re.search(r"(?i)output|result", joined):
                out.append(Evidence(relpath, line, "EMB_002", "renames data into an output path", name, SPEC))
            if _EMB_LOG.search(name) and DATA_NAMES.search(joined):
                out.append(Evidence(relpath, line, "EMB_003", "logs a dataset-like object", name, SPEC))
            if _EMB_PICKLE_DUMP.search(name) and DATA_NAMES.search(joined):
                out.append(Evidence(relpath, line, "EMB_004", "pickles a dataset-like object", name, SPEC))
            if name.startswith(("torch.save", "np.save", "numpy.save")) and "state_dict" in joined and STEGO_NAMES.search(joined):
                out.append(Evidence(relpath, line, "EMB_004", "weights plus a hiding-named value", name, SPEC))
        if scope.strings:
            names = " ".join(s for s, _ in scope.strings)
            if re.search(r"(?i)state_dict|weights|params", names) and STEGO_NAMES.search(names):
                out.append(Evidence(relpath, scope.strings[0][1], "EMB_004",
                                    "weights and a hiding-named value in one scope", "", SPEC))
    return out


def _evaluate(facts: _Facts, variant: str, relpath: str) -> List[Evidence]:
    out: List[Evidence] = []
    out += _eval_calls(facts, variant, relpath)
    out += _eval_os_exec_indirect(facts, variant, relpath)
    out += _eval_cmd_shell_binary(facts, variant, relpath)
    out += _eval_fil(facts, variant, relpath)
    out += _eval_env(facts, variant, relpath)
    out += _eval_per(facts, variant, relpath)
    out += _eval_exf(facts, variant, relpath)
    out += _eval_emb(facts, variant, relpath)
    return out


# --------------------------------------------------------------------------
# Public surface
# --------------------------------------------------------------------------

SCAN_EXTENSIONS: Tuple[str, ...] = (".py",)


def analyze_file(path: Path, variant: str, relpath: Optional[str] = None) -> Tuple[List[Evidence], Optional[str]]:
    """Every in-scope construct in one file. Returns (evidence, parse_error)."""
    if variant not in VARIANTS:
        raise ValueError(f"unknown variant {variant!r}; expected one of {VARIANTS}")
    rel = relpath or path.name
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], f"{rel}: {exc}"
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [], f"{rel}: {exc.__class__.__name__} at line {exc.lineno}"
    collector = _Collector(_aliases(tree), strict=(variant == "strict"))
    collector.visit(tree)
    return _evaluate(collector.root, variant, rel), None


def analyze_sample(sample_dir: Path, sample_id: str, variant: str,
                   extensions: Sequence[str] = SCAN_EXTENSIONS) -> SampleVerdict:
    """Label one sample directory."""
    verdict = SampleVerdict(sample_id=sample_id, variant=variant, label="benign")
    seen: Set[Tuple[str, int, str]] = set()
    for path in sorted(sample_dir.rglob("*")):
        if not path.is_file() or path.suffix not in extensions:
            continue
        verdict.files_scanned += 1
        evidence, err = analyze_file(path, variant, str(path.relative_to(sample_dir)))
        if err:
            verdict.parse_errors.append(err)
        for e in evidence:
            key = (e.file, e.line, f"{e.family}:{e.construct}")
            if key in seen:
                continue
            seen.add(key)
            verdict.evidence.append(e)
    verdict.in_scope_families = sorted({e.family for e in verdict.evidence})
    verdict.label = "malicious" if verdict.evidence else "benign"
    return verdict


def label_corpus(corpus_list: Path, benchmark_root: Path, variant: str) -> Dict[str, Any]:
    """Label every sample a corpus list declares, without touching its selection."""
    doc = json.loads(Path(corpus_list).read_text(encoding="utf-8"))
    samples = doc["samples"]
    verdicts = []
    counts = {"malicious": 0, "benign": 0}
    for s in samples:
        v = analyze_sample(Path(benchmark_root) / s["relative_path"], s["sample_id"], variant)
        verdicts.append(v.as_dict())
        counts[v.label] += 1
    return {
        "variant": variant,
        "corpus_list": str(corpus_list),
        "benchmark_root": str(benchmark_root),
        "counts": counts,
        "samples": verdicts,
    }


def rewrite_corpus_labels(corpus_list: Path, benchmark_root: Path, variant: str,
                          out_path: Path) -> Dict[str, Any]:
    """Write a corpus list whose selection is byte-identical and whose labels come
    from the oracle. The original labels are kept beside the new ones so the
    change stays auditable rather than silent."""
    doc = json.loads(Path(corpus_list).read_text(encoding="utf-8"))
    report = label_corpus(corpus_list, benchmark_root, variant)
    by_id = {r["sample_id"]: r for r in report["samples"]}
    changed = []
    for s in doc["samples"]:
        r = by_id[s["sample_id"]]
        if "legacy_label" not in s:
            s["legacy_label"] = s["label"]
        if r["label"] != s["label"]:
            changed.append({"sample_id": s["sample_id"], "was": s["label"], "now": r["label"]})
        s["label"] = r["label"]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report["out_path"] = str(out_path)
    report["changed"] = changed
    report["changed_count"] = len(changed)
    return report


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--corpus-list", type=Path, required=True)
    p.add_argument("--benchmark-root", type=Path, required=True)
    p.add_argument("--variant", choices=VARIANTS, default="primary")
    p.add_argument("--out", type=Path, default=None,
                   help="write a relabelled corpus list here; the selection is preserved")
    p.add_argument("--report", type=Path, default=None,
                   help="write the full per-sample evidence here")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.out:
        report = rewrite_corpus_labels(args.corpus_list, args.benchmark_root, args.variant, args.out)
    else:
        report = label_corpus(args.corpus_list, args.benchmark_root, args.variant)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"variant            : {report['variant']}")
    print(f"samples            : {len(report['samples'])}")
    print(f"malicious / benign : {report['counts']['malicious']} / {report['counts']['benign']}")
    if "changed_count" in report:
        print(f"labels changed     : {report['changed_count']}")
    if args.out:
        print(f"written to         : {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
