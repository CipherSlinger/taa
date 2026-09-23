# models/audit/tools/holdout_corpus.py
"""Build the holdout corpus from third-party sources.

The engine comparison is only as good as the corpus it runs on, and the main
benchmark cannot serve: the rules were aligned against it, so a clean result
there says the rules still fit the data they were fitted to. This module builds
the unseen corpus that stage H judges on.

Everything here is mechanical and outcome-blind. Samples are selected by
upstream facts - a published version, an upstream annotation, a path in
lexicographic order - and never by whether an engine reports them. The rules
being implemented were frozen before this file ran. One was amended before any
holdout data existed (plan section 12.2 rule 3, the malicious arm's
composition). Section 12.2 rule 7 records a window amendment that was later
withdrawn: it rested on an annotation count produced by a column-anchored
regex, and the frozen rule in section 4.2 - the innermost enclosing def/class -
is what this file implements.

Sources and what each contributes:

* semgrep-rules - upstream per-line ground truth. `# ruleid:` labels the line
  below it as a true positive, `# ok:` as a true negative. A sample is the
  enclosing scope of the labelled line, so the label travels with the code it
  describes.
* CodeQL's python security tests - explicitly labelled near-miss negatives.
* DataDog's trojanised PyPI packages - real malware. Scanned only: never
  installed, imported, executed, or byte-compiled. The samples' own install
  hooks are their persistence mechanism, which is why the build never runs
  anything from a sample.
* PyPI sdists of semgrep's direct dependencies - benign real-world code at
  pinned versions.

The corpus itself is not committed (plan section 12.4): it lives under an
ignored path and is rebuilt from this file plus `provenance.json`.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tarfile
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Plan section 12.2 rule 1: path substrings that mean "not the library itself".
BENIGN_EXCLUDED_SUBSTRINGS = ("tests/", "test_", "fixtures/", "examples/")
BENIGN_EXCLUDED_BASENAME = "__init__.py"

# Plan section 12.3. The upstream annotation was written for an upstream rule;
# this table translates its id to one of our families. Order matters: the first
# lexeme found in the id wins. Lexemes are deliberately specific - a loose one
# (`request`, `http`, `eval`) would sweep unrelated upstream rules into a family
# and attribute samples to rules that never look at them.
FAMILY_LEXEMES: tuple[tuple[str, str], ...] = (
    ("system-call", "CMD_001"),
    ("os-exec", "CMD_001"),
    ("spawn-process", "CMD_001"),
    ("subprocess", "CMD_001"),
    ("shell-true", "CMD_001"),
    ("reverse-shell", "CMD_001"),
    ("paramiko-exec", "CMD_001"),
    ("unchecked-subprocess", "CMD_001"),
    ("system-wildcard", "CMD_001"),
    ("urlopen", "NET_001"),
    ("urlretrieve", "NET_001"),
    ("httpsconnection", "NET_001"),
    ("http-not-https", "NET_001"),
    ("insecure-request-object", "NET_001"),
    ("json-shortcut", "NET_001"),
    ("no-auth-over-http", "NET_001"),
    ("socket", "NET_002"),
    ("telnet", "NET_002"),
    ("ssl-wrap-socket", "NET_002"),
    ("eval-detected", "DYN_001"),
    ("exec-detected", "DYN_001"),
    ("importlib", "DYN_001"),
    ("pickle", "OBF_001"),
)

# An annotation is a whole comment line. A mention inside a string or a longer
# comment is not an annotation, and treating one as such would invent labels.
# The leading whitespace matters: upstream writes an annotation at column zero
# and also indented inside the function it labels (measured: 783 column-zero,
# 1534 indented), so anchoring at column zero would silently see a third of the
# corpus and, worse, would look like a complete reading of it.
ANNOTATION_RE = re.compile(r"^\s*#\s*(ruleid|ok):\s*(\S+)")

LABEL_BY_KIND = {"ruleid": "malicious", "ok": "benign"}


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def family_of(rule_id: str) -> Optional[str]:
    """Our family for an upstream rule id, or None when it names none.

    None is not a failure: most of the upstream python corpus targets rules we
    have no counterpart for. Unmapped samples are excluded and counted, because
    a corpus that silently drops them looks better covered than it is.
    """
    if not rule_id:
        return None
    lowered = rule_id.lower()
    for lexeme, family in FAMILY_LEXEMES:
        if lexeme in lowered:
            return family
    return None


@dataclass(frozen=True)
class Window:
    """A candidate sample: a span of an upstream file with one ground truth."""

    start: int
    end: int
    kind: str
    annotated_rule: str
    family: Optional[str]

    @property
    def label(self) -> str:
        return LABEL_BY_KIND[self.kind]


@dataclass(frozen=True)
class FileExtraction:
    """What one upstream file yielded, drops included.

    Every drop is counted. A build that quietly discards what it cannot label
    reads as better covered than it is, and the counts are what let a reader
    check that the corpus is the one the rules describe.
    """

    windows: tuple[Window, ...] = ()
    annotations: int = 0
    dropped_outside: int = 0
    dropped_mixed: int = 0
    unparseable: bool = False


def _annotation_lines(lines: Sequence[str]) -> list[tuple[int, str, str]]:
    found: list[tuple[int, str, str]] = []
    for index, line in enumerate(lines, start=1):
        match = ANNOTATION_RE.match(line)
        if match:
            found.append((index, match.group(1), match.group(2)))
    return found


def _node_span(node: ast.AST) -> tuple[int, int]:
    """A statement's line span, decorators included and the body's end exact."""
    start = node.lineno
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.decorator_list:
        start = min([start] + [decorator.lineno for decorator in node.decorator_list])
    end = start
    for child in ast.walk(node):
        child_end = getattr(child, "end_lineno", None)
        if child_end and child_end > end:
            end = child_end
    return start, end


def enclosing_scope(spans: Sequence[tuple[int, int]], lineno: int) -> Optional[tuple[int, int]]:
    """The innermost def/class span holding a line, or None at module level.

    This is the frozen window definition (plan section 4.2). An annotation at
    module level has no window: a whole module is not a sample, and the rule
    says such annotations are dropped and counted rather than widened.
    """
    best: Optional[tuple[int, int]] = None
    for start, end in spans:
        if start <= lineno <= end and (best is None or (end - start) < (best[1] - best[0])):
            best = (start, end)
    return best


def scope_spans(tree: ast.AST) -> list[tuple[int, int]]:
    """Every def/class span in a file, computed once for all its annotations."""
    return [_node_span(node) for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]


def extract_file(text: str) -> FileExtraction:
    """Every labelled window in one upstream file.

    An annotation labels the statement below it, so the enclosing scope is
    looked up from the following line - looking up the comment's own line would
    find the scope of whatever ended above it.

    The span is widened to hold the annotation when the annotation sits above
    the definition it labels. The fragment is the sample and the annotation is
    the only record of its ground truth; a fragment without it cannot be audited
    by anyone reading the corpus later.

    Two annotations can share a span: a function carrying several annotated
    statements is one window, not several. When that span also holds an
    annotation of the other kind the fragment genuinely has no single label, and
    picking one would be choosing the answer the corpus then reports back.
    """
    lines = text.splitlines()
    annotations = _annotation_lines(lines)
    if not annotations:
        return FileExtraction()

    try:
        tree = ast.parse(text)
    except SyntaxError:
        return FileExtraction(annotations=len(annotations), unparseable=True)

    spans = scope_spans(tree)
    spans_by_window: dict[tuple[int, int], list[tuple[str, str]]] = {}
    outside = 0
    for lineno, kind, rule in annotations:
        span = enclosing_scope(spans, lineno + 1)
        if span is None:
            outside += 1
            continue
        window = (min(span[0], lineno), span[1])
        spans_by_window.setdefault(window, []).append((kind, rule))

    annotations_by_line = [(lineno, kind) for lineno, kind, _ in annotations]
    windows: list[Window] = []
    mixed = 0
    for (start, end), members in sorted(spans_by_window.items()):
        kinds_in_window = {kind for lineno, kind in annotations_by_line if start <= lineno <= end}
        if len(kinds_in_window) != 1:
            mixed += 1
            continue
        kind, rule = members[0]
        windows.append(Window(start=start, end=end, kind=kind,
                              annotated_rule=rule, family=family_of(rule)))

    return FileExtraction(windows=tuple(windows), annotations=len(annotations),
                          dropped_outside=outside, dropped_mixed=mixed)


def window_fragment(lines: Sequence[str], window: Window) -> str:
    """The window's text, dedented so an indented span still parses.

    A span lifted out of a function body arrives indented, and at module level
    that is a syntax error - which the corpus would then have to exclude. The
    dedent is the smallest change that makes the fragment a file.
    """
    body = "\n".join(lines[window.start - 1:window.end])
    return textwrap.dedent(body) + "\n"


def is_benign_excluded(relpath: str) -> bool:
    """Rule 1's hygiene for the benign arm: keep the library, not its furniture.

    Applies to the PyPI arm only. The malicious arm keeps `__init__.py` and
    `setup.py` on purpose - in a trojanised package those are where the payload
    lives, so excluding them would discard the malware and keep its packaging.
    """
    path = relpath.replace("\\", "/")
    if path.rsplit("/", 1)[-1] == BENIGN_EXCLUDED_BASENAME:
        return True
    return any(marker in path for marker in BENIGN_EXCLUDED_SUBSTRINGS)


def source_files(root: Path) -> Iterator[Path]:
    """Every `.py` under a directory, in path order, so selection is stable."""
    return iter(sorted(p for p in root.rglob("*.py") if p.is_file()))


def find_package_root(extracted: Path) -> Path:
    """The directory holding a package's modules, not its wrapper directory.

    An sdist unpacks to `<name>-<version>/`, and DataDog's zips add another
    layer of their own. Walking in until the layout stops being a single wrapper
    keeps the recorded paths relative to the code rather than to the archive.
    """
    current = extracted
    for _ in range(6):
        entries = [p for p in current.iterdir() if not p.name.startswith(".")]
        if len(entries) == 1 and entries[0].is_dir():
            current = entries[0]
            continue
        break
    return current


if __name__ == "__main__":
    raise SystemExit(0)
