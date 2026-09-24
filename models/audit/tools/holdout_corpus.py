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
import collections
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tarfile
import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Optional, Sequence

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
    annotated_line: int
    family: Optional[str]

    @property
    def label(self) -> str:
        return LABEL_BY_KIND[self.kind]

    def labelled_line(self) -> int:
        """The line the annotation labels, as a line of the extracted fragment.

        An annotation labels the statement below it, and the fragment starts at
        the window's first line, so the labelled line is the annotation's own
        line shifted into the fragment's numbering.
        """
        return self.annotated_line - self.start + 2


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
    spans_by_window: dict[tuple[int, int], list[tuple[int, str, str]]] = {}
    outside = 0
    for lineno, kind, rule in annotations:
        span = enclosing_scope(spans, lineno + 1)
        if span is None:
            outside += 1
            continue
        window = (min(span[0], lineno), span[1])
        spans_by_window.setdefault(window, []).append((lineno, kind, rule))

    annotations_by_line = [(lineno, kind) for lineno, kind, _ in annotations]
    windows: list[Window] = []
    mixed = 0
    for (start, end), members in sorted(spans_by_window.items()):
        kinds_in_window = {kind for lineno, kind in annotations_by_line if start <= lineno <= end}
        if len(kinds_in_window) != 1:
            mixed += 1
            continue
        lineno, kind, rule = members[0]
        windows.append(Window(start=start, end=end, kind=kind, annotated_rule=rule,
                              annotated_line=lineno, family=family_of(rule)))

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


# ------------------------------------------------------------------ assembly
#
# What the evaluator requires of a corpus, read off its own loader rather than
# assumed. Three facts drive this section:
#
# * A corpus list entry is parsed into the evaluator's SampleSpec, which rejects
#   any field it does not declare. An unrecognised key raises; it is not
#   ignored. So an entry carries the required fields and nothing else, and the
#   descriptive values an external corpus gets stay the evaluator's defaults -
#   a second copy here would be a second thing to drift.
# * The sample directory is resolved as `<benchmark_root>/<relative_path>`, and
#   the parity proof's traversal recognises `<root>/<id>/` and
#   `<root>/<project>/<id>/`. Two levels is therefore the layout that is found.
# * Attribution compares only the basename of `primary_attack_finding.file` and
#   the `rule_id`; the line number is not read. One file per sample keeps the
#   basename unambiguous.

# The five fields a corpus list entry must carry.
CORPUS_LIST_FIELDS = ("sample_id", "base_project", "family", "label", "relative_path")

# One file per sample directory, so a finding's basename identifies its sample.
SAMPLE_FILENAME = "sample.py"

# Families reported for samples whose upstream source states no rule family.
# They are not our rule families and must not be read as if they were: a
# trojanised package carries no annotation saying which of our rules sees it,
# and inventing one would put samples under rules that may never look at them.
FAMILY_PYPI = "PYPI-BENIGN"
FAMILY_CODEQL = "CODEQL-NEARMISS"
FAMILY_DATADOG = "DATADOG-MALICIOUS"
FAMILY_SEMGREP_RULES = "SEMGREP-RULES"  # only when the window maps to no family


@dataclass(frozen=True)
class Sample:
    """One sample: a single file, its label, and where it came from.

    The corpus is a list of these and nothing else. Everything a reader would
    need to check the sample - the upstream path, revision, hash, and the
    annotation that set the label - travels in `provenance`, so the corpus can
    be audited without re-running the retrieval.
    """

    sample_id: str
    base_project: str
    family: str
    label: str
    text: str
    provenance: dict[str, Any] = field(default_factory=dict)
    primary_attack_finding: Optional[dict[str, Any]] = None

    @property
    def relative_path(self) -> str:
        return f"{self.base_project}/{self.sample_id}"

    def corpus_list_entry(self) -> dict[str, str]:
        return {
            "sample_id": self.sample_id,
            "base_project": self.base_project,
            "family": self.family,
            "label": self.label,
            "relative_path": self.relative_path,
        }

    def sample_metadata(self) -> dict[str, Any]:
        """The sample's own record, read by the evaluator for attribution only.

        `expected_final` is deliberately absent. It is not read from here - the
        evaluator scores on a corpus list entry's `label`, and for a declared
        corpus it defaults the expectation to `UNSPECIFIED` - so a value here
        would be a claim nothing reads, differing from what the run reports.
        """
        return {
            "sample_id": self.sample_id,
            "base_project": self.base_project,
            "family": self.family,
            "label": self.label,
            "primary_attack_finding": self.primary_attack_finding,
            "source": self.provenance,
        }


def write_corpus(root: Path, samples: Sequence[Sample]) -> dict[str, Any]:
    """Write the corpus, and return the counts a report has to state.

    Idempotent: the corpus is rebuilt from the recipe, so every sample directory
    is written fresh rather than merged into whatever was there. Two things are
    refused rather than written, because both would look like a healthy corpus:
    a repeated `sample_id`, which the evaluator indexes pairs by, so a repeat
    silently drops a pair; and an empty sample, which scores as a file with
    nothing in it rather than as the retrieval failure it is.
    """
    root = Path(root)
    seen: set[str] = set()
    for sample in samples:
        if sample.sample_id in seen:
            raise ValueError(f"duplicate sample_id {sample.sample_id!r}; pairs are indexed by it")
        seen.add(sample.sample_id)
        if not sample.text.strip():
            raise ValueError(f"sample {sample.sample_id!r} is empty; that is a retrieval failure, not a sample")

        sample_dir = root / sample.relative_path
        sample_dir.mkdir(parents=True, exist_ok=True)
        (sample_dir / SAMPLE_FILENAME).write_text(sample.text, encoding="utf-8")
        (sample_dir / "sample.json").write_text(
            json.dumps(sample.sample_metadata(), indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )

    counts = corpus_counts(samples)
    (root / "corpus-list.json").write_text(
        json.dumps(corpus_list_payload(samples), indent=2) + "\n", encoding="utf-8"
    )
    return counts


def corpus_list_payload(samples: Sequence[Sample]) -> dict[str, Any]:
    """The run plan: an ordered list of samples and where each one lives."""
    return {"samples": [sample.corpus_list_entry() for sample in samples]}


def corpus_counts(samples: Sequence[Sample]) -> dict[str, Any]:
    """Counts by label, by family, and by source, for the report's tables.

    A per-family count is what requirement 4 is checked against, so it is
    reported for every family including the ones with no samples: a family that
    is absent from the table cannot be told apart from one that was never
    measured, and those call for different sentences in the report.
    """
    by_label: dict[str, int] = {label: 0 for label in LABEL_BY_KIND.values()}
    by_family: dict[str, dict[str, int]] = {}
    by_source: dict[str, int] = {}
    for sample in samples:
        by_label[sample.label] = by_label.get(sample.label, 0) + 1
        by_family.setdefault(sample.family, {})[sample.label] = (
            by_family.setdefault(sample.family, {}).get(sample.label, 0) + 1
        )
        source = str(sample.provenance.get("source", "unknown"))
        by_source[source] = by_source.get(source, 0) + 1
    return {
        "total": len(samples),
        "by_label": by_label,
        "by_family": {family: by_family[family] for family in sorted(by_family)},
        "by_source": {source: by_source[source] for source in sorted(by_source)},
    }


def provenance_payload(
    sources: Sequence[dict[str, Any]],
    samples: Sequence[Sample],
    drops: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """What a reader needs to check the corpus without rebuilding it.

    The per-sample records are the upstream facts only - path, revision, hash,
    annotation. They are what makes a label checkable: the label came from an
    upstream annotation, and this is the annotation.
    """
    return {
        "built_at": utc_now(),
        "sources": list(sources),
        "counts": corpus_counts(samples),
        "drops": dict(drops or {}),
        "samples": [
            {
                "sample_id": sample.sample_id,
                "family": sample.family,
                "label": sample.label,
                **sample.provenance,
            }
            for sample in samples
        ],
    }


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ------------------------------------------------- the pre-registered screen
#
# Two exclusions decided before any holdout data existed (plan section 12.2
# rules 4 and 6). Both look at the build, never at a verdict: rule 4 reads
# whether a file parses, rule 6 counts findings without looking at what they
# are or how the run concluded.

# Mirrors internal/codeaudit/scanner.go:23. The Go engine truncates its static
# findings here, and the comparison is `>=`, so a sample with exactly this many
# findings is already marked truncated - which makes ProvesCleanScan false and
# breaks the parity proof for a reason unrelated to rule drift. The Python arm
# has no such cap.
MAX_STATIC_FINDINGS = 200


def over_static_cap(
    samples: Sequence[Sample],
    finding_count: Callable[[Sample], int],
    cap: int = MAX_STATIC_FINDINGS,
) -> tuple[list[Sample], list[dict[str, Any]]]:
    """Split samples by the static-findings cap, counting what it removes.

    'At or above' rather than 'above': the Go engine's check is `>=`, so the
    two are the same case and a sample sitting exactly on the cap is already
    truncated. Excluded samples are returned with their counts rather than
    dropped, because a corpus that quietly loses its densest samples reads as
    cleaner than it is - and the count is the evidence that the rule was
    applied rather than the samples never being built.
    """
    kept: list[Sample] = []
    excluded: list[dict[str, Any]] = []
    for sample in samples:
        count = finding_count(sample)
        if count >= cap:
            excluded.append({"sample_id": sample.sample_id, "rule": "static-cap",
                             "findings": count, "cap": cap})
            continue
        kept.append(sample)
    return kept, excluded


def unparseable_samples(samples: Sequence[Sample]) -> list[dict[str, Any]]:
    """Rule 4's exclusion, as a check over built samples.

    The evaluator discards any sample whose tree has parse errors, and the Go
    engine fails its scan on the same condition, so an unparseable sample would
    consume a run and then report nothing. The arms that read whole upstream
    files need this; the annotation arm applies it when it cuts fragments.
    """
    return [{"sample_id": sample.sample_id, "rule": "unparseable", "detail": "sample does not parse"}
            for sample in samples if not parses(sample.text)]


if __name__ == "__main__":
    raise SystemExit(0)


# ------------------------------------------------- upstream annotation arm
#
# The one arm whose ground truth is per-line and comes from the same upstream
# file the sample is cut out of. The selection is a walk in path order over the
# checkout at a recorded revision: nothing here looks at what an engine reports.

SEMGREP_RULES_SOURCE = "semgrep-rules"
SEMGREP_RULES_PROJECT = "semgrep-rules"

# Upstream files are modified by construction - a fragment is not the file it
# came from - and the source licence requires modified copies to be marked.
SEMGREP_RULES_MODIFICATION = (
    "mechanical window extraction: the sample is the enclosing def/class of the "
    "annotated statement, dedented, with the annotation kept; nothing else changed"
)


def parses(text: str) -> bool:
    """Whether a fragment is a Python file at all."""
    try:
        ast.parse(text)
        return True
    except SyntaxError:
        return False


def tree_digest(root: Path) -> tuple[str, int]:
    """A content fingerprint of a checkout, and the number of files in it.

    A tarball checkout has no `.git`, so a revision string is a claim nothing
    local can check: the directory in hand says nothing about which commit it
    came from. This is the anchor that can be checked - it is computed from the
    bytes on disk, so a reader who has the same checkout can reproduce it, and
    a checkout that drifted will not match even if the revision string is
    unchanged.
    """
    root = Path(root)
    digest = hashlib.sha256()
    files = sorted(source_files(root))
    for path in files:
        relpath = path.relative_to(root).as_posix()
        digest.update(relpath.encode("utf-8"))
        digest.update(b"\0")
        digest.update(sha256_bytes(path.read_bytes()).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest(), len(files)


# Every drop this arm can make. The full set is stated up front and every key
# is reported even at zero: a report that reads a missing key as "no drops"
# cannot tell a clean build from one that never counted.
SEMGREP_RULES_DROP_KEYS = (
    "annotations",
    "dropped_outside",
    "dropped_mixed",
    "unmapped",
    "fragment_unparseable",
    "unparseable_files",
)


def samples_from_windows(
    root: Path,
    *,
    revision: str,
    prefix: str = "sr",
) -> tuple[list[Sample], dict[str, Any]]:
    """Turn every annotated window under a checkout into samples.

    A window whose upstream rule names none of our families is excluded and
    counted, not labelled with a guess: the annotation was written for an
    upstream rule, and a wrong family would file the sample under a rule that
    never sees it. A fragment that does not parse is excluded too - the
    evaluator drops a sample whose tree has parse errors, so admitting one here
    would turn a build-time fact into a round that cannot be completed.

    Nothing in the selection reads an engine's output. The order is path order,
    so the same revision yields the same samples.
    """
    root = Path(root)
    samples: list[Sample] = []
    drops: dict[str, Any] = {key: 0 for key in SEMGREP_RULES_DROP_KEYS}
    index = 0

    for path in source_files(root):
        text = path.read_text(encoding="utf-8", errors="replace")
        extraction = extract_file(text)
        drops["annotations"] += extraction.annotations
        drops["dropped_outside"] += extraction.dropped_outside
        drops["dropped_mixed"] += extraction.dropped_mixed
        if extraction.unparseable:
            drops["unparseable_files"] += 1
        if not extraction.windows:
            continue

        relpath = path.relative_to(root).as_posix()
        lines = text.splitlines()
        file_digest = sha256_text(text)
        for window in extraction.windows:
            if window.family is None:
                drops["unmapped"] += 1
                continue
            fragment = window_fragment(lines, window)
            if not parses(fragment):
                drops["fragment_unparseable"] += 1
                continue
            index += 1
            samples.append(
                Sample(
                    sample_id=f"{prefix}-{index:04d}",
                    base_project=SEMGREP_RULES_PROJECT,
                    family=window.family,
                    label=window.label,
                    text=fragment,
                    provenance={
                        "source": SEMGREP_RULES_SOURCE,
                        "revision": revision,
                        "path": relpath,
                        "file_sha256": file_digest,
                        "window": [window.start, window.end],
                        "annotation": f"# {window.kind}: {window.annotated_rule}",
                        "annotation_line": window.annotated_line,
                        "upstream_rule": window.annotated_rule,
                        "modification": SEMGREP_RULES_MODIFICATION,
                    },
                    primary_attack_finding=(
                        {"file": SAMPLE_FILENAME, "rule_id": window.family,
                         "line": window.labelled_line()}
                        if window.label == "malicious" else None
                    ),
                )
            )

    return samples, dict(drops)


if __name__ == "__main__":
    raise SystemExit(0)
