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
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping, Optional, Sequence

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
    *,
    verification: Optional[dict[str, Any]] = None,
    vendor_reference: Optional[dict[str, Any]] = None,
    arm_counts: Optional[Mapping[str, Any]] = None,
    selection: Optional[dict[str, Any]] = None,
    family_map: Optional[dict[str, Any]] = None,
    long_line: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """What a reader needs to check the corpus without rebuilding it.

    The per-sample records are the upstream facts only - path, revision, hash,
    annotation. They are what makes a label checkable: the label came from an
    upstream annotation, and this is the annotation.

    The sections the build adds are written even when the caller passes nothing,
    as empty objects: a key that is absent cannot be told apart from a section
    whose measurement was never taken, and every one of these is a measurement -
    the checkout's verification, the reference set the malicious arm was
    screened against, the CodeQL selection's taxonomy, the counts per arm, the
    long-line exclusion, and the annotation-to-family table that was used.
    """
    return {
        "built_at": utc_now(),
        "sources": list(sources),
        "counts": corpus_counts(samples),
        "arm_counts": dict(arm_counts or {}),
        "drops": dict(drops or {}),
        "vendor_reference": dict(vendor_reference or {}),
        "codeql_selection": dict(selection or {}),
        "semgrep_rules_checkout": dict(verification or {}),
        "family_map": dict(family_map or {}),
        "long_line_exclusion": dict(long_line or {}),
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

# Rule 9 (plan section 12.2). The Tier 2 prompt is assembled per finding out of
# a context window bounded by *lines* - fifteen either side - and not by bytes,
# so one enormous line makes the prompt arbitrarily large: the largest sample in
# this corpus carries a single 22,608,571-byte line, which puts 22,608,716 bytes
# into the prompt for one finding, of which only 43 are the matched snippet. The
# bound below excludes it. It is outcome-blind like the parse rule and the
# static cap: it reads the sample's bytes and never a scan result or a verdict.
#
# The value is not knife-edge. On the built corpus it selects exactly five
# samples, with max lines of 22,608,571 / 624,660 / 613,852 / 198,052 / 188,904
# bytes, and the next largest max line in the whole corpus is 42,869 - a 4.6x
# gap. Apart from those five, the largest prompt payload any sample can assemble
# is 1,127 bytes, so any bound of 4 KB or more leaves the other 311 samples
# byte-identical.
MAX_SAMPLE_LINE_BYTES = 100_000

# Rule 9 is applied to the merged corpus, not inside any arm, so its counts are
# added to every arm's table by the build rather than by the arm's own loader.
# The longest line each arm brought is reported alongside the count, at zero for
# arms that lost nothing: how close an arm came to the bound is a measurement,
# and "0 dropped" alone does not distinguish an arm that was never near it from
# one that was one byte away.
LONG_LINE_DROP_KEYS = (
    "long_line",
    "long_line_max_bytes",
)


def sample_max_line(sample: Sample) -> int:
    """The longest line of a sample, in the bytes it contributes to a prompt.

    Bytes rather than characters because the bound is about what is sent to the
    model, and a line of multi-byte characters is larger than its length.
    """
    return max((len(line.encode("utf-8")) for line in sample.text.split("\n")), default=0)


def drop_long_lines(
    samples: Sequence[Sample],
    limit: int = MAX_SAMPLE_LINE_BYTES,
) -> tuple[list[Sample], list[dict[str, Any]]]:
    """Split off samples carrying a line longer than the prompt budget allows.

    Excluded rather than truncated, and returned rather than dropped: cutting
    the line would change what the model is shown, and that is a prompt
    construction decision affecting both arms and production, not a corpus
    decision. A silently shortened sample would also make the prompt the model
    sees unlike the prompt the tier builds in production, which is the property
    the holdout exists to predict.
    """
    kept: list[Sample] = []
    dropped: list[dict[str, Any]] = []
    for sample in samples:
        longest = sample_max_line(sample)
        if longest > limit:
            dropped.append({
                "sample_id": sample.sample_id,
                "source": str(sample.provenance.get("source", "unknown")),
                "max_line_bytes": longest,
                "sample_bytes": len(sample.text.encode("utf-8")),
                "limit": limit,
            })
            continue
        kept.append(sample)
    return kept, dropped


def long_line_exclusion(dropped: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """The rule-9 exclusion as provenance, so the corpus can be checked without it.

    The records carry the measured length of the offending line and the size of
    the file it sat in, because both are checkable against the upstream source:
    a reader who doubts the exclusion can fetch `dd-0060` and measure its longest
    line without rerunning the build. The criterion itself is written out rather
    than named, since a rule number means nothing to a reader in two years.
    """
    return {
        "limit_bytes": MAX_SAMPLE_LINE_BYTES,
        "criterion": (
            "excluded when any single line of the sample exceeds limit_bytes, "
            "measured in UTF-8 bytes, before any scan"
        ),
        "count": len(dropped),
        "samples": [dict(row) for row in dropped],
    }


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


# ------------------------------------------------------ manifest-backed arms
#
# Three of the four arms arrive as manifests written by the retrieval step
# rather than as a directory to be walked. Each manifest records, per file, the
# upstream coordinates a reader needs in order to check the label: the package,
# the version, the archive, the member's path inside it, and the member's own
# sha256. Everything below reads those records. Nothing runs a sample: the
# malicious arm is real malware, and its files are opened for their bytes only -
# hashed, decoded as text, and written into the corpus. They are never imported,
# executed, or byte-compiled, and no sample text is copied into a report, a
# docstring, or a commit message; the malware is referred to by path and sha256.
#
# Three facts about the data shape the code below. All three were measured on
# the manifests themselves, and each one moves a count that a report has to
# state rather than a decision that could be made either way.
#
# * A manifest entry's `sha256` is the file's own hash, so it can be checked
#   against the bytes on disk before anything is read out of them. Every arm
#   checks it and a mismatch raises. The manifest is the claim and the bytes are
#   the evidence, so a file that does not hash to what the manifest says is a
#   file the manifest does not describe - and the sample built from it would
#   carry a label nobody could check.
# * Content repeats across the arms. The malicious manifest's 220 entries cover
#   181 distinct files, mostly one package uploaded under several versions; the
#   sdist arm repeats one file and the CodeQL arm three (all empty). A
#   byte-identical file is one sample, not several: scoring the same bytes twice
#   weights the corpus by how often a package was re-uploaded.
# * Some archive members are directories literally named `*.py`, and some files
#   are empty. Both are excluded and counted against their own reason, because
#   the evaluator refuses a sample that does not parse or has nothing in it, and
#   a build that admitted one would stop a run where it should have reported.

MALICIOUS_MANIFEST_FILENAME = "malicious-manifest.json"
BENIGN_MANIFEST_FILENAME = "benign-manifest.json"
VENDOR_REFERENCE_FILENAME = "vendor-references.json"
DD_DIRNAME = "dd"
SDIST_DIRNAME = "sdist"
CODEQL_DIRNAME = "codeql"

# The `arm` values the benign manifest uses for its two populations. The
# malicious manifest carries a single population and no such field.
BENIGN_ARM = "benign"
NEAR_MISS_ARM = "near-miss"

# What provenance records as where a sample came from, and what `corpus_counts`
# then groups by.
MALICIOUS_SOURCE = "datadog-malicious"
SDIST_SOURCE = "pypi-sdist"
CODEQL_SOURCE = "codeql"

# The directory each arm's samples are written under. A base project that named
# the upstream package instead would scatter 190 samples over 190 projects and
# leave the parity proof's two-level traversal looking for a layout that is
# three levels deep.
MALICIOUS_BASE_PROJECT = "ddpypi"
SDIST_BASE_PROJECT = "pypi"
CODEQL_BASE_PROJECT = "codeql"

# Sample id prefixes. Distinct per arm so a corpus-list entry identifies which
# arm it came from without a lookup.
MALICIOUS_ID_PREFIX = "dd"
SDIST_ID_PREFIX = "pypi"
CODEQL_ID_PREFIX = "cq"

# Why a sample is labelled what it is. A label without its basis is a claim a
# reader cannot check, and these three arms are labelled by three different
# kinds of upstream fact.
MALICIOUS_LABEL_BASIS = "DataDog malicious_intent package, non-vendored payload file"
SDIST_LABEL_BASIS = "genuine PyPI sdist file"
CODEQL_LABEL_BASIS = "upstream CodeQL explicit negative marker"

# The keys every reference entry has to carry. `file_sha256` is the list of
# hashes the distribution is known to ship; `sdist_sha256` is the distribution's
# own archive, carried so the reference can name its source.
VENDOR_REFERENCE_KEYS = ("dist", "version", "url", "sdist_sha256", "file_sha256", "matched_entries")

HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# The empty file's digest. It is evidence of nothing: it belongs to every empty
# file in every project, so a reference that lists it matches all of them at
# once. The malicious arm carries 19 empty files across 13 packages, and every
# PyPI project that ships an empty `__init__.py` hashes to this value - measured
# on the first real reference artifact, where a single row was read as 19
# matches for a library the arm does not vendor at all. The digest is removed
# from every reference's set before the screen reads it, and the removal is
# counted and reported rather than done quietly.
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# What provenance says a reference set was built from, when the reference carries
# no note of its own (plan section 12.2 rule 3, the revised malicious arm): the
# candidate names are resolved on PyPI and only a candidate that matches an entry
# already in the arm is kept, so a generic word that is also a real project
# cannot remove anything by accident.
VENDOR_REFERENCE_NOTE = (
    "candidate distribution names resolved on PyPI, every sdist's .py hashes collected, "
    "and only a candidate matching an entry already in the arm kept as a reference"
)


def read_vendor_reference(path: Path) -> tuple[dict[str, str], dict[str, Any]]:
    """The vendored-file map, and the record of how the file was read.

    `load_vendor_reference` is this function's map; the record is what
    provenance carries - every reference with the coordinates that make it
    checkable, and what reading the file removed from it.

    The malicious arm is trojanised packages, and a trojanised package is
    usually a genuine one plus a payload: measured on this manifest, 118 of the
    220 files (54%) are byte-identical to the real PyPI release of the same
    version. Those files are not malicious code, and keeping them in the
    malicious arm would charge an engine for failing to flag a library it is
    right about. This mapping is what identifies them - it is built from the
    published archives of the real distributions, so membership is an upstream
    fact rather than a judgement made here.

    Every defect raises. A reference that is missing, malformed, or ambiguous
    would otherwise read as "nothing is vendored", which silently restores
    exactly the files it exists to remove. An ambiguous hash - one two
    distributions both claim - raises for the same reason: the build cannot pick
    one of them without inventing a fact, and a hash in two references counts
    one file against two distributions. A hash repeated inside one reference
    raises for the same reason one step down: it would count one file as two
    matches. The empty file's digest is removed rather than honoured (see
    EMPTY_SHA256), and a reference left with no hashes at all raises, because a
    row that can match nothing reads as a distribution that was consulted and
    cleared when it was never evidence of anything.
    """
    path = Path(path)
    if not path.is_file():
        raise ValueError(
            f"vendor reference {path} does not exist; without it nothing is recognised as "
            "vendored and the malicious arm silently keeps every released library copy"
        )
    raw = path.read_bytes()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"vendor reference {path} is not valid JSON: {exc}") from exc

    if not isinstance(payload, dict) or "references" not in payload:
        raise ValueError(f"vendor reference {path} must be a JSON object with a 'references' key")
    references = payload["references"]
    if not isinstance(references, list):
        raise ValueError(
            f"vendor reference {path} 'references' must be a list, not {type(references).__name__}"
        )

    mapping: dict[str, str] = {}
    records: list[dict[str, Any]] = []
    screened: list[dict[str, Any]] = []
    screened_total = 0
    for index, reference in enumerate(references):
        where = f"{path} reference #{index + 1}"
        if not isinstance(reference, dict):
            raise ValueError(f"{where} must be an object")
        for key in VENDOR_REFERENCE_KEYS:
            if key not in reference:
                raise ValueError(f"{where} has no {key!r}")
        origin = f"{reference['dist']}=={reference['version']}"
        digests = reference["file_sha256"]
        if not isinstance(digests, list):
            raise ValueError(f"{where} ({origin}) 'file_sha256' must be a list")
        for digest in [reference["sdist_sha256"], *digests]:
            if not isinstance(digest, str) or not HEX_SHA256_RE.match(digest):
                raise ValueError(
                    f"{where} ({origin}) carries a hash that is not 64 lowercase hex "
                    f"characters: {digest!r}"
                )
        if len(set(digests)) != len(digests):
            repeated = sorted({digest for digest in digests if digests.count(digest) > 1})
            raise ValueError(
                f"{where} ({origin}) lists the same hash more than once: {repeated}; "
                "a repeated hash would count one file as two matches"
            )
        kept = [digest for digest in digests if digest != EMPTY_SHA256]
        removed = len(digests) - len(kept)
        if removed:
            screened_total += removed
            screened.append({"dist": reference["dist"], "version": reference["version"],
                             "removed": removed})
        if not kept:
            raise ValueError(
                f"{where} ({origin}) has no file hashes left once the empty file's digest "
                f"({EMPTY_SHA256}) is removed; a reference that can match nothing is a row "
                "that reads as evidence and carries none"
            )
        for digest in kept:
            if digest in mapping:
                raise ValueError(
                    f"{where} ({origin}) claims hash {digest}, which {mapping[digest]} already "
                    "claims; an ambiguous vendored reference is a build error, not a silent pick"
                )
            mapping[digest] = origin
        records.append({
            "dist": reference["dist"],
            "version": reference["version"],
            "url": reference["url"],
            "sdist_sha256": reference["sdist_sha256"],
            "matched_entries": reference["matched_entries"],
            "note": reference.get("note") or VENDOR_REFERENCE_NOTE,
            "file_sha256": kept,
        })

    record: dict[str, Any] = {
        "path": str(path),
        "sha256": sha256_bytes(raw),
        "references": records,
        "reference_count": len(records),
        "empty_digest_screen": {
            "digest": EMPTY_SHA256,
            "removed": screened_total,
            "references": screened,
        },
    }
    return mapping, record


def load_vendor_reference(path: Path) -> dict[str, str]:
    """Map every vendored file's sha256 to the distribution that ships it.

    The map is `read_vendor_reference`'s first value; that function is where the
    validation and the empty-file screen live, and this is the shape the arm's
    screen reads. Every defect raises, for the reasons stated there.
    """
    return read_vendor_reference(path)[0]


def vendor_reference_payload(
    record: Mapping[str, Any],
    entries: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """The reference set as provenance carries it, with every match recomputed.

    The reference file states its own `matched_entries`, and that number was
    measured wrong once: a row declared 19 matches for a library the arm does
    not vendor, because the empty file's digest sat in its set and the arm
    carries 19 empty files. The count a report is read against is therefore the
    one measured here against the arm's manifest, and where the file's own
    number disagrees both are carried under `declared_vs_measured` - a reader
    has to see the discrepancy rather than have either number resolved for them
    silently.

    The unit is the manifest entry, not the sample: this counts before the arm's
    own exclusions, so the number is comparable with the declared one. Counting
    over the raw manifest is safe only because the empty file's digest is no
    longer in any reference's set, which is what stops the empty entries from
    matching.

    The hash lists themselves are not carried - a few hundred distributions'
    worth of hashes would bury the numbers a reader checks - only how many each
    reference was left with.
    """
    manifest_digests = [entry.get("sha256") for entry in entries]
    references: list[dict[str, Any]] = []
    for reference in record.get("references", []):
        hashes = set(reference.get("file_sha256", ()))
        measured = sum(1 for digest in manifest_digests if digest in hashes)
        declared = reference.get("matched_entries")
        row: dict[str, Any] = {
            "dist": reference.get("dist"),
            "version": reference.get("version"),
            "url": reference.get("url"),
            "sdist_sha256": reference.get("sdist_sha256"),
            "matched_entries": measured,
            "declared_matched_entries": declared,
            "file_sha256_count": len(hashes),
            "note": reference.get("note"),
        }
        if declared != measured:
            row["declared_vs_measured"] = {
                "declared": declared,
                "measured": measured,
                "note": "the reference file's own count disagrees with the count this build "
                        "measured against the arm manifest; the measured one is authoritative",
            }
        references.append(row)
    return {
        "path": record.get("path"),
        "sha256": record.get("sha256"),
        "reference_count": len(references),
        "references": references,
        "empty_digest_screen": record.get("empty_digest_screen"),
        "note": "the empty file's digest is removed from every reference before the screen "
                "runs: it matches every project that ships an empty file, so it is not "
                "evidence that anything is vendored",
    }


def drop_vendored(
    entries: Sequence[dict[str, Any]],
    reference: dict[str, str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split entries into non-vendored and vendored, in input order.

    The kept list is what the malicious arm may label malicious. The dropped
    list is returned as entries rather than discarded, so the build can report
    how many files a package's real release accounts for. That number is the
    evidence that rule 3's premise was measured and revised rather than
    assumed - the premise it replaced treated a package's label as a fact about
    every file in it, which the measurement falsified.
    """
    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    for entry in entries:
        if entry.get("sha256") in reference:
            dropped.append(entry)
        else:
            kept.append(entry)
    return kept, dropped


def dedup_key(entry: dict[str, Any]) -> tuple[str, str, str, str]:
    """The sort key content dedup runs on.

    `relpath` is the malicious manifest's name for the member path and `path`
    is the other two manifests' name for the same thing, so one key reads both.
    The version and the hash are tie-breakers rather than decoration: the arms
    really do carry one package under several versions, where the same member
    path holds different bytes, and without them two such entries would keep
    whichever the manifest happened to list first.
    """
    member = entry.get("relpath", entry.get("path"))
    return (
        str(entry.get("package", "")),
        str(member if member is not None else ""),
        str(entry.get("version", "")),
        str(entry.get("sha256", "")),
    )


def dedup_by_content(
    entries: Sequence[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Keep the first entry per file hash, in a total, reproducible order.

    Duplicates are real and counted: 39 files in the malicious manifest are
    byte-identical repeats of another entry, mostly one package uploaded under
    several versions, plus one in the sdist arm and three in the CodeQL arm.
    Byte-identical files are one sample - keeping both would score the same code
    twice and weight the corpus by upload history rather than by content.

    The order is total, so the survivor of a duplicate group is a property of
    the entries and not of the order the manifest listed them in. An entry with
    no hash has nothing to dedup on and is kept, which leaves the absence to be
    refused where every entry's hash is actually read.
    """
    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in sorted(entries, key=dedup_key):
        digest = entry.get("sha256")
        if not isinstance(digest, str) or not digest:
            kept.append(entry)
            continue
        if digest in seen:
            dropped.append(entry)
            continue
        seen.add(digest)
        kept.append(entry)
    return kept, dropped


def drop_empty(
    entries: Sequence[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split off the entries whose file is zero bytes long, in input order.

    A file with nothing in it holds no code, so it can be neither an instance of
    what an arm labels nor a fair negative for one, and the evaluator reads a
    sample as text that has to score. The size is the manifest's own `bytes`
    field rather than the disk's: this runs before anything is read, and the
    retrieval already recorded the size of every file it describes. An entry
    that does not record one raises, because a size silently read as zero would
    drop a file that may well hold the payload.

    Running it in all three manifest arms, and before dedup, is what makes the
    exclusion neutral between them: an arm that dropped zero-byte files later
    would hold samples the others had already removed, and every empty file
    shares one hash, so an arm that deduped first would report the rest as
    duplicates of a file that is not a sample.
    """
    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    for entry in entries:
        size = entry.get("bytes")
        if not isinstance(size, int) or isinstance(size, bool):
            member = entry.get("relpath", entry.get("path"))
            raise ValueError(f"entry {member!r} records no byte size: {size!r}")
        (dropped if size == 0 else kept).append(entry)
    return kept, dropped


# The CodeQL near-miss marker. Upstream writes it as a trailing comment on the
# line it is about, and reads:
#
#     os.system(cmd)  # $ SPURIOUS: Alert
#     open(z)         # $ result=OK
#
# so a marker is a `#` comment carrying a `$` with SPURIOUS or result=OK after
# it. A bare `$` is common in this corpus - `re.match(r"^[a-z]+$", s)` is an
# expression, not a marker - and the marker has to follow the `$` for that
# reason. The pattern is anchored on the comment's `#`, not on the start of the
# line: measured on the 102 downloaded files, all 30 marker lines carry the
# marker as a trailing comment, so a pattern anchored at a comment start finds
# none of them and would silently select an empty arm.
CODEQL_MARKER_RE = re.compile(r"#.*\$.*(SPURIOUS|result\s*=\s*OK)")

# An annotation line is a line carrying a `$` after its `#`, which is where
# upstream writes its expectations. Every marker line is one of these, and so is
# a line whose `$` annotation says something else - `# $ Alert` above all.
CODEQL_ANNOTATION_RE = re.compile(r"#.*\$")

# The label shapes that are an alert expectation and nothing else. A label
# carrying a qualifier - `Alert result=BAD`, `Alert SPURIOUS: ...` - is not one
# of these: the qualifier is the whole of what it adds.
CODEQL_ALERT_POSITIVE_RE = re.compile(r"^Alert(\[[^\]]*\])?$")

# The upstream marker strings that make a label an explicit negative. Read off
# the manifest's own labels, and used to cross-check the marker the file's bytes
# carry rather than to stand in for it.
CODEQL_NEGATIVE_LABEL_MARKERS = ("SPURIOUS", "result=OK")

# The same markers as a pattern, for reading them back out of a label.
CODEQL_NEGATIVE_LABEL_RE = re.compile(r"SPURIOUS|result\s*=\s*OK")

# What a file's annotations can make it. Only `negative_only` is a near-miss,
# and the other three are reported by name so that the scope a ruling narrowed
# is measured rather than asserted.
CODEQL_CLASSES = ("negative_only", "positive_only", "no_marker", "mixed")


def marker_name(raw: str) -> str:
    """A marker's canonical name, so `result = OK` and `result=OK` tally once."""
    return re.sub(r"\s+", "", raw)


def codeql_markers(text: str) -> dict[str, int]:
    """Every explicit negative marker in a file, as marker name -> line count."""
    found: dict[str, int] = {}
    for line in text.splitlines():
        match = CODEQL_MARKER_RE.search(line)
        if match:
            name = marker_name(match.group(1))
            found[name] = found.get(name, 0) + 1
    return found


def codeql_per_line_labels(label_lines: Any) -> dict[int, list[str]]:
    """The manifest's label -> lines map, inverted to line -> labels.

    Upstream records one entry per label, so a line stating two expectations
    appears under two labels and can be read back here. The shape is checked
    because everything below reads it as a fact about a line: a malformed map
    would read as "no line carries two", which is the answer that excludes
    nothing.
    """
    if not isinstance(label_lines, dict):
        raise ValueError(f"label_lines must map a label to its lines, not {label_lines!r}")
    per_line: dict[int, list[str]] = {}
    for label, lines in label_lines.items():
        if not isinstance(lines, list):
            raise ValueError(f"label_lines[{label!r}] must be a list of line numbers")
        for line in lines:
            if not isinstance(line, int) or isinstance(line, bool):
                raise ValueError(f"label_lines[{label!r}] carries a line that is not an int: {line!r}")
            per_line.setdefault(line, []).append(str(label))
    return per_line


def _both_kinds_lines(per_line: Mapping[int, Sequence[str]]) -> int:
    """How many of these lines state a negative and another expectation at once."""
    both = 0
    for labels in per_line.values():
        negative = [label for label in labels if CODEQL_NEGATIVE_LABEL_RE.search(label)]
        if negative and len(negative) < len(labels):
            both += 1
    return both


def codeql_both_kinds_lines(label_lines: Any) -> int:
    """Count the lines whose annotation marks a negative and something else.

    A line such as `# $ Alert, SPURIOUS: Source` states both at once. The
    line-level rule reads it as a negative line, so a file whose only other
    annotations were negative would be classified `negative_only` on the
    strength of a line that also asks for an alert. Excluding such a file is the
    safe response, and it is what the caller does.
    """
    return _both_kinds_lines(codeql_per_line_labels(label_lines))


def codeql_file_class(text: str, label_lines: Any) -> dict[str, Any]:
    """Classify one CodeQL test file by the annotations its own bytes carry.

    A negative line is an annotation line naming a negative marker; every other
    annotation line is positive. The file is then one of four things:

    - `no_marker`: no line carries a `$` annotation. Upstream wrote down
      nothing, which is not a statement that a query must not fire.
    - `positive_only`: annotations exist and none is negative, so upstream says
      a query SHOULD fire somewhere in this file.
    - `negative_only`: at least one annotation is negative and every annotation
      line is, which is the near-miss scope.
    - `mixed`: both kinds appear, so the file also asserts that something must
      be reported and cannot stand as a negative for the whole file.

    Measured on the 102 downloaded files, this classifies 5 negative-only, 67
    positive-only, 20 with no marker at all and 10 mixed, and the 10 mixed files
    carry 78 positive annotation lines between them - the false positives the
    narrower scope exists to keep out of the negative arm.
    """
    negative = 0
    annotations = 0
    for line in text.splitlines():
        if not CODEQL_ANNOTATION_RE.search(line):
            continue
        annotations += 1
        if CODEQL_MARKER_RE.search(line):
            negative += 1
    if not annotations:
        name = "no_marker"
    elif not negative:
        name = "positive_only"
    elif negative == annotations:
        name = "negative_only"
    else:
        name = "mixed"
    return {
        "class": name,
        "negative_lines": negative,
        "annotation_lines": annotations,
        "positive_lines": annotations - negative,
        "both_kinds_lines": _both_kinds_lines(codeql_per_line_labels(label_lines)),
    }


def codeql_near_miss_files(
    entries: Sequence[dict[str, Any]],
    codeql_root: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Select the negative-only files, and report what the selection saw.

    A near-miss is not "a file with no alert". It is a file whose upstream
    author wrote down that a location must not be reported, and a negative
    marker alone does not say that about a whole file: a file that also asserts
    a query SHOULD fire has a positive expectation in it, and counting it as a
    negative would charge an engine for an alert upstream asked for. So the arm
    keeps the files whose every annotation is negative - measured on this
    manifest that is 5 of 102 - and the report carries the other three classes
    plus each `mixed` file's two counts, so the scope is a measurement rather
    than a claim.

    Zero-byte files are dropped before anything is read, as in every manifest
    arm, and by the same reasoning: they hold no code, and a file that cannot be
    scored cannot be a fair negative either.

    The marker is read from the file's own bytes, and the sha256 is checked
    first, so the bytes the marker came from are the bytes the manifest
    describes. The manifest's per-entry `labels` records the same fact, and is
    reported alongside as a second reading: measured on this manifest the two
    agree on all 102 entries, and the report states the counts rather than
    asking a reader to take the agreement on trust.
    """
    codeql_root = Path(codeql_root)
    total = len(entries)
    entries, empty_entries = drop_empty(entries)

    selected: list[dict[str, Any]] = []
    classes: dict[str, int] = {name: 0 for name in CODEQL_CLASSES}
    mixed_files: list[dict[str, Any]] = []
    both_kinds_files: list[str] = []
    tallies: dict[str, int] = {}
    files_by_marker: dict[str, int] = {}
    both_kinds = 0
    excluded_both_kinds = 0
    label_marked = 0
    file_marked = 0
    alert_positive_only = 0
    disagreements = 0

    for entry in entries:
        relpath = str(entry.get("path", ""))
        payload = _verified_bytes(codeql_root / relpath, entry.get("sha256"))
        # Markers are ASCII, so a decode that replaces what it cannot read still
        # cannot invent one, and a file that is not UTF-8 stays selectable here.
        text = payload.decode("utf-8", errors="replace")
        markers = codeql_markers(text)
        verdict = codeql_file_class(text, entry.get("label_lines"))
        classes[verdict["class"]] += 1
        if verdict["class"] == "mixed":
            mixed_files.append({
                "path": relpath,
                "negative_lines": verdict["negative_lines"],
                "positive_lines": verdict["positive_lines"],
            })
        if verdict["both_kinds_lines"]:
            both_kinds += verdict["both_kinds_lines"]
            both_kinds_files.append(relpath)

        labels = entry.get("labels")
        labels = labels if isinstance(labels, list) else []
        named = [str(label) for label in labels]
        label_says_marker = any(
            marker in label for label in named for marker in CODEQL_NEGATIVE_LABEL_MARKERS
        )

        if named and all(CODEQL_ALERT_POSITIVE_RE.match(label) for label in named):
            alert_positive_only += 1
        if label_says_marker:
            label_marked += 1
        if bool(markers) != label_says_marker:
            disagreements += 1
        if markers:
            file_marked += 1
            for name, lines in markers.items():
                tallies[name] = tallies.get(name, 0) + lines
                files_by_marker[name] = files_by_marker.get(name, 0) + 1

        if verdict["class"] != "negative_only":
            continue
        if verdict["both_kinds_lines"]:
            # The line rule cannot tell a line that marks a negative from one
            # that marks a negative and an alert at once, so the file is left
            # out rather than read on the strength of an ambiguous line.
            excluded_both_kinds += 1
            continue
        selected.append(entry)

    return selected, {
        "total_entries": total,
        "empty": len(empty_entries),
        "classified": len(entries),
        "classification": {name: classes[name] for name in CODEQL_CLASSES},
        "mixed_files": mixed_files,
        "both_kinds_lines": both_kinds,
        "both_kinds_files": both_kinds_files,
        "excluded_both_kinds": excluded_both_kinds,
        "selected": len(selected),
        "selected_files": [str(entry.get("path", "")) for entry in selected],
        "marker_tallies": {name: tallies[name] for name in sorted(tallies)},
        "marker_files": {name: files_by_marker[name] for name in sorted(files_by_marker)},
        "alert_positive_only": alert_positive_only,
        "label_marked": label_marked,
        "file_marked": file_marked,
        "label_and_file_disagree": disagreements,
        "marker_pattern": CODEQL_MARKER_RE.pattern,
    }


def _verified(payload: bytes, expected_sha256: Any, where: str) -> bytes:
    """The bytes, once they hash to what the manifest says they hash to.

    A mismatch raises rather than excluding the file. Excluding would be a
    silent repair of a fact the corpus depends on: the sample would be gone, the
    arm would look complete, and the manifest's own record of how many files it
    describes would no longer match anything the build reported.
    """
    digest = sha256_bytes(payload)
    if not isinstance(expected_sha256, str) or digest != expected_sha256:
        raise ValueError(f"{where} has sha256 {digest}, the manifest says {expected_sha256!r}")
    return payload


def _verified_bytes(path: Path, expected_sha256: Any) -> bytes:
    """A file's bytes, verified against the hash its manifest entry records.

    A file the manifest lists and the disk does not have is a failure of the
    retrieval or of the path, not a file to be skipped: there is no marker to
    read and no sample to build, and both callers have to know which.
    """
    path = Path(path)
    if not path.is_file():
        raise ValueError(f"{path} is not a file; the manifest lists it")
    return _verified(path.read_bytes(), expected_sha256, str(path))


def _decode_utf8(payload: bytes) -> Optional[str]:
    """The file as text, or None when it is not valid UTF-8.

    None is a drop and not a failure: the bytes are intact, they are simply not
    Python source. The evaluator reads a sample as text, so a file it cannot
    decode is one it cannot score, and admitting one here would stop a run at
    the point where the sample is read.
    """
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _read_manifest_file(
    root: Path,
    relpath: str,
    expected_sha256: Any,
    drops: dict[str, Any],
) -> Optional[bytes]:
    """A manifest-listed file's bytes, or None after counting why it is absent.

    `is_file()` rather than `exists()`: six members of the malicious archives
    are directories literally named `*.py`, and a build that tried to read one
    would stop exactly where it is meant to produce a sample. The two failures
    are counted apart - a directory named `*.py` is a quirk of how the archive
    was packed, while an absent path means the retrieval and the manifest
    disagree about what exists - and both mean there is no file here to label.
    """
    if not relpath:
        drops["missing_file"] += 1
        return None
    where = root / relpath
    if not where.is_file():
        if where.is_dir():
            drops["directory_entry"] += 1
        else:
            drops["missing_file"] += 1
        return None
    return _verified_bytes(where, expected_sha256)


def _sdist_member(archive: Path, member: str) -> Optional[bytes]:
    """One member's bytes out of an sdist, or None when it holds no such member.

    The sdists are read as archives and their members loaded directly: nothing
    is unpacked to disk. `None` is reserved for a member the archive does not
    hold, which is a real disagreement with the manifest; a corrupt archive
    raises out of `tarfile` rather than being counted as a missing member,
    because the two are different failures and only one of them is about this
    manifest.
    """
    if not member:
        return None
    with tarfile.open(archive, "r:gz") as tar:
        try:
            handle = tar.extractfile(member)
        except KeyError:
            return None
        if handle is None:
            return None
        return handle.read()


# Every drop each manifest arm can make. As with the annotation arm, the full
# set is stated up front and every key is reported even at zero: a report that
# reads a missing key as "no drops" cannot tell a clean arm from one that never
# counted. `entries` and `loaded` sit in the same table so that every count a
# reader needs to check the arm against its manifest is in one place.
MALICIOUS_DROP_KEYS = (
    "entries",
    "vendored",
    "duplicate_content",
    "missing_file",
    "directory_entry",
    "empty",
    "undecodable",
    "loaded",
    "family_mapped",
    "family_unmapped",
)

SDIST_DROP_KEYS = (
    "entries",
    "duplicate_content",
    "missing_archive",
    "missing_member",
    "empty",
    "undecodable",
    "loaded",
)

CODEQL_DROP_KEYS = (
    "entries",
    "duplicate_content",
    "missing_file",
    "directory_entry",
    "empty",
    "undecodable",
    "loaded",
)


def samples_from_malicious(
    entries: Sequence[dict[str, Any]],
    sources_root: Path,
    reference: dict[str, str],
) -> tuple[list[Sample], dict[str, Any]]:
    """Turn DataDog's manifest into the malicious arm.

    Three exclusions run before a file is read, and their order is what makes
    each count mean one thing. Zero-byte files go first: a file with nothing in
    it cannot be a sample, and every empty file hashes alike, so a build that
    deduped first would report the rest of them as duplicates of a file that is
    not a sample. Vendored files go second, because vendoring is a property of
    the file and dedup must not be free to keep a genuine release copy in place
    of the payload copy that repeats it. Then content dedup, then the files are
    read.

    Reading a file means opening it for its bytes, hashing it, and decoding it
    as text. Nothing here imports, executes, or byte-compiles a sample: these
    packages persist by their install hooks, which is precisely why the build
    never runs one.

    The family is derived from the member path, which is upstream-ish evidence
    of what the file is. Nothing consults an engine. A holdout judged by the
    engine that would be measured against it is not held out at all, so a file
    whose path names no family keeps no attack finding and is counted as
    unmapped rather than guessed at.
    """
    sources_root = Path(sources_root)
    drops: dict[str, Any] = {key: 0 for key in MALICIOUS_DROP_KEYS}
    drops["entries"] = len(entries)
    entries, empty_entries = drop_empty(entries)
    drops["empty"] = len(empty_entries)
    entries, vendored = drop_vendored(entries, reference)
    entries, duplicates = dedup_by_content(entries)
    drops["vendored"] = len(vendored)
    drops["duplicate_content"] = len(duplicates)

    samples: list[Sample] = []
    index = 0
    for entry in entries:
        payload = _read_manifest_file(
            sources_root, str(entry.get("extracted_path", "")), entry.get("sha256"), drops
        )
        if payload is None:
            continue
        text = _decode_utf8(payload)
        if text is None:
            drops["undecodable"] += 1
            continue
        if not text.strip():
            # The same drop as a zero-byte file, reached from the other side: a
            # file whose bytes are there but hold nothing to score. It cannot
            # come out of `drop_empty`, which counts by the size the manifest
            # recorded, so it is counted here under the same reason.
            drops["empty"] += 1
            continue

        index += 1
        relpath = str(entry.get("relpath", ""))
        family = family_of(relpath)
        if family is None:
            drops["family_unmapped"] += 1
        else:
            drops["family_mapped"] += 1
        samples.append(
            Sample(
                sample_id=f"{MALICIOUS_ID_PREFIX}-{index:04d}",
                base_project=MALICIOUS_BASE_PROJECT,
                family=family if family is not None else FAMILY_DATADOG,
                label=LABEL_BY_KIND["ruleid"],
                text=text,
                provenance={
                    "source": MALICIOUS_SOURCE,
                    "package": entry.get("package"),
                    "version": entry.get("version"),
                    "archive_path": entry.get("archive_path"),
                    "archive_sha256": entry.get("archive_sha256"),
                    "in_archive_path": entry.get("in_archive_path"),
                    "relpath": relpath,
                    "file_sha256": entry.get("sha256"),
                    "label_basis": MALICIOUS_LABEL_BASIS,
                },
                primary_attack_finding=(
                    None if family is None
                    else {"file": SAMPLE_FILENAME, "rule_id": family, "line": 1}
                ),
            )
        )

    drops["loaded"] = len(samples)
    return samples, drops


def samples_from_benign(
    entries: Sequence[dict[str, Any]],
    sources_root: Path,
) -> tuple[list[Sample], dict[str, Any]]:
    """Turn the sdist manifest into the benign arm.

    The text is one member of the distribution's published archive, taken from
    the archive rather than from an unpacked copy, so the bytes a sample carries
    are the bytes the archive holds and the hash in the manifest can be checked
    against them. The archive's own hash is checked too: a sample's provenance
    claims which download it came from, and that claim is only checkable if the
    download is the one on disk.

    Zero-byte members are dropped first, as in every manifest arm, and the
    size the manifest records for a member is the one `drop_empty` reads.
    """
    sources_root = Path(sources_root)
    drops: dict[str, Any] = {key: 0 for key in SDIST_DROP_KEYS}
    drops["entries"] = len(entries)
    entries, empty_entries = drop_empty(entries)
    drops["empty"] = len(empty_entries)
    entries, duplicates = dedup_by_content(entries)
    root = sources_root / SDIST_DIRNAME
    drops["duplicate_content"] = len(duplicates)

    samples: list[Sample] = []
    verified_archives: set[str] = set()
    index = 0
    for entry in entries:
        member = str(entry.get("path", ""))
        name = str(entry.get("archive_filename", ""))
        archive = root / name
        if not archive.is_file():
            drops["missing_archive"] += 1
            continue
        if name not in verified_archives:
            # Once per archive. The member's own hash proves the file; only the
            # archive's proves the download that the sample's provenance names.
            _verified(
                archive.read_bytes(), entry.get("archive_sha256_observed"), f"archive {archive}"
            )
            verified_archives.add(name)
        member_payload = _sdist_member(archive, member)
        if member_payload is None:
            drops["missing_member"] += 1
            continue

        payload = _verified(member_payload, entry.get("sha256"), f"{archive}:{member}")
        text = _decode_utf8(payload)
        if text is None:
            drops["undecodable"] += 1
            continue
        if not text.strip():
            drops["empty"] += 1
            continue

        index += 1
        samples.append(
            Sample(
                sample_id=f"{SDIST_ID_PREFIX}-{index:04d}",
                base_project=SDIST_BASE_PROJECT,
                family=FAMILY_PYPI,
                label=LABEL_BY_KIND["ok"],
                text=text,
                provenance={
                    "source": SDIST_SOURCE,
                    "package": entry.get("package"),
                    "version": entry.get("version"),
                    "archive_filename": entry.get("archive_filename"),
                    "archive_sha256": entry.get("archive_sha256_observed"),
                    "in_archive_path": member,
                    "url": entry.get("url"),
                    "file_sha256": entry.get("sha256"),
                    "label_basis": SDIST_LABEL_BASIS,
                },
                primary_attack_finding=None,
            )
        )

    drops["loaded"] = len(samples)
    return samples, drops


def samples_from_near_miss(
    entries: Sequence[dict[str, Any]],
    sources_root: Path,
) -> tuple[list[Sample], dict[str, Any]]:
    """Turn the selected CodeQL files into the near-miss arm.

    The entries passed here are the ones `codeql_near_miss_files` selected, so
    every file carries upstream's own words that a query must not fire on it and
    carries no positive expectation. They are labelled benign because that is
    what the marker means: not that the file is harmless, but that its expected
    verdict is "no finding".

    Zero-byte files and then content duplicates are dropped first, as in every
    manifest arm. The selection has already removed the zero-byte files from the
    arm's population, so the count here is zero by construction and the arm's
    real one is the selection's; the guard is kept so this loader holds the same
    line on its own.
    """
    sources_root = Path(sources_root)
    drops: dict[str, Any] = {key: 0 for key in CODEQL_DROP_KEYS}
    drops["entries"] = len(entries)
    entries, empty_entries = drop_empty(entries)
    drops["empty"] = len(empty_entries)
    entries, duplicates = dedup_by_content(entries)
    root = sources_root / CODEQL_DIRNAME
    drops["duplicate_content"] = len(duplicates)

    samples: list[Sample] = []
    index = 0
    for entry in entries:
        payload = _read_manifest_file(root, str(entry.get("path", "")), entry.get("sha256"), drops)
        if payload is None:
            continue
        text = _decode_utf8(payload)
        if text is None:
            drops["undecodable"] += 1
            continue
        if not text.strip():
            drops["empty"] += 1
            continue

        index += 1
        samples.append(
            Sample(
                sample_id=f"{CODEQL_ID_PREFIX}-{index:04d}",
                base_project=CODEQL_BASE_PROJECT,
                family=FAMILY_CODEQL,
                label=LABEL_BY_KIND["ok"],
                text=text,
                provenance={
                    "source": CODEQL_SOURCE,
                    "package": entry.get("package"),
                    "version": entry.get("version"),
                    # This arm has no archive: the upstream coordinate is a git
                    # blob at a recorded commit, which is what `git_blob_sha1`
                    # is, and there is no archive hash to record.
                    "archive_sha256": None,
                    "in_archive_path": entry.get("path"),
                    "path": entry.get("path"),
                    "url": entry.get("url"),
                    "git_blob_sha1": entry.get("git_blob_sha1"),
                    "file_sha256": entry.get("sha256"),
                    "label_basis": CODEQL_LABEL_BASIS,
                },
                primary_attack_finding=None,
            )
        )

    drops["loaded"] = len(samples)
    return samples, drops


def load_manifest(path: Path) -> dict[str, Any]:
    """Read a retrieval manifest, refusing one that describes no files.

    The two manifests share no schema beyond the file list, so this checks only
    what every arm needs: a JSON object with a list of entries under `entries`.
    Anything more would be this module asserting a shape it does not own, and
    the arm loaders already refuse an entry that lacks a field they read.
    """
    path = Path(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"manifest {path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("entries"), list):
        raise ValueError(f"manifest {path} must be a JSON object with an 'entries' list")
    return payload


def manifest_entries(
    payload: dict[str, Any],
    arm: Optional[str] = None,
) -> list[dict[str, Any]]:
    """The entries of one arm of a manifest, in the order the manifest lists them.

    `arm` is None for the malicious manifest, which carries a single population
    and so records no `arm` field on its entries.

    A manifest carrying an arm this build does not know is refused rather than
    read past. Ignoring it would build a corpus smaller than the retrieval
    produced and say nothing about the difference, which is the one failure a
    reader cannot see in the finished corpus.
    """
    entries = list(payload["entries"])
    names = {str(entry.get("arm")) for entry in entries} - {"None"}
    unknown = sorted(names - {BENIGN_ARM, NEAR_MISS_ARM})
    if unknown:
        raise ValueError(f"manifest carries arm(s) this build does not know: {unknown}")
    if arm is None:
        if names:
            raise ValueError(f"manifest carries arms {sorted(names)}; the arm has to be named")
        return entries
    return [entry for entry in entries if entry.get("arm") == arm]


def build_holdout(
    sources_root: Path,
    *,
    reference_path: Optional[Path] = None,
) -> tuple[list[Sample], dict[str, Any]]:
    """Build the three manifest-backed arms, in a fixed order, with one report.

    The order is fixed - malicious, sdist, CodeQL - because the corpus list is
    an ordered run plan and a sample's id is derived from its position. A build
    that walked the sources in filesystem order would produce a different corpus
    on a different machine from the same bytes, which would make the corpus
    unreproducible in exactly the way the plan forbids.

    The vendor reference is read through `read_vendor_reference` from
    `reference_path`, which defaults to the retrieval's own location. It is read
    before any arm is built, and an absent one raises: an absent reference
    screens nothing, which silently restores every released library copy into
    the malicious arm - precisely the defect the screen exists to fix.

    The annotation arm is not built here. Its samples are cut out of a checkout
    by `samples_from_windows`, not read out of a manifest, and the two are
    assembled together by the caller so that each arm's report stays its own.
    """
    sources_root = Path(sources_root)
    reference_path = (
        Path(reference_path) if reference_path is not None
        else sources_root / DD_DIRNAME / VENDOR_REFERENCE_FILENAME
    )
    reference, reference_record = read_vendor_reference(reference_path)
    malicious_manifest = load_manifest(sources_root / MALICIOUS_MANIFEST_FILENAME)
    benign_manifest = load_manifest(sources_root / BENIGN_MANIFEST_FILENAME)

    malicious, malicious_report = samples_from_malicious(
        manifest_entries(malicious_manifest), sources_root, reference
    )
    benign, benign_report = samples_from_benign(
        manifest_entries(benign_manifest, BENIGN_ARM), sources_root
    )
    near_miss_all = manifest_entries(benign_manifest, NEAR_MISS_ARM)
    selected, selection = codeql_near_miss_files(near_miss_all, sources_root / CODEQL_DIRNAME)
    near_miss, near_miss_report = samples_from_near_miss(selected, sources_root)

    arms: dict[str, Any] = {
        MALICIOUS_SOURCE: malicious_report,
        SDIST_SOURCE: benign_report,
        # The selection report travels with the arm it produced: the count of
        # files the marker selected is what a reader checks the near-miss arm
        # against, and it is a property of the selection rather than of loading.
        # `entries` and `empty` are the arm's own population - everything the
        # retrieval downloaded and the zero-byte files among them - because that
        # is where those two exclusions happen for this arm; the loader below
        # never sees an empty file, so its own count of them is zero.
        CODEQL_SOURCE: {
            **near_miss_report,
            "entries": len(near_miss_all),
            "empty": selection["empty"],
            "selection": selection,
        },
    }
    samples = [*malicious, *benign, *near_miss]
    codeql_section = benign_manifest.get("codeql")
    codeql_section = codeql_section if isinstance(codeql_section, dict) else {}
    malicious_entries = manifest_entries(malicious_manifest)
    benign_entries = manifest_entries(benign_manifest, BENIGN_ARM)

    return samples, {
        "total": len(samples),
        "counts": corpus_counts(samples),
        # The same per-arm tables under two names: `arms` reads as the build's
        # own report and `drops` is what `provenance_payload` takes.
        "arms": arms,
        "drops": arms,
        # The reference set the malicious arm was screened against, with each
        # match count measured here rather than taken from the file.
        "vendor_reference": vendor_reference_payload(reference_record, malicious_entries),
        "sources": [
            {
                "name": MALICIOUS_SOURCE,
                "manifest": MALICIOUS_MANIFEST_FILENAME,
                "dataset": malicious_manifest.get("source"),
                "revision": malicious_manifest.get("revision"),
                "category": malicious_manifest.get("category"),
                "retrieved_at": malicious_manifest.get("retrieved_at"),
                "entries": len(malicious_entries),
                "reference": VENDOR_REFERENCE_FILENAME,
                "vendored_files": len(reference),
            },
            {
                "name": SDIST_SOURCE,
                "manifest": BENIGN_MANIFEST_FILENAME,
                "semgrep_version": benign_manifest.get("semgrep_version"),
                "retrieved_at": benign_manifest.get("retrieved_at"),
                "entries": len(benign_entries),
            },
            {
                "name": CODEQL_SOURCE,
                "manifest": BENIGN_MANIFEST_FILENAME,
                "repo": codeql_section.get("repo"),
                "ref": codeql_section.get("ref"),
                "subtree": codeql_section.get("subtree"),
                "retrieved_at": benign_manifest.get("retrieved_at"),
                "entries": len(near_miss_all),
                "selected": selection["selected"],
            },
        ],
    }


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


# ----------------------------------------------------------- the build driver
#
# What turns the four arms into one corpus, and what a reader checks first.
# Nothing here runs a sample: the malicious arm's files are opened for their
# bytes by the loaders above and are never executed, imported or byte-compiled,
# and this section only hashes, orders, counts and writes.

# The recorded facts of the semgrep-rules retrieval (plan section 12.1). The
# revision is the plan's recorded HEAD, and the two digests are the fingerprints
# of the retrieval itself - which is what a checkout with no history can
# actually be checked against. Section 14 records the trap this exists for: the
# directory is a codeload extraction with no `.git`, so `git log` inside it
# walks up to the parent repository and reports *that* repository's HEAD.
SEMGREP_RULES_URL = "https://codeload.github.com/semgrep/semgrep-rules/tar.gz/refs/heads/develop"
SEMGREP_RULES_REVISION = "a84ff9cc2453ca91d581380de4b8b3f272f6f4be"
SEMGREP_RULES_HEAD_URL = "https://api.github.com/repos/semgrep/semgrep-rules/commits/develop"
SEMGREP_RULES_CHECKOUT_DIRNAME = "semgrep-rules-develop"
SEMGREP_RULES_TARBALL_FILENAME = "sr.tgz"
SEMGREP_RULES_TARBALL_SHA256 = "a08f4fb36d9ffb286ad584044eca1c3ed1bedbdd70bfdb701ca0384c7a26964d"
SEMGREP_RULES_TREE_DIGEST = "d6a87432ca329d9d7a90482daa54cda334faa1ba62cd0fb55097a3c8201ce102"
SEMGREP_RULES_HEAD_TIMEOUT = 30

# Where the retrieval put the sources and where the corpus belongs. The corpus
# is not committed (plan section 12.4); the build is reproducible from this file
# plus `provenance.json`.
HOLDOUT_SOURCES_ROOT = REPO_ROOT / "models" / "audit" / "holdout-sources"
HOLDOUT_CORPUS_ROOT = REPO_ROOT / "models" / "audit" / "benchmarks" / "audit-holdout"

# The two records the build writes beside the corpus.
PROVENANCE_FILENAME = "provenance.json"
CORPUS_REPORT_FILENAME = "corpus-report.json"

# Requirement 4's floor (plan section 12.2 rule 5): at least 50 malicious and at
# least 50 benign, the near-miss arm counted on the benign side.
REQUIREMENT_4_FLOOR = 50

# The four arms, in the order the report states them. The corpus itself is
# written in `sample_id` order, so this is the report's order, not the corpus's.
ARM_ORDER = (SEMGREP_RULES_SOURCE, MALICIOUS_SOURCE, SDIST_SOURCE, CODEQL_SOURCE)

# Where each source came from and under what terms (plan sections 11.4 and
# 12.1). One URL per source is what a re-retrieval starts from; the per-sample
# provenance carries the URL of the individual download or file.
SOURCE_URLS = {
    SEMGREP_RULES_SOURCE: SEMGREP_RULES_URL,
    MALICIOUS_SOURCE: "https://github.com/DataDog/malicious-software-packages-dataset",
    SDIST_SOURCE: "https://pypi.org/pypi/",
    CODEQL_SOURCE: "https://github.com/github/codeql",
}

# The licence each arm's source is under, as the plan's retrieval table records
# it (section 12.1). The corpus is not committed (section 12.4), which is what
# keeps the semgrep-rules terms satisfied.
SOURCE_LICENSES = {
    SEMGREP_RULES_SOURCE: "Semgrep Rules License v1.0 (internal use only; no redistribution, no service)",
    MALICIOUS_SOURCE: "Apache-2.0",
    SDIST_SOURCE: "each package's own, as its sdist metadata states",
    CODEQL_SOURCE: "MIT",
}


def fetch_semgrep_rules_head(url: str = SEMGREP_RULES_HEAD_URL) -> str:
    """The upstream default branch's HEAD, from GitHub's API.

    The checkout cannot answer this itself: it is a tarball extraction with no
    `.git`, so `git log` inside it reports the parent repository's HEAD -
    measured, and one of the two recording traps this build exists to avoid. The
    API is the only party that can say which commit the default branch is at.
    The call is injectable so the build can be tested, and re-run, offline.
    """
    request = urllib.request.Request(url, headers={"User-Agent": "taa-holdout-corpus-build"})
    with urllib.request.urlopen(request, timeout=SEMGREP_RULES_HEAD_TIMEOUT) as response:
        payload = json.loads(response.read().decode("utf-8"))
    revision = payload.get("sha") if isinstance(payload, dict) else None
    if not isinstance(revision, str) or not revision:
        raise ValueError(f"{url} named no commit: {str(payload)[:200]}")
    return revision


def verify_semgrep_rules_checkout(
    root: Path,
    *,
    recorded_revision: str,
    recorded_tarball_sha256: str,
    tarball: Path,
    recorded_tree_digest: str,
    head_lookup: Optional[Callable[[], str]] = None,
) -> dict[str, Any]:
    """Verify the checkout against all three anchors the retrieval recorded.

    Three checks, because no one of them can stand in for the others. The
    tarball's hash covers the download the checkout was unpacked from; the tree
    digest covers the bytes actually on disk in path order, so a checkout that
    drifted - a file added, removed, renamed or edited - does not match even
    though both still describe "a semgrep-rules checkout"; and the upstream HEAD
    says which commit the default branch is at now, which is the only thing that
    can tell an intact but stale checkout from a current one.

    The checks run cheapest first, so a checkout that is wrong is refused
    locally without asking GitHub about it. Any mismatch raises, naming the
    check and both values: a build that carried on would label samples with a
    revision nobody could check, and the label on a sample is the whole of its
    ground truth.
    """
    root = Path(root)
    tarball = Path(tarball)

    if not tarball.is_file():
        raise ValueError(
            f"semgrep-rules tarball check failed: {tarball} is not a file; it is the "
            "download the checkout is verified against"
        )
    observed_tarball_sha256 = sha256_bytes(tarball.read_bytes())
    if observed_tarball_sha256 != recorded_tarball_sha256:
        raise ValueError(
            f"semgrep-rules tarball check failed: {tarball} hashes to "
            f"{observed_tarball_sha256}, the recorded tarball sha256 is {recorded_tarball_sha256}"
        )

    if not root.is_dir():
        raise ValueError(
            f"semgrep-rules tree check failed: {root} is not a directory; it is the "
            "checkout the windows are cut out of"
        )
    observed_tree_digest, files = tree_digest(root)
    if observed_tree_digest != recorded_tree_digest:
        raise ValueError(
            f"semgrep-rules tree check failed: {root} digests to {observed_tree_digest} over "
            f"{files} files, the recorded tree digest is {recorded_tree_digest}"
        )

    observed_revision = (head_lookup or fetch_semgrep_rules_head)()
    if observed_revision != recorded_revision:
        raise ValueError(
            f"semgrep-rules revision check failed: {SEMGREP_RULES_HEAD_URL} reports "
            f"{observed_revision}, the recorded revision is {recorded_revision}"
        )

    return {
        "root": str(root),
        "tarball": str(tarball),
        "tarball_sha256": {"recorded": recorded_tarball_sha256, "observed": observed_tarball_sha256},
        "tree_digest": {"recorded": recorded_tree_digest, "observed": observed_tree_digest,
                        "files": files},
        "revision": {"recorded": recorded_revision, "observed": observed_revision,
                     "endpoint": SEMGREP_RULES_HEAD_URL},
    }


def samples_by_source(samples: Sequence[Sample]) -> dict[str, list[Sample]]:
    """Group samples by the source their own provenance names, in input order."""
    grouped: dict[str, list[Sample]] = {}
    for sample in samples:
        source = str(sample.provenance.get("source", "unknown"))
        grouped.setdefault(source, []).append(sample)
    return grouped


def merge_arms(arms: Mapping[str, Sequence[Sample]]) -> list[Sample]:
    """Every arm in one corpus, in a deterministic order that refuses a repeat.

    The corpus list is an ordered run plan and the evaluator pairs the two arms
    by `sample_id`, so a repeated id does not fail a run - it silently collapses
    two samples into one pair and drops another. The check is here as well as in
    `write_corpus` because this is where the arms meet: a collision is a
    difference between two arms, and the message can then say which two, which
    is the fact a reader needs in order to find it.

    The order is the sorted `sample_id` and nothing else. The arms' id prefixes
    keep them in blocks, and the sort makes the list a property of the samples
    rather than of the order the arms happened to be built in.
    """
    merged: list[Sample] = []
    origin: dict[str, str] = {}
    for arm, samples in arms.items():
        for sample in samples:
            if sample.sample_id in origin:
                raise ValueError(
                    f"duplicate sample_id {sample.sample_id!r} in arm {origin[sample.sample_id]!r} "
                    f"and arm {arm!r}; the evaluator pairs the arms by it, so a repeat drops a pair"
                )
            origin[sample.sample_id] = arm
            merged.append(sample)
    return sorted(merged, key=lambda sample: sample.sample_id)


def clear_sample_dirs(root: Path) -> list[str]:
    """Remove the sample trees a previous build wrote, and name what it removed.

    The corpus is rebuilt from its recipe, so a second build must not merge into
    the first: an arm that shrank would leave directories behind that the new
    corpus list does not name, and a walk over the corpus directory would still
    find samples that no report counts. Only directories are removed - every
    sample lives in one, and the reports are files that get overwritten.
    """
    root = Path(root)
    if not root.is_dir():
        return []
    removed: list[str] = []
    for entry in sorted(root.iterdir()):
        if entry.is_dir():
            shutil.rmtree(entry)
            removed.append(entry.name)
    return removed


def arm_sample_counts(arms: Mapping[str, Sequence[Sample]]) -> dict[str, Any]:
    """Per arm: how many samples, and how the two labels split."""
    return {
        arm: {
            "samples": len(samples),
            "malicious": sum(1 for sample in samples if sample.label == LABEL_BY_KIND["ruleid"]),
            "benign": sum(1 for sample in samples if sample.label != LABEL_BY_KIND["ruleid"]),
        }
        for arm, samples in arms.items()
    }


def requirement_4_floor(samples: Sequence[Sample]) -> dict[str, Any]:
    """Requirement 4's floor, as a verdict that is reported and never raised.

    The plan fixes two thresholds - at least 50 malicious samples and at least
    50 benign, with the near-miss arm counted on the benign side - and says a
    shortfall is written up as insufficient evidence rather than met by lowering
    the threshold. So this returns a verdict and does not raise: a build that
    refused to finish would leave no corpus and no provenance to write the
    shortfall up in, which is less than a corpus with a stated gap.

    `shortfalls` names only the two sides the requirement counts. A sub-arm may
    be below the floor on its own - the CodeQL near-miss files are five, and are
    not meant to carry the side by themselves - and that is a fact about the
    arm's composition rather than a failed requirement, so it is visible in the
    per-arm verdicts and absent from the shortfalls.
    """
    malicious = 0
    benign = 0
    near_miss = 0
    for sample in samples:
        if sample.label == LABEL_BY_KIND["ruleid"]:
            malicious += 1
        elif str(sample.provenance.get("source", "")) == SDIST_SOURCE:
            benign += 1
        else:
            # Everything benign that is not the sdist arm: the two upstream
            # sources of explicit negatives. A source this build does not know
            # would land here too, which keeps it on the benign side rather than
            # letting it disappear from the table.
            near_miss += 1
    benign_side = benign + near_miss
    verdicts: dict[str, Any] = {
        "malicious": {
            "count": malicious,
            "meets_floor": malicious >= REQUIREMENT_4_FLOOR,
            "basis": "every malicious-labelled sample: the ruleid windows and the non-vendored DataDog files",
        },
        "benign": {
            "count": benign,
            "meets_floor": benign >= REQUIREMENT_4_FLOOR,
            "basis": "the PyPI sdist arm",
        },
        "near_miss": {
            "count": near_miss,
            "meets_floor": near_miss >= REQUIREMENT_4_FLOOR,
            "basis": "the ok windows and the CodeQL negative-only files",
        },
        "benign_side": {
            "count": benign_side,
            "meets_floor": benign_side >= REQUIREMENT_4_FLOOR,
            "basis": "the benign arm together with the near-miss arm, which is the side requirement 4 counts",
        },
    }
    shortfalls = [name for name in ("malicious", "benign_side") if not verdicts[name]["meets_floor"]]
    return {
        "floor": REQUIREMENT_4_FLOOR,
        "met": not shortfalls,
        "verdicts": verdicts,
        "shortfalls": shortfalls,
    }


def family_map_snapshot() -> dict[str, Any]:
    """The annotation-to-family table this build used, frozen into the record.

    The table is ours, not upstream's: the annotations were written for upstream
    rules and this is the translation (plan section 11.3). Carrying it with the
    corpus is what lets a reader re-derive every family attribution without
    re-running the build, and the digest over the pairs is what notices a later
    edit to the table. The order is part of the fact - the first lexeme found in
    an upstream rule id wins - so the pairs are carried as an ordered list.
    """
    pairs = [[lexeme, family] for lexeme, family in FAMILY_LEXEMES]
    return {
        "lexemes": pairs,
        "sha256": sha256_text(json.dumps(pairs, separators=(",", ":"))),
        "order": "first lexeme found in the upstream rule id wins",
    }


def source_records(
    report_sources: Sequence[Mapping[str, Any]],
    sources_root: Path,
    *,
    checkout: Mapping[str, Any],
    semgrep_rules_samples: int,
) -> list[dict[str, Any]]:
    """Every source with the URL, revision and hashes a reader needs to re-fetch it.

    The build's own report says what each arm read and how much of it; this adds
    the coordinates provenance is for. `sha256` is the hash of the artifact the
    arm was built from, which only the semgrep-rules tarball has: the other
    three arms are manifests of per-file downloads, there is no single archive,
    and each sample's own provenance carries the URL and hash of its own file.
    The manifest's own sha256 is carried too, so a reader can tell whether the
    manifest in hand is the one this corpus was built against.
    """
    records: list[dict[str, Any]] = []
    for source in report_sources:
        record = dict(source)
        name = str(record.get("name"))
        record["url"] = SOURCE_URLS.get(name)
        record["license"] = SOURCE_LICENSES.get(name)
        # One arm is pinned to a commit and another to a dependency set; both are
        # what make it reproducible, so both are carried under `revision`.
        if not record.get("revision"):
            record["revision"] = record.get("ref") or record.get("semgrep_version")
        record["sha256"] = None
        manifest = record.get("manifest")
        record["manifest_sha256"] = (
            sha256_bytes((Path(sources_root) / str(manifest)).read_bytes()) if manifest else None
        )
        records.append(record)
    records.append({
        "name": SEMGREP_RULES_SOURCE,
        "url": SEMGREP_RULES_URL,
        "license": SOURCE_LICENSES[SEMGREP_RULES_SOURCE],
        "revision": checkout["revision"]["observed"],
        "sha256": checkout["tarball_sha256"]["observed"],
        "tarball": checkout["tarball"],
        "tree_digest": checkout["tree_digest"]["observed"],
        "files": checkout["tree_digest"]["files"],
        "manifest": None,
        "manifest_sha256": None,
        "selected": semgrep_rules_samples,
        "modification": SEMGREP_RULES_MODIFICATION,
    })
    return records


def build_holdout_corpus(
    sources_root: Path,
    corpus_root: Path,
    *,
    reference_path: Path,
    semgrep_rules_root: Path,
    revision: str,
    semgrep_rules_tarball: Path,
    recorded_tarball_sha256: str,
    recorded_tree_digest: str,
    head_lookup: Optional[Callable[[], str]] = None,
) -> dict[str, Any]:
    """Build the whole corpus, and fail before writing anything unverifiable.

    The order is the point. The checkout is verified first, because a sample's
    revision is the only record of which upstream code it came from and a
    revision that cannot be checked is a label nobody can audit. Then the arms
    are built - the windows out of the verified checkout, the three
    manifest-backed arms out of the sources root - with the vendor reference
    refused rather than defaulted when it is absent, since an absent reference
    silently restores every released library copy into the malicious arm. Only
    then is anything written: the corpus, `provenance.json` and
    `corpus-report.json`.

    Idempotent. The sample directories of a previous build are removed first,
    and every value in the two reports is measured from the inputs rather than
    from the clock or the filesystem's order, so two runs over the same inputs
    differ only in `built_at`.
    """
    sources_root = Path(sources_root)
    corpus_root = Path(corpus_root)
    semgrep_rules_root = Path(semgrep_rules_root)

    checkout = verify_semgrep_rules_checkout(
        semgrep_rules_root,
        recorded_revision=revision,
        recorded_tarball_sha256=recorded_tarball_sha256,
        tarball=semgrep_rules_tarball,
        recorded_tree_digest=recorded_tree_digest,
        head_lookup=head_lookup,
    )

    windows, window_drops = samples_from_windows(semgrep_rules_root, revision=revision)
    manifest_samples, holdout_report = build_holdout(sources_root, reference_path=reference_path)

    grouped = samples_by_source([*windows, *manifest_samples])
    unknown = sorted(set(grouped) - set(ARM_ORDER))
    if unknown:
        raise ValueError(f"samples carry source(s) this build does not know: {unknown}")
    # Every arm is present in the tables even when it built nothing: an arm that
    # is absent cannot be told apart from one that was never measured.
    arms_before_filter = {name: grouped.get(name, []) for name in ARM_ORDER}
    drops = {name: dict(table) for name, table in
             {SEMGREP_RULES_SOURCE: window_drops, **holdout_report["drops"]}.items()}
    samples = merge_arms(arms_before_filter)

    # Rule 9, applied once to the merged list so that no arm can be built
    # without passing through it. The arms are then rebuilt from what survived,
    # because every count below - the per-arm tables, the floor, the written
    # corpus - has to describe the corpus that is written rather than the one
    # the arms produced.
    samples, long_line_dropped = drop_long_lines(samples)
    filtered = samples_by_source(samples)
    arms = {name: filtered.get(name, []) for name in ARM_ORDER}
    for name in ARM_ORDER:
        drops[name]["long_line"] = sum(1 for row in long_line_dropped if row["source"] == name)
        # The longest line the arm brought to the filter, kept even for arms
        # that lost nothing, so a reader can see how close an arm came to the
        # bound instead of having to trust that it did not.
        drops[name]["long_line_max_bytes"] = max(
            (sample_max_line(sample) for sample in arms_before_filter[name]), default=0
        )

    removed = clear_sample_dirs(corpus_root)
    counts = write_corpus(corpus_root, samples)
    corpus_root.mkdir(parents=True, exist_ok=True)

    provenance = provenance_payload(
        source_records(holdout_report["sources"], sources_root, checkout=checkout,
                       semgrep_rules_samples=len(windows)),
        samples,
        drops,
        verification=checkout,
        vendor_reference=holdout_report["vendor_reference"],
        arm_counts=arm_sample_counts(arms),
        selection=holdout_report["drops"][CODEQL_SOURCE]["selection"],
        family_map=family_map_snapshot(),
        long_line=long_line_exclusion(long_line_dropped),
    )
    floor = requirement_4_floor(samples)
    report = {
        "built_at": provenance["built_at"],
        "counts": counts,
        "arm_counts": provenance["arm_counts"],
        "requirement_4": floor,
        "long_line_exclusion": {
            "limit_bytes": provenance["long_line_exclusion"]["limit_bytes"],
            "count": provenance["long_line_exclusion"]["count"],
            "sample_ids": [row["sample_id"] for row in provenance["long_line_exclusion"]["samples"]],
        },
    }
    (corpus_root / PROVENANCE_FILENAME).write_text(
        json.dumps(provenance, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )
    (corpus_root / CORPUS_REPORT_FILENAME).write_text(
        json.dumps(report, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )

    return {
        "corpus_root": str(corpus_root),
        "counts": counts,
        "arm_counts": provenance["arm_counts"],
        "drops": drops,
        "requirement_4": floor,
        "removed": removed,
        "checkout": checkout,
        "sources": provenance["sources"],
        "long_line_exclusion": provenance["long_line_exclusion"],
    }


def format_summary(summary: Mapping[str, Any]) -> str:
    """The build's counts, drop tables and floor verdict, as plain text.

    Plain ASCII in fixed columns: this is read in a terminal and pasted into a
    report, and both are worse for anything cleverer.
    """
    counts = summary["counts"]
    by_label = ", ".join(f"{label}={counts['by_label'][label]}" for label in sorted(counts["by_label"]))
    lines = [
        f"corpus: {summary['corpus_root']}",
        f"samples: {counts['total']} ({by_label})",
        "",
        f"{'arm':<20}{'samples':>8}{'malicious':>11}{'benign':>8}",
    ]
    for name, arm in summary["arm_counts"].items():
        lines.append(f"{name:<20}{arm['samples']:>8}{arm['malicious']:>11}{arm['benign']:>8}")

    lines.append("")
    lines.append("drops")
    for name, table in summary["drops"].items():
        counts_text = "  ".join(
            f"{key}={table[key]}" for key in sorted(table) if isinstance(table[key], int)
        )
        lines.append(f"  {name}: {counts_text}")
    selection = summary["drops"].get(CODEQL_SOURCE) or {}
    selection = selection.get("selection") if isinstance(selection, Mapping) else None
    if isinstance(selection, Mapping):
        classes = "  ".join(f"{name}={count}" for name, count in selection["classification"].items())
        lines.append(f"  {CODEQL_SOURCE} selection: {classes}")

    floor = summary["requirement_4"]
    lines.append("")
    lines.append(
        f"requirement 4 floor (>={floor['floor']} per side): {'met' if floor['met'] else 'NOT MET'}"
    )
    for name, verdict in floor["verdicts"].items():
        mark = "ok" if verdict["meets_floor"] else "below floor"
        lines.append(f"  {name:<12}{verdict['count']:>6}  {mark}")
    for name in floor["shortfalls"]:
        lines.append(f"  shortfall: {name} is below {floor['floor']}, reported and not raised")

    checkout = summary.get("checkout") or {}
    if checkout:
        lines.append(
            "semgrep-rules checkout verified: tarball sha256 "
            f"{checkout['tarball_sha256']['observed']}, tree digest over "
            f"{checkout['tree_digest']['files']} files, upstream HEAD "
            f"{checkout['revision']['observed']}"
        )
    if summary.get("removed"):
        lines.append(f"cleared stale sample dirs: {', '.join(summary['removed'])}")

    exclusion = summary.get("long_line_exclusion") or {}
    if exclusion:
        # Printed with the ids rather than the count alone: a count says the rule
        # fired, the ids say which samples a reader would have to fetch to
        # disagree with it.
        ids = ", ".join(row["sample_id"] for row in exclusion.get("samples", []))
        lines.append(
            f"long-line exclusion (>{exclusion['limit_bytes']} B): {exclusion['count']}"
            + (f" - {ids}" if ids else "")
        )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    """The driver's command line, with the recorded facts as its defaults.

    The digests default to what the retrieval recorded, so a rebuild of the
    corpus the plan describes is one command; each one can be overridden, which
    is what makes a checkout from another retrieval checkable against its own
    record rather than against this one's.
    """
    parser = argparse.ArgumentParser(
        prog="holdout_corpus",
        description="Build the stage-H holdout corpus, verifying its sources first.",
    )
    parser.add_argument("--sources-root", type=Path, default=HOLDOUT_SOURCES_ROOT,
                        help=f"the retrieved sources (default: {HOLDOUT_SOURCES_ROOT})")
    parser.add_argument("--corpus-root", type=Path, default=HOLDOUT_CORPUS_ROOT,
                        help=f"where the corpus is written (default: {HOLDOUT_CORPUS_ROOT})")
    parser.add_argument("--reference", type=Path, default=None,
                        help="the vendor reference "
                             f"(default: <sources-root>/{DD_DIRNAME}/{VENDOR_REFERENCE_FILENAME})")
    parser.add_argument("--semgrep-rules-root", type=Path, default=None,
                        help="the semgrep-rules checkout "
                             f"(default: <sources-root>/{SEMGREP_RULES_CHECKOUT_DIRNAME})")
    parser.add_argument("--semgrep-rules-tarball", type=Path, default=None,
                        help="the tarball the checkout was unpacked from "
                             f"(default: <sources-root>/{SEMGREP_RULES_TARBALL_FILENAME})")
    parser.add_argument("--revision", default=SEMGREP_RULES_REVISION,
                        help="the recorded upstream revision (default: the plan's recorded HEAD)")
    parser.add_argument("--semgrep-rules-tarball-sha256", default=SEMGREP_RULES_TARBALL_SHA256,
                        help="the recorded tarball hash (default: the retrieval's)")
    parser.add_argument("--semgrep-rules-tree-digest", default=SEMGREP_RULES_TREE_DIGEST,
                        help="the recorded tree digest (default: the retrieval's)")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Build from the command line: 0 when the corpus is written, 2 when it is not.

    A failure is any verification the build could not complete - a tarball, a
    tree digest or a revision that does not match its record, an absent vendor
    reference, a manifest that does not describe what is on disk. It is printed
    with the values that disagree and exits non-zero: the corpus is either the
    one its provenance describes or it is not written at all.

    The requirement-4 floor is not a failure here. It is a verdict the reports
    carry, and a shortfall still exits 0, because the plan asks for it to be
    written up as insufficient evidence rather than for the build to refuse.
    """
    args = build_parser().parse_args(argv)
    reference = args.reference or args.sources_root / DD_DIRNAME / VENDOR_REFERENCE_FILENAME
    semgrep_rules_root = args.semgrep_rules_root or args.sources_root / SEMGREP_RULES_CHECKOUT_DIRNAME
    tarball = args.semgrep_rules_tarball or args.sources_root / SEMGREP_RULES_TARBALL_FILENAME
    try:
        summary = build_holdout_corpus(
            args.sources_root,
            args.corpus_root,
            reference_path=reference,
            semgrep_rules_root=semgrep_rules_root,
            revision=args.revision,
            semgrep_rules_tarball=tarball,
            recorded_tarball_sha256=args.semgrep_rules_tarball_sha256,
            recorded_tree_digest=args.semgrep_rules_tree_digest,
        )
    except (ValueError, OSError) as exc:
        print(f"holdout build failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(format_summary(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
