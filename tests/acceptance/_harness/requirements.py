"""Ratified-requirement registry and exact backreference enforcement.

Every acceptance assertion in this suite must backreference an exact ratified
requirement. That is enforced mechanically here rather than by convention:

* :func:`verify_manifest` recomputes SHA-256 over every artifact the ratification
  manifest names and refuses to let the suite run against different bytes. A
  digest disagreement is ``INVALID_HARNESS`` -- the instrument is not measuring
  the ratified specification -- never a product failure.
* :func:`spec_ref` decorates a test with one or more :class:`SpecRef` records.
  Each record names the gate, the ratified artifact, a section anchor, and a
  *verbatim quote*. The quote must occur in that artifact (modulo the artifact's
  markdown hard-wrapping, which is normalised away) or the reference is invalid.
* ``test_backreference_integrity.py`` asserts that every collected test node
  carries at least one resolvable reference and that no reference points at an
  artifact outside the ratified precedence chain.

Authority precedence, from ``spec/ratification-manifest.json``:

    source-request.md > product.md > architecture.md > threat-model.md >
    verification.md > cli.md

``spec/behavior-ledger.md``, ``spec/glossary.md``, ``spec/leak-runbook.md``,
``spec/review-rubric.md`` and the review disposition may be cited only as
``TRACE`` references. Per the Tester dispatch they trace intent and cannot
create or weaken a requirement, so a ``TRACE`` reference never satisfies the
"every test is backreferenced" rule on its own.
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence

# --------------------------------------------------------------------------
# Frozen ratification constants. These are the Tester's binding to the run.
# --------------------------------------------------------------------------

RATIFICATION_MANIFEST_SHA256 = (
    "12dd4c18aaca12c29cc816ca4a5161b5e011814f021879897b88b0e6e85168dd"
)
BASELINE_COMMIT = "e29f3fe03595d594c0546f9b0012b58f7c45bac1"

#: ``spec/ratification-manifest.json`` -> ``authority_precedence`` verbatim.
AUTHORITY_PRECEDENCE: tuple[str, ...] = (
    "spec/source-request.md",
    "spec/product.md",
    "spec/architecture.md",
    "spec/threat-model.md",
    "spec/verification.md",
    "spec/cli.md",
)

#: Artifacts that may be cited for intent tracing only. Per the Tester dispatch
#: these "may help trace intent but cannot create or weaken requirements".
TRACE_ONLY_ARTIFACTS: tuple[str, ...] = (
    "spec/behavior-ledger.md",
    "spec/glossary.md",
    "spec/leak-runbook.md",
    "spec/review-rubric.md",
    "spec/README.md",
    "spec/reviews/pre-ratification-disposition.md",
    "spec/receipts/founder-ratification-ac8a13d1.json",
    "spec/receipts/validator-ratification-ac8a13d1.json",
)

#: The two ratification receipts the Tester is permitted to read.
RECEIPTS: tuple[str, ...] = (
    "spec/receipts/founder-ratification-ac8a13d1.json",
    "spec/receipts/validator-ratification-ac8a13d1.json",
)

GATES: tuple[str, ...] = (
    "V-1",
    "V-2",
    "V-3",
    "V-4",
    "V-5",
    "V-6",
    "V-7",
    "V-8",
    "V-9",
    "V-10",
    "NONFUNCTIONAL",
    "EVIDENCE",
    "VERDICT",
    "INSTRUMENT",
)


class HarnessInvalid(AssertionError):
    """Raised when the instrument itself, not the product, is untrustworthy.

    ``spec/verification.md`` "Verdict semantics" separates ``INVALID_HARNESS``
    from ``PRODUCT_FAILURE``; conflating them would let a broken detector be
    reported as a product defect or vice versa. Every raise site here is an
    instrument-integrity condition.
    """


class ProductFailure(AssertionError):
    """Raised when the product violates a ratified obligation."""


# --------------------------------------------------------------------------
# Repository location
# --------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def repo_root() -> Path:
    """Locate the standalone proof repository containing ``spec/``.

    ``KINBASE_SPEC_ROOT`` overrides discovery so the Validator can combine the
    Coder snapshot and this suite in a scratch tree.
    """
    override = os.environ.get("KINBASE_SPEC_ROOT")
    if override:
        candidate = Path(override).resolve()
        if (candidate / "spec" / "ratification-manifest.json").is_file():
            return candidate
        raise HarnessInvalid(
            f"KINBASE_SPEC_ROOT={override!r} has no spec/ratification-manifest.json"
        )
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "spec" / "ratification-manifest.json").is_file():
            return parent
    raise HarnessInvalid(
        "cannot locate the ratified spec/ tree; set KINBASE_SPEC_ROOT"
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# --------------------------------------------------------------------------
# Manifest verification
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ManifestVerification:
    manifest_sha256: str
    artifact_digests: dict[str, str]
    precedence: tuple[str, ...]
    receipt_digests: dict[str, str]


@functools.lru_cache(maxsize=2)
def verify_manifest(reviewer_mode: bool = False) -> ManifestVerification:
    """Recompute and check every digest the ratification manifest names.

    A mismatch raises :class:`HarnessInvalid`. The suite must never quietly
    measure against unratified bytes.

    ``reviewer_mode`` restricts verification to the six ratified authority
    artifacts. ``spec/verification.md`` "Instrument validity" gives the
    implementation-blind Detector Reviewer only "ratified specs, tests/fixtures,
    detector design, and the eligible licensed-public auxiliary-corpus pool", so
    the review-evidence and receipt paths named by the manifest are outside its
    surface. Receipt verification is the Validator's step and is unchanged for
    an ordinary run.
    """
    root = repo_root()
    manifest_path = root / "spec" / "ratification-manifest.json"
    observed_manifest = sha256_file(manifest_path)
    if observed_manifest != RATIFICATION_MANIFEST_SHA256:
        raise HarnessInvalid(
            "ratification manifest digest mismatch: expected "
            f"{RATIFICATION_MANIFEST_SHA256} observed {observed_manifest}"
        )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    precedence = tuple(manifest["authority_precedence"])
    if precedence != AUTHORITY_PRECEDENCE:
        raise HarnessInvalid(
            f"authority precedence changed: {precedence!r}"
        )

    digests: dict[str, str] = {}
    for artifact in manifest["artifacts"]:
        rel = artifact["path"]
        observed = sha256_file(root / rel)
        if observed != artifact["sha256"]:
            raise HarnessInvalid(
                f"ratified artifact {rel} digest mismatch: expected "
                f"{artifact['sha256']} observed {observed}"
            )
        digests[rel] = observed
    if tuple(digests) != AUTHORITY_PRECEDENCE:
        raise HarnessInvalid(
            "manifest artifact set does not equal the precedence chain: "
            f"{tuple(digests)!r}"
        )

    if reviewer_mode:
        return ManifestVerification(
            manifest_sha256=observed_manifest,
            artifact_digests=digests,
            precedence=precedence,
            receipt_digests={},
        )

    # The advocate review evidence digest is taken over the *decoded* JSON, not
    # the base64 container; verified here so a silently swapped evidence file is
    # visible to the instrument.
    review = manifest["review_evidence"]
    import base64

    b64_path = root / review["advocate_final_path"]
    try:
        container = b64_path.read_bytes()
    except OSError as exc:
        # An unreadable authority path is an *environment* prerequisite, not a
        # product observation and not a crash. Detector Reviewer finding 10:
        # the instrument must classify its own missing prerequisites.
        raise HarnessInvalid(
            f"cannot read ratification evidence {b64_path}: {exc}. This is an "
            "instrument environment prerequisite. An implementation-blind "
            "reviewer whose lane excludes evidence/** must set "
            "KINBASE_REVIEWER_MODE=1, which verifies the six ratified "
            "authority artifacts only."
        ) from exc
    decoded = base64.b64decode(b"".join(container.split()))
    decoded_digest = hashlib.sha256(decoded).hexdigest()
    if decoded_digest != review["advocate_final_sha256"]:
        raise HarnessInvalid(
            "advocate final review digest mismatch: expected "
            f"{review['advocate_final_sha256']} observed {decoded_digest}"
        )

    receipts: dict[str, str] = {}
    for rel in RECEIPTS:
        path = root / rel
        try:
            if not path.is_file():
                raise HarnessInvalid(f"missing ratification receipt {rel}")
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise HarnessInvalid(
                f"cannot read ratification receipt {rel}: {exc}; set "
                "KINBASE_REVIEWER_MODE=1 for an implementation-blind lane"
            ) from exc
        payload = json.loads(raw)
        if payload.get("manifest_sha256") != RATIFICATION_MANIFEST_SHA256:
            raise HarnessInvalid(
                f"receipt {rel} does not bind manifest "
                f"{RATIFICATION_MANIFEST_SHA256}"
            )
        receipts[rel] = sha256_file(path)

    return ManifestVerification(
        manifest_sha256=observed_manifest,
        artifact_digests=digests,
        precedence=precedence,
        receipt_digests=receipts,
    )


@functools.lru_cache(maxsize=None)
def _artifact_text(rel: str) -> str:
    return (repo_root() / rel).read_text(encoding="utf-8")


_WHITESPACE = re.compile(r"\s+")
#: A hyphen immediately before a hard line break. The ratified artifacts wrap at
#: roughly 80 columns, so ``positive-\ncontrol`` is the single token
#: ``positive-control``. Both readings are kept so a quote matches either way and
#: no genuine hyphenated pair is silently rewritten.
_HYPHEN_BREAK = re.compile(r"-\n[ \t]*")


def _normalise(text: str) -> str:
    """Collapse markdown hard-wrapping so a quote can span source lines.

    Only whitespace runs are collapsed and the text is NFC normalised. No word,
    punctuation mark, threshold or identifier is altered, so an "exact quote"
    remains exact in every semantically load-bearing character.
    """
    return _WHITESPACE.sub(" ", unicodedata.normalize("NFC", text)).strip()


def _normalise_dehyphenated(text: str) -> str:
    """As :func:`_normalise`, but rejoining hyphen-at-end-of-line wraps."""
    joined = _HYPHEN_BREAK.sub("-", unicodedata.normalize("NFC", text))
    return _WHITESPACE.sub(" ", joined).strip()


#: Markdown blockquote markers. ``spec/source-request.md`` preserves the founder's
#: statements as blockquotes, so a quote that spans two wrapped lines otherwise
#: picks up a stray ``>``. Only the structural marker is removed; the quoted
#: words are untouched.
_BLOCKQUOTE = re.compile(r"^[ \t]*>[ \t]?", re.MULTILINE)


def _strip_blockquote(text: str) -> str:
    return _BLOCKQUOTE.sub("", text)


def _variants(text: str) -> tuple[str, ...]:
    """Every structurally-normalised reading of one markdown passage."""
    stripped = _strip_blockquote(text)
    return (
        _normalise(text),
        _normalise_dehyphenated(text),
        _normalise(stripped),
        _normalise_dehyphenated(stripped),
    )


@functools.lru_cache(maxsize=None)
def _artifact_variants(rel: str) -> tuple[str, ...]:
    return _variants(_artifact_text(rel))


# --------------------------------------------------------------------------
# Spec references
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SpecRef:
    """One exact backreference from a test to a ratified requirement."""

    gate: str
    artifact: str
    anchor: str
    quote: str
    trace_only: bool = field(default=False)

    def __post_init__(self) -> None:
        if self.gate not in GATES:
            raise HarnessInvalid(f"unknown gate {self.gate!r}")
        if self.artifact in TRACE_ONLY_ARTIFACTS:
            object.__setattr__(self, "trace_only", True)
        elif self.artifact not in AUTHORITY_PRECEDENCE:
            raise HarnessInvalid(
                f"{self.artifact!r} is neither a ratified authority artifact "
                "nor a permitted trace artifact"
            )

    @property
    def authority_rank(self) -> int:
        """Lower is higher authority. Trace artifacts rank after everything."""
        if self.trace_only:
            return len(AUTHORITY_PRECEDENCE)
        return AUTHORITY_PRECEDENCE.index(self.artifact)

    def resolve(self) -> bool:
        """True when the verbatim quote occurs in the ratified artifact."""
        needles = _variants(self.quote)
        haystacks = _artifact_variants(self.artifact)
        return any(needle in hay for needle in needles for hay in haystacks)

    def require(self) -> None:
        if not self.resolve():
            raise HarnessInvalid(
                f"backreference does not resolve: {self.gate} "
                f"{self.artifact}#{self.anchor}\n  quote: {self.quote!r}"
            )

    def render(self) -> str:
        kind = "TRACE" if self.trace_only else "AUTHORITY"
        return f"[{kind} {self.gate}] {self.artifact}#{self.anchor}: {self.quote!r}"


#: Registry populated by the :func:`spec_ref` decorator at import time.
REGISTRY: dict[str, tuple[SpecRef, ...]] = {}


def _qualified_name(func: Callable) -> str:
    return f"{func.__module__}::{func.__qualname__}"


def spec_ref(*refs: SpecRef) -> Callable:
    """Attach ratified backreferences to a test function.

    The references are validated eagerly at import time so a stale quote fails
    collection rather than silently passing an unbackreferenced assertion.
    """
    if not refs:
        raise HarnessInvalid("spec_ref requires at least one SpecRef")

    def decorator(func: Callable) -> Callable:
        for ref in refs:
            ref.require()
        existing = getattr(func, "__spec_refs__", ())
        merged = tuple(existing) + tuple(refs)
        func.__spec_refs__ = merged  # type: ignore[attr-defined]
        REGISTRY[_qualified_name(func)] = merged
        return func

    return decorator


def refs_of(func: Callable) -> tuple[SpecRef, ...]:
    return tuple(getattr(func, "__spec_refs__", ()))


def authority_refs(refs: Iterable[SpecRef]) -> tuple[SpecRef, ...]:
    return tuple(r for r in refs if not r.trace_only)


def cite(refs: Sequence[SpecRef], detail: str = "") -> str:
    """Render a failure message that names the exact requirement violated."""
    lines = [r.render() for r in refs]
    if detail:
        lines.append(detail)
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Shorthand constructors for the ratified artifacts
# --------------------------------------------------------------------------


def SRC(gate: str, anchor: str, quote: str) -> SpecRef:
    return SpecRef(gate, "spec/source-request.md", anchor, quote)


def PRODUCT(gate: str, anchor: str, quote: str) -> SpecRef:
    return SpecRef(gate, "spec/product.md", anchor, quote)


def ARCH(gate: str, anchor: str, quote: str) -> SpecRef:
    return SpecRef(gate, "spec/architecture.md", anchor, quote)


def THREAT(gate: str, anchor: str, quote: str) -> SpecRef:
    return SpecRef(gate, "spec/threat-model.md", anchor, quote)


def VERIFY(gate: str, anchor: str, quote: str) -> SpecRef:
    return SpecRef(gate, "spec/verification.md", anchor, quote)


def CLI(gate: str, anchor: str, quote: str) -> SpecRef:
    return SpecRef(gate, "spec/cli.md", anchor, quote)


def TRACE(gate: str, artifact: str, anchor: str, quote: str) -> SpecRef:
    return SpecRef(gate, artifact, anchor, quote, trace_only=True)
