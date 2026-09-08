#!/usr/bin/env python3
"""Materialize Guildhall amendment 001 from its frozen base artifacts."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import posixpath
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path


TARGET = re.compile(r"^In `(spec/[^`]+)`.*\b(replace|insert)\b.*:$")
SECTION_ROW = re.compile(r"^\| (O-\d{2}) \| (spec/[^ |]+) \| (#{1,6} .+) \|$")
SUPPLEMENT_ROW = re.compile(r"^\| (spec/[^ |]+\.md) \| `([0-9a-f]{64})` \|$")
BUNDLE_ROW = re.compile(r"^\| (spec/[^ |]+) \| .+ \|$")
MARKDOWN_LINK = re.compile(r"\]\(([^)#]+\.md)(?:#[^)]+)?\)")
REFERENCE_LINK = re.compile(
    r"(?m)^[ ]{0,3}\[[^\]\r\n]+\]:[ \t]*<?([^ \t>\r\n]+\.md(?:#[^ \t>\r\n]+)?)>?"
)
AUTOLINK = re.compile(r"<([^<>\s]+\.md(?:#[^<>\s]+)?)>")
SAFE_PATH = re.compile(r"^spec/[A-Za-z0-9._/-]+$")
SAFE_LOCAL_MD_TARGET = re.compile(r"^[A-Za-z0-9._/-]+\.md$")


@dataclass(frozen=True)
class Operation:
    ordinal: int
    operation_id: str
    path: str
    containing_heading: str
    mode: str
    source: bytes
    new: bytes


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def occurrence_count(body: bytes, needle: bytes) -> int:
    """Count overlapping exact-byte occurrences without regex semantics."""
    count = 0
    cursor = 0
    while True:
        offset = body.find(needle, cursor)
        if offset < 0:
            return count
        count += 1
        cursor = offset + 1


def validate_document_bytes(body: bytes, label: str) -> None:
    if body.startswith(b"\xef\xbb\xbf"):
        raise ValueError(f"{label} must not contain UTF-8 BOM")
    if b"\r" in body:
        raise ValueError(f"{label} must be LF-only")
    body.decode("utf-8")


def quoted_block(lines: list[str], start: int) -> tuple[bytes, int]:
    index = start
    while index < len(lines) and not lines[index].startswith(">"):
        index += 1
    if index == len(lines):
        raise ValueError(f"missing quoted block after amendment line {start + 1}")

    decoded: list[str] = []
    while index < len(lines) and lines[index].startswith(">"):
        line = lines[index]
        if line.endswith((" ", "\t")):
            raise ValueError(f"trailing whitespace in blockquote at amendment line {index + 1}")
        if line == ">":
            decoded.append("")
        elif line.startswith("> "):
            decoded.append(line[2:])
        else:
            raise ValueError(f"noncanonical blockquote at amendment line {index + 1}")
        index += 1
    return ("\n".join(decoded) + "\n").encode("utf-8"), index


def parse_operations(amendment: bytes) -> list[Operation]:
    validate_document_bytes(amendment, "amendment")
    text = amendment.decode("utf-8")
    lines = text.splitlines()
    section_rows: dict[str, tuple[str, str]] = {}
    for line in lines:
        match = SECTION_ROW.match(line)
        if not match:
            continue
        operation_id, path, heading = match.groups()
        if operation_id in section_rows:
            raise ValueError(f"duplicate section declaration for {operation_id}")
        section_rows[operation_id] = (path, heading)
    operations: list[Operation] = []

    for index, line in enumerate(lines):
        match = TARGET.match(line)
        if not match:
            continue
        path, verb = match.groups()
        mode = "replace" if verb == "replace" else "insert"
        source, next_index = quoted_block(lines, index + 1)

        expected_marker = "with this exact new" if mode == "replace" else "this new"
        marker_index = next_index
        while marker_index < len(lines) and not lines[marker_index].startswith(
            expected_marker
        ):
            if TARGET.match(lines[marker_index]):
                raise ValueError(f"missing new-block marker after amendment line {index + 1}")
            marker_index += 1
        if marker_index == len(lines):
            raise ValueError(f"missing new-block marker after amendment line {index + 1}")
        new, _ = quoted_block(lines, marker_index + 1)

        ordinal = len(operations) + 1
        operation_id = f"O-{ordinal:02d}"
        if operation_id not in section_rows:
            raise ValueError(f"missing section declaration for {operation_id}")
        declared_path, heading = section_rows[operation_id]
        if declared_path != path:
            raise ValueError(f"section path mismatch for {operation_id}")
        operations.append(
            Operation(
                ordinal=ordinal,
                operation_id=operation_id,
                path=path,
                containing_heading=heading,
                mode=mode,
                source=source,
                new=new,
            )
        )

    if not operations:
        raise ValueError("no overlay operations found")
    expected_ids = {operation.operation_id for operation in operations}
    if set(section_rows) != expected_ids:
        raise ValueError("section declaration census does not match operation census")
    return operations


def parse_supplements(amendment: bytes) -> dict[str, str]:
    supplements: dict[str, str] = {}
    for line in amendment.decode("utf-8").splitlines():
        match = SUPPLEMENT_ROW.match(line)
        if not match:
            continue
        path, digest = match.groups()
        if path in supplements:
            raise ValueError(f"duplicate supplemental path {path}")
        supplements[path] = digest
    if len(supplements) != 2:
        raise ValueError(f"expected 2 supplemental artifacts, got {len(supplements)}")
    return supplements


def parse_bundle_members(amendment: bytes) -> list[str]:
    lines = amendment.decode("utf-8").splitlines()
    try:
        intro = next(
            index
            for index, line in enumerate(lines)
            if line.startswith("The bundle members are the rows of this table;")
        )
    except StopIteration as exc:
        raise ValueError("missing bundle-member table") from exc
    index = intro + 1
    while index < len(lines) and lines[index] != "| Bundle member | Derivation |":
        index += 1
    if index == len(lines):
        raise ValueError("missing bundle-member table header")
    index += 2
    members: list[str] = []
    while index < len(lines) and lines[index].startswith("|"):
        match = BUNDLE_ROW.fullmatch(lines[index])
        if not match:
            raise ValueError(f"malformed bundle-member row at line {index + 1}")
        path = match.group(1)
        if path in members:
            raise ValueError(f"duplicate bundle member {path}")
        members.append(path)
        index += 1
    if not members:
        raise ValueError("empty bundle-member table")
    return members


def validate_authority_path(path: str) -> None:
    if unicodedata.normalize("NFC", path) != path or not SAFE_PATH.fullmatch(path):
        raise ValueError(f"unsafe authority path {path!r}")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"unsafe authority path segment in {path!r}")
    encoded = path.encode("utf-8")
    if len(encoded) > 255:
        raise ValueError(f"authority path exceeds 255 bytes: {path!r}")
    if any(byte < 0x20 or 0x7F <= byte <= 0x9F for byte in encoded):
        raise ValueError(f"control byte in authority path {path!r}")


def resolve_local_authority_link(source_path: str, target: str) -> str | None:
    if "://" in target:
        return None
    target_path = target.split("#", 1)[0]
    if (
        target_path.startswith("/")
        or "%" in target_path
        or "\\" in target_path
        or unicodedata.normalize("NFC", target_path) != target_path
        or not SAFE_LOCAL_MD_TARGET.fullmatch(target_path)
    ):
        raise ValueError(f"noncanonical local Markdown target {target!r}")
    parts = target_path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"unsafe local Markdown target segment in {target!r}")
    encoded = target_path.encode("utf-8")
    if any(byte < 0x20 or 0x7F <= byte <= 0x9F for byte in encoded):
        raise ValueError(f"control byte in local Markdown target {target!r}")
    resolved = posixpath.join(posixpath.dirname(source_path), target_path)
    validate_authority_path(resolved)
    return resolved


def reject_noncanonical_local_links(source_path: str, source_text: str) -> None:
    for noncanonical in (*REFERENCE_LINK.finditer(source_text), *AUTOLINK.finditer(source_text)):
        target = noncanonical.group(1)
        if "://" not in target:
            raise ValueError(
                f"noncanonical local Markdown link in {source_path}: {target!r}"
            )


def validate_operation_layout(rows: list[dict[str, object]]) -> str:
    ordered = sorted(rows, key=lambda row: (int(row["start"]), int(row["ordinal"])))
    grouped: dict[int, list[dict[str, object]]] = {}
    for row in ordered:
        grouped.setdefault(int(row["start"]), []).append(row)
    for offset, same_offset in grouped.items():
        if len(same_offset) > 1 and any(int(row["end"]) != offset for row in same_offset):
            raise ValueError("mixed insertion/replacement at same offset")
    cursor = 0
    operation_ids: list[str] = []
    for row in ordered:
        start = int(row["start"])
        end = int(row["end"])
        if start < cursor:
            raise ValueError("overlapping operation")
        cursor = end
        operation_ids.append(str(row["id"]))
    return ",".join(operation_ids)


def containing_heading(body: bytes, source_start: int) -> tuple[str, int, bytes]:
    cursor = 0
    found: tuple[str, int, bytes] | None = None
    for line in body.splitlines(keepends=True):
        if cursor >= source_start:
            break
        heading_bytes = line.removesuffix(b"\n")
        if re.fullmatch(rb"#{1,6} .+", heading_bytes):
            found = (heading_bytes.decode("utf-8"), cursor, heading_bytes)
        cursor += len(line)
    if found is None:
        raise ValueError(f"no containing heading before byte {source_start}")
    return found


def section_extent(body: bytes, heading_start: int, heading_bytes: bytes) -> tuple[int, int]:
    heading_level = len(heading_bytes) - len(heading_bytes.lstrip(b"#"))
    line_end = body.find(b"\n", heading_start)
    section_start = len(body) if line_end < 0 else line_end + 1
    cursor = section_start
    section_end = len(body)
    for line in body[section_start:].splitlines(keepends=True):
        candidate = line.removesuffix(b"\n")
        match = re.fullmatch(rb"(#{1,6}) .+", candidate)
        if match and len(match.group(1)) <= heading_level:
            section_end = cursor
            break
        cursor += len(line)
    return section_start, section_end


def exercise_section_case(case: dict[str, object]) -> str:
    body = str(case["body"]).encode("utf-8")
    source = str(case["source"]).encode("utf-8")
    expected_heading = str(case["heading"])
    occurrences = occurrence_count(body, source)
    if occurrences != 1:
        raise ValueError(f"source occurs {occurrences} times")
    source_start = body.find(source)
    source_end = source_start + len(source)
    heading, heading_start, heading_bytes = containing_heading(body, source_start)
    if heading != expected_heading:
        raise ValueError(f"heading {heading!r} != {expected_heading!r}")
    heading_occurrences = sum(
        line.removesuffix(b"\n") == heading_bytes
        for line in body.splitlines(keepends=True)
    )
    if heading_occurrences != 1:
        raise ValueError(f"heading occurs {heading_occurrences} times")
    if any(re.fullmatch(rb"#{1,6} .+", line) for line in source.splitlines()):
        raise ValueError("source contains an ATX heading")
    section_start, section_end = section_extent(body, heading_start, heading_bytes)
    if source_start < section_start or source_end > section_end:
        raise ValueError("source crosses section extent")
    return "contained"


def run_self_test_corpus(path: Path) -> dict[str, object]:
    corpus_bytes = path.read_bytes()
    corpus = json.loads(corpus_bytes)
    if corpus.get("schema") != "guildhall-materializer-adversarial-corpus/1":
        raise ValueError("wrong self-test corpus schema")
    results: list[dict[str, str]] = []
    for raw_case in corpus["cases"]:
        case = dict(raw_case)
        case_id = str(case["id"])
        try:
            kind = case["kind"]
            if kind == "quoted":
                value = quoted_block([str(line) for line in case["lines"]], 0)[0].hex()
            elif kind == "document":
                validate_document_bytes(bytes.fromhex(str(case["hex"])), "document")
                value = "ok"
            elif kind == "path":
                validate_authority_path(str(case["path"]))
                value = "ok"
            elif kind == "path-repeat":
                candidate = (
                    str(case["prefix"])
                    + str(case["character"]) * int(case["count"])
                    + str(case["suffix"])
                )
                validate_authority_path(candidate)
                value = "ok"
            elif kind == "section":
                value = exercise_section_case(case)
            elif kind == "same-offset":
                rows = [dict(row) for row in case["rows"]]
                if len(rows) > 1 and any(
                    int(row["end"]) != int(row["start"]) for row in rows
                ):
                    raise ValueError("mixed insertion/replacement at same offset")
                value = "ok"
            elif kind == "operation-layout":
                value = validate_operation_layout([dict(row) for row in case["rows"]])
            elif kind == "seam-recount":
                body = (
                    str(case["left"]) + str(case["new"]) + str(case["right"])
                ).encode("utf-8")
                value = str(occurrence_count(body, str(case["needle"]).encode("utf-8")))
            elif kind == "link-target":
                resolved = resolve_local_authority_link(
                    str(case["source"]), str(case["target"])
                )
                value = "external" if resolved is None else resolved
            elif kind == "link-document":
                reject_noncanonical_local_links(
                    str(case["source"]), str(case["document"])
                )
                value = "ok"
            elif kind == "insertion":
                anchor = str(case["anchor"]).encode("utf-8")
                if not anchor.endswith(b"\n"):
                    raise ValueError("insertion anchor must end LF")
                value = (anchor + str(case["new"]).encode("utf-8")).hex()
            else:
                raise ValueError(f"unknown self-test kind {kind}")
            status = "ok"
            error = ""
        except (KeyError, TypeError, ValueError) as exc:
            status = "error"
            value = ""
            error = str(exc)

        if status != case["expected_status"]:
            raise ValueError(f"{case_id}: status {status} != {case['expected_status']}")
        if "expected_value" in case and value != case["expected_value"]:
            raise ValueError(f"{case_id}: value {value!r} != {case['expected_value']!r}")
        if "expected_error_contains" in case and str(case["expected_error_contains"]) not in error:
            raise ValueError(f"{case_id}: missing expected error fragment in {error!r}")
        results.append({"id": case_id, "status": status})
    return {
        "schema": "guildhall-materializer-adversarial-result/1",
        "corpus_sha256": sha256(corpus_bytes),
        "case_count": len(results),
        "cases": results,
    }


def materialize(
    root: Path, amendment_path: Path, manifest_path: Path
) -> tuple[dict[str, bytes], dict[str, object]]:
    amendment = amendment_path.read_bytes()
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    expected = {item["path"]: item["sha256"] for item in manifest["artifacts"]}
    operations = parse_operations(amendment)
    supplements = parse_supplements(amendment)
    bundle_members = parse_bundle_members(amendment)

    for operation in operations:
        for other in operations:
            if operation.operation_id != other.operation_id and other.source in operation.new:
                raise ValueError(
                    f"{operation.operation_id}: new bytes contain {other.operation_id} source"
                )

    base: dict[str, bytes] = {}
    for path, digest in expected.items():
        validate_authority_path(path)
        body = (root / path).read_bytes()
        validate_document_bytes(body, f"base {path}")
        actual = sha256(body)
        if actual != digest:
            raise ValueError(f"base digest mismatch for {path}: {actual} != {digest}")
        base[path] = body

    supplemental_bodies: dict[str, bytes] = {}
    for path, expected_digest in supplements.items():
        validate_authority_path(path)
        if path in base:
            raise ValueError(f"supplement duplicates base path {path}")
        body = (root / path).read_bytes()
        validate_document_bytes(body, f"supplement {path}")
        if sha256(body) != expected_digest:
            raise ValueError(f"supplement digest mismatch for {path}")
        supplemental_bodies[path] = body

    resolved: list[dict[str, object]] = []
    by_path: dict[str, list[dict[str, object]]] = {}
    for operation in operations:
        if operation.path not in base:
            raise ValueError(f"{operation.operation_id}: target not in base manifest")
        body = base[operation.path]
        occurrences = occurrence_count(body, operation.source)
        if occurrences != 1:
            raise ValueError(
                f"{operation.operation_id}: source occurs {occurrences} times in {operation.path}"
            )
        source_start = body.find(operation.source)
        source_end = source_start + len(operation.source)
        heading, heading_start, heading_bytes = containing_heading(body, source_start)
        if heading != operation.containing_heading:
            raise ValueError(
                f"{operation.operation_id}: heading {heading!r} != {operation.containing_heading!r}"
            )
        heading_occurrences = sum(
            line.removesuffix(b"\n") == heading_bytes
            for line in body.splitlines(keepends=True)
        )
        if heading_occurrences != 1:
            raise ValueError(
                f"{operation.operation_id}: heading occurs {heading_occurrences} times"
            )
        if any(
            re.fullmatch(rb"#{1,6} .+", line)
            for line in operation.source.splitlines()
        ):
            raise ValueError(f"{operation.operation_id}: source contains an ATX heading")
        section_start, section_end = section_extent(body, heading_start, heading_bytes)
        if source_start < section_start or source_end > section_end:
            raise ValueError(
                f"{operation.operation_id}: source range crosses declared section extent"
            )
        start = source_start if operation.mode == "replace" else source_end
        end = source_end if operation.mode == "replace" else source_end
        context_start = max(0, source_start - 200)
        context_end = min(len(body), source_end + 200)
        context = body[context_start:context_end]
        row: dict[str, object] = {
            "id": operation.operation_id,
            "ordinal": operation.ordinal,
            "mode": operation.mode,
            "path": operation.path,
            "containing_heading": heading,
            "heading_start": heading_start,
            "heading_sha256": sha256(heading_bytes),
            "heading_occurrences_in_raw_base": heading_occurrences,
            "section_start": section_start,
            "section_end": section_end,
            "context_start": context_start,
            "context_end": context_end,
            "context_sha256": sha256(context),
            "context_base64": base64.b64encode(context).decode("ascii"),
            "base_sha256": sha256(body),
            "source_start": source_start,
            "source_end": source_end,
            "write_start": start,
            "write_end": end,
            "base_byte_before_write_hex": body[start - 1 : start].hex() if start else None,
            "base_byte_after_write_hex": body[end : end + 1].hex() if end < len(body) else None,
            "new_first_byte_hex": operation.new[:1].hex() if operation.new else None,
            "new_last_byte_hex": operation.new[-1:].hex() if operation.new else None,
            "source_sha256": sha256(operation.source),
            "source_bytes": len(operation.source),
            "source_base64": base64.b64encode(operation.source).decode("ascii"),
            "new_sha256": sha256(operation.new),
            "new_bytes": len(operation.new),
            "new_base64": base64.b64encode(operation.new).decode("ascii"),
            "occurrences_in_raw_base": occurrences,
            "new_body": operation.new,
        }
        resolved.append(row)
        by_path.setdefault(operation.path, []).append(row)

    effective = dict(base)
    for path, rows in by_path.items():
        rows.sort(key=lambda row: (int(row["write_start"]), int(row["ordinal"])))
        grouped: dict[int, list[dict[str, object]]] = {}
        for row in rows:
            grouped.setdefault(int(row["write_start"]), []).append(row)
        for offset, same_offset in grouped.items():
            if len(same_offset) > 1 and any(
                int(row["write_end"]) != offset for row in same_offset
            ):
                raise ValueError(f"mixed insertion/replacement at {path}:{offset}")

        cursor = 0
        chunks: list[bytes] = []
        for row in rows:
            start = int(row["write_start"])
            end = int(row["write_end"])
            if start < cursor:
                raise ValueError(f"overlapping operation {row['id']} in {path}")
            chunks.append(base[path][cursor:start])
            chunks.append(row["new_body"])  # type: ignore[arg-type]
            cursor = end
        chunks.append(base[path][cursor:])
        effective[path] = b"".join(chunks)

    for operation, row in zip(operations, resolved):
        body = effective[operation.path]
        source_occurrences = occurrence_count(body, operation.source)
        expected_source_occurrences = 0 if operation.mode == "replace" else 1
        if source_occurrences != expected_source_occurrences:
            raise ValueError(
                f"{operation.operation_id}: source occurs {source_occurrences} times "
                f"after materialization; expected {expected_source_occurrences}"
            )
        heading_bytes = operation.containing_heading.encode("utf-8")
        heading_occurrences = sum(
            line.removesuffix(b"\n") == heading_bytes
            for line in body.splitlines(keepends=True)
        )
        if heading_occurrences != 1:
            raise ValueError(
                f"{operation.operation_id}: heading occurs {heading_occurrences} times "
                "after materialization"
            )
        row["source_occurrences_in_effective"] = source_occurrences
        row["heading_occurrences_in_effective"] = heading_occurrences

    # Bind the non-overlay generation controls in the amendment into the same
    # authority bundle consumed by downstream roles.
    effective.update(supplemental_bodies)
    effective[str(amendment_path.relative_to(root))] = amendment

    if set(bundle_members) != set(effective) or len(bundle_members) != len(effective):
        raise ValueError(
            "bundle-member table disagrees with materialized artifact census"
        )

    markdown_links: list[dict[str, str]] = []
    for source_path in sorted(effective, key=lambda value: value.encode("utf-8")):
        source_text = effective[source_path].decode("utf-8")
        reject_noncanonical_local_links(source_path, source_text)
        for link_match in MARKDOWN_LINK.finditer(source_text):
            target = link_match.group(1)
            resolved_target = resolve_local_authority_link(source_path, target)
            if resolved_target is None:
                continue
            if resolved_target not in effective:
                raise ValueError(
                    f"unbound Markdown authority link {source_path} -> {resolved_target}"
                )
            markdown_links.append({"source": source_path, "target": resolved_target})

    for path in effective:
        validate_authority_path(path)
    artifact_rows = [
        {"path": path, "sha256": sha256(effective[path]), "bytes": len(effective[path])}
        for path in sorted(effective, key=lambda value: value.encode("utf-8"))
    ]
    if len(artifact_rows) != len(bundle_members):
        raise ValueError(
            f"authority bundle count {len(artifact_rows)} != table count {len(bundle_members)}"
        )
    root_bytes = (
        f"guildhall-authority-bundle-v1\nartifact-count\t{len(artifact_rows)}\n"
        + "".join(
        f"{row['path']}\t{row['sha256']}\n" for row in artifact_rows
        )
    ).encode("utf-8")
    for row in resolved:
        row.pop("new_body")

    receipt: dict[str, object] = {
        "schema": "guildhall-amendment-overlay/1",
        "algorithm": "raw UTF-8/LF base offsets; declaration IDs; ascending-offset stream",
        "amendment_path": str(amendment_path.relative_to(root)),
        "amendment_sha256": sha256(amendment),
        "base_manifest_path": str(manifest_path.relative_to(root)),
        "base_manifest_sha256": sha256(manifest_bytes),
        "operations": resolved,
        "supplements": [
            {"path": path, "sha256": supplements[path]}
            for path in sorted(supplements, key=lambda value: value.encode("utf-8"))
        ],
        "bundle_members": bundle_members,
        "markdown_authority_links": markdown_links,
        "artifacts": artifact_rows,
        "bundle_root_method": "sha256(guildhall-authority-bundle-v1 LF, artifact-count TAB N LF, then path TAB artifact_sha256 LF; NFC-safe paths sorted by raw UTF-8 bytes)",
        "bundle_root_sha256": sha256(root_bytes),
    }
    return effective, receipt


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--amendment", default="spec/amendment-001-rust-vast.md")
    parser.add_argument("--manifest", default="spec/ratification-manifest.json")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--self-test-corpus", type=Path)
    args = parser.parse_args()

    if args.self_test_corpus is not None:
        print(json.dumps(run_self_test_corpus(args.self_test_corpus), sort_keys=True))
        return
    if args.out is None or args.receipt is None:
        parser.error("--out and --receipt are required unless --self-test-corpus is used")

    root = args.root.resolve()
    effective, receipt = materialize(root, root / args.amendment, root / args.manifest)
    args.out.mkdir(parents=True, exist_ok=True)
    for path, body in effective.items():
        (args.out / Path(path).name).write_bytes(body)
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(receipt["bundle_root_sha256"])


if __name__ == "__main__":
    main()
