#!/usr/bin/env python3
"""Generate DATA_QUALITY.md at the repo root.

The report summarises the shape and freshness of every on-disk data
source the scanners and lookup tools consume:

  * malicious-packages JSON per ecosystem
  * typosquat-db/known_typosquats.json
  * vulnerabilities/osv/<ecosystem>/index.json
  * vulnerabilities/cve/code-relevant/cve_patterns.json
  * manifest.json (signature + file count)

The report is deliberately Markdown so it's diffable in a PR and
renderable on GitHub without extra tooling. CI re-runs this script
and fails if the committed DATA_QUALITY.md is out of date — that
keeps the figures honest as the corpus grows.

Usage
-----
    python3 scripts/generate-data-quality.py            # write DATA_QUALITY.md
    python3 scripts/generate-data-quality.py --check    # exit 1 if stale

The CLI surface is deliberately small; downstream callers that want
to embed the figures in another document should read the JSON
sources directly rather than scraping the generated Markdown.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = REPO_ROOT / "DATA_QUALITY.md"

# Anything older than FRESHNESS_WARN_DAYS gets a ⚠️ in the freshness
# column. The threshold is deliberately tight — the OSV cache is
# refreshed weekly and the curated databases are touched on every
# advisory cut, so 30 days of staleness signals that the refresh
# automation has stopped running.
FRESHNESS_WARN_DAYS = 30


def _read_json(path: Path) -> dict | list | None:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as exc:
        print(f"warning: {path}: {exc}", file=sys.stderr)
        return None


def _parse_iso(value: str) -> dt.datetime | None:
    """Parse an ISO-8601 date or datetime; return None on failure."""
    if not value:
        return None
    value = value.strip()
    # The corpus mixes "2026-05-14" and "2026-05-14T16:01:44Z" forms.
    # We normalise to UTC-naive datetimes so the age math below stays
    # straightforward.
    try:
        if "T" in value:
            return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
                dt.timezone.utc
            ).replace(tzinfo=None)
        return dt.datetime.fromisoformat(value)
    except ValueError:
        return None


def _age_days(ts: dt.datetime | None, now: dt.datetime) -> int | None:
    if ts is None:
        return None
    return (now - ts).days


def _ref_coverage(entries: list[dict]) -> tuple[int, int]:
    """Return (with_refs, total) for an iterable of dict-shaped entries.

    An entry counts as referenced when it carries at least one
    non-empty URL in its `references` array. Empty strings are
    treated as missing so a placeholder row does not inflate the
    coverage percentage.
    """
    total = len(entries)
    with_refs = sum(
        1
        for e in entries
        if any(str(r).strip() for r in (e.get("references") or []))
    )
    return with_refs, total


def _malicious_per_eco(now: dt.datetime) -> list[dict]:
    rows: list[dict] = []
    dirpath = REPO_ROOT / "vulnerabilities" / "supply-chain" / "malicious-packages"
    for path in sorted(dirpath.glob("*.json")):
        data = _read_json(path) or {}
        entries = data.get("entries") or []
        curated = sum(1 for e in entries if not (e.get("source") or "").strip())
        ossf = sum(
            1
            for e in entries
            if (e.get("source") or "").strip() == "ossf-malicious-packages"
        )
        other = len(entries) - curated - ossf
        with_refs, total = _ref_coverage(entries)
        last_updated = _parse_iso(data.get("last_updated") or "")
        rows.append(
            {
                "ecosystem": data.get("ecosystem") or path.stem,
                "path": path.relative_to(REPO_ROOT).as_posix(),
                "entries": total,
                "curated": curated,
                "ossf": ossf,
                "other": other,
                "with_refs": with_refs,
                "last_updated": last_updated,
                "age_days": _age_days(last_updated, now),
            }
        )
    return rows


def _typosquat_summary(now: dt.datetime) -> dict:
    path = (
        REPO_ROOT
        / "vulnerabilities"
        / "supply-chain"
        / "typosquat-db"
        / "known_typosquats.json"
    )
    data = _read_json(path) or {}
    entries = data.get("entries") or []
    by_source: dict[str, int] = {}
    for e in entries:
        key = (e.get("source") or "").strip() or "curated"
        by_source[key] = by_source.get(key, 0) + 1
    with_refs, total = _ref_coverage(entries)
    last_updated = _parse_iso(data.get("last_updated") or "")
    return {
        "path": path.relative_to(REPO_ROOT).as_posix(),
        "entries": total,
        "by_source": by_source,
        "with_refs": with_refs,
        "last_updated": last_updated,
        "age_days": _age_days(last_updated, now),
    }


def _osv_per_eco(now: dt.datetime) -> list[dict]:
    rows: list[dict] = []
    base = REPO_ROOT / "vulnerabilities" / "osv"
    for index_path in sorted(base.glob("*/index.json")):
        data = _read_json(index_path) or {}
        by_pkg = data.get("by_package") or {}
        n_advisories = sum(len(v) for v in by_pkg.values())
        generated_at = _parse_iso(data.get("generated_at") or "")
        last_updated = _parse_iso(data.get("last_updated") or "") or generated_at
        rows.append(
            {
                "ecosystem": index_path.parent.name,
                "path": index_path.relative_to(REPO_ROOT).as_posix(),
                "advisories": n_advisories,
                "packages": len(by_pkg),
                "generated_at": generated_at,
                "last_updated": last_updated,
                "age_days": _age_days(last_updated, now),
            }
        )
    return rows


def _cve_summary(now: dt.datetime) -> dict:
    path = REPO_ROOT / "vulnerabilities" / "cve" / "code-relevant" / "cve_patterns.json"
    data = _read_json(path) or {}
    entries = data.get("entries") or []
    with_refs, total = _ref_coverage(entries)
    last_updated = _parse_iso(data.get("last_updated") or "")
    return {
        "path": path.relative_to(REPO_ROOT).as_posix(),
        "entries": total,
        "with_refs": with_refs,
        "last_updated": last_updated,
        "age_days": _age_days(last_updated, now),
    }


def _manifest_summary() -> dict:
    path = REPO_ROOT / "manifest.json"
    data = _read_json(path) or {}
    sig = (data.get("signature") or "").strip()
    return {
        "path": "manifest.json",
        "version": data.get("version") or "",
        "released_at": data.get("released_at") or "",
        "files": len(data.get("files") or []),
        "signature": sig,
        "signed": bool(sig) and sig.upper() != "TBD",
    }


def _fmt_date(ts: dt.datetime | None) -> str:
    if ts is None:
        return "—"
    return ts.strftime("%Y-%m-%d")


def _fmt_freshness(age_days: int | None) -> str:
    if age_days is None:
        return "—"
    if age_days > FRESHNESS_WARN_DAYS:
        return f"{age_days}d ⚠️"
    return f"{age_days}d"


def _pct(num: int, denom: int) -> str:
    if denom == 0:
        return "—"
    return f"{(100 * num / denom):.1f}%"


def render(now: dt.datetime) -> str:
    malicious = _malicious_per_eco(now)
    typosquat = _typosquat_summary(now)
    osv = _osv_per_eco(now)
    cve = _cve_summary(now)
    manifest = _manifest_summary()

    total_malicious = sum(r["entries"] for r in malicious)
    total_curated = sum(r["curated"] for r in malicious)
    total_ossf = sum(r["ossf"] for r in malicious)
    total_osv = sum(r["advisories"] for r in osv)

    lines: list[str] = []
    lines.append("# Data quality report")
    lines.append("")
    lines.append(
        "Auto-generated by `scripts/generate-data-quality.py`. Re-run after any"
        " change to the on-disk vulnerability or skills data; CI fails if the"
        " committed file is out of date."
    )
    lines.append("")
    lines.append(f"_Generated: {now.strftime('%Y-%m-%d %H:%M UTC')}_")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Source | Entries | Curated | Derived (OSSF) | Last updated |")
    lines.append("|---|---:|---:|---:|---|")
    lines.append(
        f"| malicious-packages | {total_malicious} | {total_curated} | {total_ossf} | "
        f"{_fmt_date(max((r['last_updated'] for r in malicious if r['last_updated']), default=None))} |"
    )
    lines.append(
        f"| typosquat-db | {typosquat['entries']} |"
        f" {typosquat['by_source'].get('curated', 0)} |"
        f" {typosquat['by_source'].get('ossf-malicious-packages-derived', 0)} |"
        f" {_fmt_date(typosquat['last_updated'])} |"
    )
    lines.append(
        f"| osv (sampled) | {total_osv} | — | {total_osv} |"
        f" {_fmt_date(max((r['last_updated'] for r in osv if r['last_updated']), default=None))} |"
    )
    lines.append(
        f"| cve-patterns | {cve['entries']} | {cve['entries']} | 0 | {_fmt_date(cve['last_updated'])} |"
    )
    lines.append("")

    # Per-ecosystem malicious-packages breakdown.
    lines.append("## Malicious packages by ecosystem")
    lines.append("")
    lines.append(
        "| Ecosystem | Entries | Curated | OSSF-derived | Other | "
        "Reference coverage | Last updated | Age |"
    )
    lines.append("|---|---:|---:|---:|---:|---:|---|---:|")
    for r in malicious:
        lines.append(
            "| {eco} | {n} | {c} | {o} | {x} | {ref} | {date} | {age} |".format(
                eco=r["ecosystem"],
                n=r["entries"],
                c=r["curated"],
                o=r["ossf"],
                x=r["other"],
                ref=_pct(r["with_refs"], r["entries"]),
                date=_fmt_date(r["last_updated"]),
                age=_fmt_freshness(r["age_days"]),
            )
        )
    lines.append("")

    # Typosquat-db breakdown.
    lines.append("## Typosquat database")
    lines.append("")
    by_src = typosquat["by_source"]
    lines.append(
        f"- File: `{typosquat['path']}`"
    )
    lines.append(f"- Entries: **{typosquat['entries']}**")
    if by_src:
        parts = ", ".join(f"`{k}`: {v}" for k, v in sorted(by_src.items()))
        lines.append(f"- By source: {parts}")
    lines.append(
        f"- Reference coverage: {_pct(typosquat['with_refs'], typosquat['entries'])}"
    )
    lines.append(
        f"- Last updated: {_fmt_date(typosquat['last_updated'])}"
        f" ({_fmt_freshness(typosquat['age_days'])})"
    )
    lines.append("")

    # OSV cache: SAMPLED is bolded so reviewers don't mistake the
    # cache count for full OSV coverage.
    lines.append("## OSV cache (SAMPLED)")
    lines.append("")
    lines.append(
        "> **SAMPLED.** This repo ships a stride-sampled subset of each"
        " ecosystem's OSV archive so the tree stays reviewable. The current"
        " sample target is set by `scripts/ingest-osv.py --per-ecosystem`"
        " (default 500). Operators who need full coverage should re-run with"
        " `--per-ecosystem 0`."
    )
    lines.append("")
    lines.append(
        "| Ecosystem | Advisories | Packages indexed | Generated at | Age |"
    )
    lines.append("|---|---:|---:|---|---:|")
    for r in osv:
        lines.append(
            "| {eco} | {adv} | {pkg} | {gen} | {age} |".format(
                eco=r["ecosystem"],
                adv=r["advisories"],
                pkg=r["packages"],
                gen=_fmt_date(r["generated_at"]),
                age=_fmt_freshness(r["age_days"]),
            )
        )
    lines.append("")

    # CVE patterns.
    lines.append("## CVE patterns (code-relevant)")
    lines.append("")
    lines.append(f"- File: `{cve['path']}`")
    lines.append(f"- Entries: **{cve['entries']}**")
    lines.append(
        f"- Reference coverage: {_pct(cve['with_refs'], cve['entries'])}"
    )
    lines.append(
        f"- Last updated: {_fmt_date(cve['last_updated'])}"
        f" ({_fmt_freshness(cve['age_days'])})"
    )
    lines.append("")

    # Manifest integrity.
    lines.append("## Manifest integrity")
    lines.append("")
    sig_state = "signed" if manifest["signed"] else "**unsigned (TBD)**"
    lines.append(f"- File: `manifest.json`")
    lines.append(f"- Release version: `{manifest['version']}`")
    lines.append(f"- Released at: {manifest['released_at'] or '—'}")
    lines.append(f"- Files indexed: {manifest['files']}")
    lines.append(f"- Signature: {sig_state}")
    if not manifest["signed"]:
        lines.append("")
        lines.append(
            "> Releases prior to the first signed cut ship with"
            " `\"signature\": \"TBD\"`. Verify the on-disk bundle with"
            " `skills-check manifest verify --checksums-only` against the"
            " committed `manifest.json`."
        )
    lines.append("")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Exit non-zero if the generated DATA_QUALITY.md differs from the"
            " committed copy. Used in CI to enforce regeneration."
        ),
    )
    parser.add_argument(
        "--now",
        default="",
        help=(
            "Override the 'generated at' timestamp (ISO-8601). Tests use this"
            " to keep golden output stable."
        ),
    )
    args = parser.parse_args(argv)

    now_str = args.now or dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    now = _parse_iso(now_str) or dt.datetime.utcnow()
    body = render(now)
    if args.check:
        if not OUTPUT_PATH.exists():
            print(
                f"DATA_QUALITY.md does not exist; run scripts/generate-data-quality.py",
                file=sys.stderr,
            )
            return 1
        existing = OUTPUT_PATH.read_text()
        # Compare everything except the "_Generated: ...Z_" line because
        # that one mutates every run; CI cares about the structural
        # contents, not the timestamp.
        def _strip_timestamp(text: str) -> str:
            return "\n".join(
                line for line in text.splitlines() if not line.startswith("_Generated:")
            )

        if _strip_timestamp(existing) != _strip_timestamp(body):
            print(
                "DATA_QUALITY.md is out of date; run scripts/generate-data-quality.py and commit",
                file=sys.stderr,
            )
            return 1
        return 0
    OUTPUT_PATH.write_text(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
