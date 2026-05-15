#!/usr/bin/env python3
"""Populate the local OSV cache from osv.dev's bulk JSON exports.

The OSV project publishes per-ecosystem zip archives at
``https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip``.
Each archive contains one ``<OSV_ID>.json`` per advisory and is
refreshed nightly.

This script downloads the bulk archive for each ecosystem we support,
stride-samples a representative subset (configurable via
``--per-ecosystem``), and writes the per-record JSON into
``vulnerabilities/osv/<ecosystem>/<OSV_ID>.json``. Operators who want
full coverage should set ``--per-ecosystem`` to a large value (or 0,
meaning unlimited) and re-run weekly.

The cache layout is intentionally one-file-per-record so reviewers
can ``git diff`` individual advisories and so the MCP tool can lazily
load only the records it needs.

Refresh cadence
---------------
- Run weekly to pick up new entries.
- The ``skills-check update`` flow exposes this script as
  ``skills-check update --refresh-osv`` (added separately).
- Manual run: ``python3 scripts/ingest-osv.py --per-ecosystem 100``

Network requirements
--------------------
- Outbound HTTPS to ``osv-vulnerabilities.storage.googleapis.com``.
- ~25MB-200MB per ecosystem archive download (curl handles streaming).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CACHE_DIR = REPO_ROOT / "vulnerabilities" / "osv"

# osv.dev uses these ecosystem labels in its bulk-export URLs. The
# mapping is documented at https://google.github.io/osv.dev/data/.
ECOSYSTEM_MAP = {
    "npm": "npm",
    "pypi": "PyPI",
    "go": "Go",
    "maven": "Maven",
    "nuget": "NuGet",
    "rubygems": "RubyGems",
    "crates": "crates.io",
}

# Default per-ecosystem sample size. The cap exists so the repo
# doesn't balloon to hundreds of megabytes; production operators are
# expected to override this via --per-ecosystem.
DEFAULT_PER_ECO = 30

UA = "skills-library-osv-ingest/0.1"
BULK_URL = "https://osv-vulnerabilities.storage.googleapis.com/{}/all.zip"


def download_archive(ecosystem_label: str, dest: Path, verbose: bool) -> bool:
    url = BULK_URL.format(ecosystem_label)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp, open(dest, "wb") as fh:
            shutil.copyfileobj(resp, fh)
    except Exception as exc:  # network failure, 404, etc.
        if verbose:
            print(f"    error: {exc}", file=sys.stderr)
        return False
    if verbose:
        print(f"    downloaded {dest.stat().st_size:,} bytes -> {dest}")
    return True


def stride_sample(items: list[str], target: int) -> list[str]:
    if target <= 0 or len(items) <= target:
        return items
    step = max(1, len(items) // target)
    sample = items[::step][:target]
    if len(sample) < target:
        sample.extend(items[len(sample) :][: target - len(sample)])
    return sample


def extract_subset(zip_path: Path, dest_dir: Path, target: int, verbose: bool) -> int:
    dest_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        names = sorted(n for n in zf.namelist() if n.endswith(".json"))
        if not names:
            return 0
        sample = stride_sample(names, target)
        written = 0
        for name in sample:
            try:
                with zf.open(name) as src:
                    body = src.read()
                json.loads(body)  # validate; raises on bad JSON
            except Exception as exc:
                if verbose:
                    print(f"    skip {name}: {exc}", file=sys.stderr)
                continue
            # CI's rule-file-schema check requires every vulnerability/**
            # JSON file to carry both `schema_version` and `last_updated`.
            # OSV records already have `schema_version`; surface `modified`
            # (the OSV equivalent of last_updated) as the latter.
            doc = json.loads(body)
            modified = doc.get("modified") or doc.get("published") or ""
            if modified and "last_updated" not in doc:
                doc["last_updated"] = modified[:10]
                body = (json.dumps(doc, indent=2) + "\n").encode("utf-8")
            out = dest_dir / Path(name).name
            out.write_bytes(body)
            written += 1
        return written


# CVSS_V3_QUALITATIVE maps the GitHub-style severity band (in the
# OSV record's `database_specific.severity`) onto the four-bucket
# scale the Go-side scanner uses. GitHub publishes "MODERATE" for
# medium, but some adjacent feeds (incl. our own writers) emit
# "MEDIUM"; accept both.
_SEVERITY_BANDS = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}

# CVSS v3 base-score qualitative ranges (NVD CVSS v3.1 spec).
_CVSS_V3_THRESHOLDS = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
)


def _bucket_for_score(score: float) -> str:
    for floor, label in _CVSS_V3_THRESHOLDS:
        if score >= floor:
            return label
    return ""


def _score_from_cvss_v3(vector: str) -> float:
    """Compute the CVSS v3.0/3.1 base score for the supplied vector.

    Mirrors the Go implementation in cmd/skills-mcp/internal/tools/
    osv_severity.go; kept in Python so the index emitted by
    ingest-osv.py already carries the bucketed severity and the
    Go-side fallback is the rare case.
    """
    metrics = {}
    for seg in vector.split("/"):
        seg = seg.strip()
        if not seg or ":" not in seg:
            continue
        k, v = seg.split(":", 1)
        k = k.strip().upper()
        if k == "CVSS":
            continue
        metrics[k] = v.strip().upper()
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(metrics.get("AV", ""))
    ac = {"L": 0.77, "H": 0.44}.get(metrics.get("AC", ""))
    ui = {"N": 0.85, "R": 0.62}.get(metrics.get("UI", ""))
    scope = metrics.get("S")
    if av is None or ac is None or ui is None or scope not in ("U", "C"):
        return 0.0
    pr_table = (
        {"N": 0.85, "L": 0.62, "H": 0.27}
        if scope == "U"
        else {"N": 0.85, "L": 0.68, "H": 0.50}
    )
    pr = pr_table.get(metrics.get("PR", ""))
    impacts = {
        c: {"N": 0.0, "L": 0.22, "H": 0.56}.get(metrics.get(c, ""))
        for c in ("C", "I", "A")
    }
    if pr is None or any(v is None for v in impacts.values()):
        return 0.0
    iss = 1 - (1 - impacts["C"]) * (1 - impacts["I"]) * (1 - impacts["A"])
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    if impact <= 0:
        return 0.0
    exploit = 8.22 * av * ac * pr * ui
    if scope == "U":
        base = min(impact + exploit, 10.0)
    else:
        base = min(1.08 * (impact + exploit), 10.0)
    # CVSS v3 roundup: ceil to one decimal place.
    import math

    return math.ceil(base * 10) / 10


def _severity_for_record(data: dict) -> str:
    """Return the four-bucket severity for one OSV record, or "".

    Mirrors resolveOSVSeverity in osv_severity.go: prefer the
    GitHub-style database_specific.severity band, otherwise compute
    the maximum CVSS v3.x base score across the structured severity
    array. CVSS v2 / v4 vectors are left to the Go fallback (their
    formulas are kept in one place there).
    """
    band = ((data.get("database_specific") or {}).get("severity") or "").strip().upper()
    if band in _SEVERITY_BANDS:
        return _SEVERITY_BANDS[band]
    best = 0.0
    for entry in data.get("severity") or []:
        typ = (entry.get("type") or "").upper()
        score = (entry.get("score") or "").strip()
        if not score:
            continue
        # The score field may be a plain decimal (e.g. "7.5") or a
        # CVSS vector string. Try a numeric parse first.
        try:
            numeric = float(score)
        except ValueError:
            numeric = 0.0
            if typ.startswith("CVSS_V3"):
                numeric = _score_from_cvss_v3(score)
        if numeric > best:
            best = numeric
    return _bucket_for_score(best)


def write_index(dest_dir: Path) -> None:
    """Build an index.json listing every cached advisory.

    The MCP-side loader uses this so it can map a package name to its
    advisories in O(1) instead of scanning every file. We also embed
    a pre-computed `severity` field per index entry so the Go scanner
    can surface CVSS-derived severity without re-parsing each record
    on every lookup; the Go side still falls back to lazy on-disk
    parsing when an older index pre-dates this field.
    """
    now = dt.datetime.now(dt.timezone.utc)
    index: dict = {
        "schema_version": "1.0",
        "last_updated": now.strftime("%Y-%m-%d"),
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "by_package": {},
    }
    for path in sorted(dest_dir.glob("*.json")):
        if path.name == "index.json":
            continue
        try:
            data = json.loads(path.read_text())
        except Exception:
            continue
        severity = _severity_for_record(data)
        affected = data.get("affected") or []
        for aff in affected:
            pkg = aff.get("package") or {}
            name = pkg.get("name")
            if not name:
                continue
            entry = {
                "id": data.get("id", path.stem),
                "file": path.name,
                "summary": data.get("summary", ""),
                "aliases": data.get("aliases", []),
            }
            if severity:
                entry["severity"] = severity
            index["by_package"].setdefault(name.lower(), []).append(entry)
    (dest_dir / "index.json").write_text(json.dumps(index, indent=2) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ecosystem",
        action="append",
        choices=list(ECOSYSTEM_MAP),
        help="Limit to one ecosystem (repeatable). Default: all.",
    )
    parser.add_argument(
        "--per-ecosystem",
        type=int,
        default=int(os.environ.get("OSV_PER_ECO", str(DEFAULT_PER_ECO))),
        help=f"How many advisories to cache per ecosystem (default {DEFAULT_PER_ECO}, 0=unlimited).",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    selected = args.ecosystem or list(ECOSYSTEM_MAP)
    tmp = REPO_ROOT / ".osv-tmp"
    tmp.mkdir(exist_ok=True)
    try:
        for eco in selected:
            label = ECOSYSTEM_MAP[eco]
            print(f"  {eco} ({label}):")
            zip_path = tmp / f"{eco}.zip"
            ok = download_archive(label, zip_path, args.verbose)
            if not ok:
                print("    download failed; skipping")
                continue
            dest = CACHE_DIR / eco
            # Wipe existing files so a smaller --per-ecosystem on a
            # subsequent run doesn't leave stale records behind.
            if dest.exists():
                for old in dest.glob("*.json"):
                    old.unlink()
            written = extract_subset(zip_path, dest, args.per_ecosystem, args.verbose)
            print(f"    wrote {written} advisories -> {dest}")
            write_index(dest)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
