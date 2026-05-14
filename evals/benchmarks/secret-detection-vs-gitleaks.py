#!/usr/bin/env python3
"""Precision/recall benchmark for the `secret-detection` skill.

Reads skills/secret-detection/tests/corpus.json (the source-of-truth
fixture set) and evaluates two engines against it:

  1. skills-library DLP patterns (skills/secret-detection/rules/
     dlp_patterns.json), via the same regex+hotword logic the
     `skills-check test` runner uses.
  2. (optional) gitleaks v8 with its default ruleset — the most
     widely-deployed open-source secret scanner. The script will
     auto-detect the `gitleaks` binary on $PATH and run it in
     `--no-git --report-format json` mode against a temp file per
     fixture. If gitleaks is not installed the gitleaks columns are
     reported as "n/a" but the skills-library numbers still print.

Output: a Markdown table with TP/FP/FN/TN counts, precision, recall,
and F1 for each engine. Designed to be human-reviewable and to live
in a PR description.

Why not call the existing `skills-check test` Go binary? `test`
exits non-zero on the first failed fixture and does not emit a
machine-readable confusion matrix. Re-implementing the (small)
regex+hotword matcher in Python here keeps the harness dependency-
free and lets us compute precision/recall across every fixture in
one pass.

AI authorship disclosure: this harness was drafted with AI
assistance per AGENTS.md. The matching logic is a faithful
re-implementation of cmd/skills-check/cmd/test.go (see the
`matchAny`, `hotwordNear`, `denylisted` functions there) — any
divergence is a bug the human reviewer should flag.
"""

from __future__ import annotations

import argparse
import json
import math
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Iterable

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
CORPUS = ROOT / "skills/secret-detection/tests/corpus.json"
PATTERNS = ROOT / "skills/secret-detection/rules/dlp_patterns.json"


@dataclass
class CompiledPattern:
    name: str
    regex: re.Pattern[str]
    hotwords: list[str]
    hotword_window: int
    require_hotword: bool
    denylist: list[str]


def load_patterns() -> list[CompiledPattern]:
    raw = json.loads(PATTERNS.read_text())
    out: list[CompiledPattern] = []
    for p in raw["patterns"]:
        try:
            rx = re.compile(p["regex"])
        except re.error:
            # Mirror the Go runner's behaviour: skip patterns that
            # don't compile cleanly under this engine.
            continue
        out.append(
            CompiledPattern(
                name=p["name"],
                regex=rx,
                hotwords=p.get("hotwords") or [],
                hotword_window=p.get("hotword_window") or 80,
                require_hotword=bool(p.get("require_hotword")),
                denylist=p.get("denylist_substrings") or [],
            )
        )
    return out


def hotword_near(text: str, span: tuple[int, int], hotwords: list[str], window: int) -> bool:
    if window <= 0:
        window = 80
    start = max(0, span[0] - window)
    end = min(len(text), span[1] + window)
    region = text[start:end].lower()
    return any(h.lower() in region for h in hotwords)


def denylisted(match_text: str, denylist: list[str]) -> bool:
    lower = match_text.lower()
    return any(sub.lower() in lower for sub in denylist)


def skills_match(text: str, patterns: list[CompiledPattern]) -> bool:
    """Returns True iff at least one pattern fires on `text`,
    respecting hotwords and denylists. This is the same selection
    rule the Go runner uses; the per-pattern *name* doesn't matter
    for precision/recall, only the binary detect/ignore outcome."""
    for p in patterns:
        m = p.regex.search(text)
        if not m:
            continue
        if denylisted(m.group(0), p.denylist):
            continue
        if p.require_hotword or p.hotwords:
            if not hotword_near(text, m.span(), p.hotwords, p.hotword_window):
                if p.require_hotword:
                    continue
        return True
    return False


def gitleaks_match(text: str, binary: str) -> bool:
    """Run gitleaks once per fixture. Returns True iff gitleaks finds
    at least one leak. Slow (~50–100ms per call); only use when the
    binary is present and the user opted in."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write(text)
        tmp.flush()
        report = tmp.name + ".json"
    try:
        result = subprocess.run(
            [
                binary,
                "detect",
                "--no-git",
                "--source",
                tmp.name,
                "--report-format",
                "json",
                "--report-path",
                report,
                "--exit-code",
                "0",
                "--no-banner",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    finally:
        pathlib.Path(tmp.name).unlink(missing_ok=True)
    try:
        leaks = json.loads(pathlib.Path(report).read_text() or "[]")
    except (FileNotFoundError, json.JSONDecodeError):
        leaks = []
    pathlib.Path(report).unlink(missing_ok=True)
    return bool(leaks)


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else math.nan

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else math.nan

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        if math.isnan(p) or math.isnan(r) or (p + r) == 0:
            return math.nan
        return 2 * p * r / (p + r)


def score(fixtures: Iterable[dict], predict) -> Counts:
    c = Counts()
    for fx in fixtures:
        want = fx["expected"] == "detect"
        got = predict(fx["text"])
        if want and got:
            c.tp += 1
        elif want and not got:
            c.fn += 1
        elif (not want) and got:
            c.fp += 1
        else:
            c.tn += 1
    return c


def fmt_pct(x: float) -> str:
    return "n/a" if math.isnan(x) else f"{x * 100:.1f}%"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--gitleaks",
        default="auto",
        help="Path to gitleaks binary (default: auto-detect on $PATH; "
        "pass 'skip' to disable gitleaks even if installed).",
    )
    ap.add_argument(
        "--out",
        default="-",
        help="Output path for the markdown report (default: stdout).",
    )
    args = ap.parse_args()

    corpus = json.loads(CORPUS.read_text())
    fixtures = corpus["fixtures"]
    patterns = load_patterns()

    gitleaks_bin: str | None = None
    if args.gitleaks == "auto":
        gitleaks_bin = shutil.which("gitleaks")
    elif args.gitleaks != "skip":
        gitleaks_bin = args.gitleaks if shutil.which(args.gitleaks) else None

    skills_counts = score(fixtures, lambda t: skills_match(t, patterns))
    if gitleaks_bin:
        gitleaks_counts: Counts | None = score(
            fixtures, lambda t: gitleaks_match(t, gitleaks_bin)
        )
    else:
        gitleaks_counts = None

    tp = sum(1 for f in fixtures if f["expected"] == "detect")
    tn = sum(1 for f in fixtures if f["expected"] == "ignore")

    lines: list[str] = []
    lines.append("# secret-detection benchmark")
    lines.append("")
    lines.append(f"Corpus: `{CORPUS.relative_to(ROOT)}` ({len(fixtures)} fixtures: {tp} TP, {tn} TN)")
    lines.append("")
    lines.append(
        "> **Honesty note.** The skills-library DLP rule set is *tuned*\n"
        "> against this corpus — perfect or near-perfect numbers here\n"
        "> only show the rules cover their own test bed, not that they\n"
        "> will generalize. The gitleaks column is the more interesting\n"
        "> signal: it measures how a popular general-purpose ruleset\n"
        "> scores on shapes that the skills-library claims to handle.\n"
        "> Treat regressions in the gitleaks column as expected when\n"
        "> we add a new pattern that gitleaks does not know about, and\n"
        "> regressions in the skills-library column as a hard fail.\n"
    )
    lines.append("| engine | TP | FP | FN | TN | precision | recall | F1 |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    lines.append(
        "| skills-library DLP patterns | "
        f"{skills_counts.tp} | {skills_counts.fp} | {skills_counts.fn} | {skills_counts.tn} | "
        f"{fmt_pct(skills_counts.precision)} | {fmt_pct(skills_counts.recall)} | "
        f"{fmt_pct(skills_counts.f1)} |"
    )
    if gitleaks_counts is not None:
        lines.append(
            f"| gitleaks (default ruleset, `{gitleaks_bin}`) | "
            f"{gitleaks_counts.tp} | {gitleaks_counts.fp} | {gitleaks_counts.fn} | {gitleaks_counts.tn} | "
            f"{fmt_pct(gitleaks_counts.precision)} | {fmt_pct(gitleaks_counts.recall)} | "
            f"{fmt_pct(gitleaks_counts.f1)} |"
        )
    else:
        lines.append(
            "| gitleaks (default ruleset) | n/a | n/a | n/a | n/a | n/a | n/a | n/a |"
        )
        lines.append("")
        lines.append("> gitleaks not installed; pass `--gitleaks /path/to/gitleaks` to compare. ")
        lines.append("> Install via `go install github.com/gitleaks/gitleaks/v8@latest`.")

    body = "\n".join(lines) + "\n"
    if args.out == "-":
        sys.stdout.write(body)
    else:
        pathlib.Path(args.out).write_text(body)
        sys.stderr.write(f"wrote {args.out}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
