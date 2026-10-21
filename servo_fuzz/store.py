"""Findings on disk: data/findings/<id>/ with the reproducer, logs and finding.json; findings.md as the index."""

import hashlib
import json
import shutil
import threading
import time
import tomllib
import re
from pathlib import Path

from .builds import ROOT
from .runner import Outcome

DATA = ROOT / "data"
MAX_EXTRA_TESTCASES = 5

CLASS_ORDER = ["qjs-engine", "qjs-shim", "qjs-exposed", "both-differ", "servo", "flaky", "known", "untriaged"]
CLASS_TITLES = {
    "qjs-engine": "QuickJS only, QuickJS C code on top",
    "qjs-shim": "QuickJS only, shim on top",
    "qjs-exposed": "QuickJS only, Servo code on top",
    "both-differ": "Both engines crash, with different signatures",
    "servo": "Servo (same crash on SpiderMonkey)",
    "flaky": "Not reproduced when run alone",
    "known": "Known issues (known.toml)",
    "untriaged": "Not triaged yet",
}


def finding_id(kind: str, signature: str) -> str:
    return hashlib.sha1(f"{kind}|{signature}".encode()).hexdigest()[:12]


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


class Known:
    def __init__(self, path: Path = ROOT / "known.toml"):
        with open(path, "rb") as f:
            self.entries = tomllib.load(f).get("known", [])

    def match(self, kind: str, signature: str) -> dict | None:
        for entry in self.entries:
            if entry.get("kind", kind) == kind and re.search(entry["pattern"], signature):
                return entry
        return None


class Store:
    def __init__(self, root: Path = DATA):
        self.root = root / "findings"
        self.root.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()

    def path(self, ident: str) -> Path:
        return self.root / ident

    def load(self, ident: str) -> dict | None:
        path = self.path(ident) / "finding.json"
        return json.loads(path.read_text()) if path.exists() else None

    def save(self, finding: dict) -> None:
        path = self.path(finding["id"]) / "finding.json"
        path.write_text(json.dumps(finding, indent=2, sort_keys=True) + "\n")

    def update(self, ident: str, **fields) -> dict:
        with self.lock:
            finding = self.load(ident)
            finding.update(fields)
            self.save(finding)
            return finding

    def record_hit(self, outcome: Outcome, testcase: Path, source: str, known: dict | None) -> tuple[dict, bool]:
        """Adds a hit; returns the finding and whether it is new."""
        c = outcome.classification
        ident = finding_id(c.kind, c.signature)
        with self.lock:
            finding = self.load(ident)
            directory = self.path(ident)
            if finding:
                finding["hits"] += 1
                finding["last_seen"] = now()
                finding["sources"][source] = finding["sources"].get(source, 0) + 1
                extra = directory / "more"
                if len(list(extra.glob("*"))) < MAX_EXTRA_TESTCASES:
                    extra.mkdir(exist_ok=True)
                    shutil.copy(testcase, extra / testcase.name)
                self.save(finding)
                return finding, False
            directory.mkdir(parents=True)
            shutil.copy(testcase, directory / ("testcase" + testcase.suffix))
            (directory / f"{outcome.build}.first.log").write_text(outcome.log)
            finding = {
                "id": ident,
                "kind": c.kind,
                "signature": c.signature,
                "summary": c.summary,
                "frames": c.frames[:12],
                "class": "known" if known else "untriaged",
                "known": known,
                "testcase": testcase.name,
                "sources": {source: 1},
                "hits": 1,
                "first_seen": now(),
                "last_seen": now(),
            }
            self.save(finding)
            return finding, True

    def all(self) -> list[dict]:
        return [json.loads(p.read_text()) for p in sorted(self.root.glob("*/finding.json"))]

    def write_report(self, stats: dict | None = None) -> Path:
        findings = self.all()
        lines = ["# Findings", "", f"Updated {now()}. One row per signature; `hits` counts every testcase that hit it.", ""]
        if stats:
            lines += ["## Runs", "", "| Source | Runs | ok | timeout | crashes | s/run |", "|---|---:|---:|---:|---:|---:|"]
            for source, s in sorted(stats.items()):
                runs = s.get("runs", 0)
                crashes = runs - s.get("ok", 0) - s.get("timeout", 0)
                per_run = s.get("seconds", 0) / runs if runs else 0
                lines.append(f"| {source} | {runs} | {s.get('ok', 0)} | {s.get('timeout', 0)} | {crashes} | {per_run:.1f} |")
            lines.append("")
        for cls in CLASS_ORDER:
            group = sorted((f for f in findings if f["class"] == cls), key=lambda f: -f["hits"])
            if not group:
                continue
            lines += [f"## {CLASS_TITLES[cls]} ({len(group)})", "", "| ID | Kind | Summary | Hits | Repro | Sources | First seen | Note |", "|---|---|---|---:|---|---|---|---|"]
            for f in group:
                repro = f.get("repro", {})
                repro_text = ", ".join(f"{k} {v}" for k, v in repro.items())
                note = (f.get("known") or {}).get("issue", "") or f.get("note", "")
                summary = f["summary"].replace("|", "\\|")[:140]
                sources = ", ".join(f"{k} {v}" for k, v in sorted(f["sources"].items()))
                lines.append(
                    f"| [{f['id']}](findings/{f['id']}/) | {f['kind']} | {summary} | {f['hits']} | {repro_text} | {sources} | {f['first_seen'][:10]} | {note} |"
                )
            lines.append("")
        report = self.root.parent / "findings.md"
        report.write_text("\n".join(lines))
        return report
