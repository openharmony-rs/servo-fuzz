"""The fuzzing loop: worker threads generate small batches, run them on the target build and record crashes."""

import itertools
import json
import shutil
import threading
import time
from collections import defaultdict
from pathlib import Path

from . import generators
from .builds import Build
from .runner import Outcome, run
from .store import DATA, Known, Store
from .triage import triage


class Stats:
    def __init__(self, path: Path = DATA / "stats.json"):
        self.path = path
        self.lock = threading.Lock()
        self.data = json.loads(path.read_text()) if path.exists() else {}

    def add(self, source: str, outcome: Outcome) -> None:
        with self.lock:
            s = self.data.setdefault(source, defaultdict(int))
            s = self.data[source] = defaultdict(int, s)
            s["runs"] += 1
            s[outcome.kind] += 1
            s["seconds"] += outcome.seconds

    def save(self) -> None:
        with self.lock:
            self.path.write_text(json.dumps(self.data, indent=2, sort_keys=True) + "\n")


class Fuzzer:
    def __init__(self, target: Build, reference: Build | None, sources: list[str], workers: int, batch: int, timeout: float):
        self.target = target
        self.reference = reference
        self.sources = sources
        self.workers = workers
        self.batch = batch
        self.timeout = timeout
        self.store = Store()
        self.known = Known()
        self.stats = Stats()
        self.stop = threading.Event()
        self.new_findings: list[dict] = []
        self.work = DATA / "work"

    def handle(self, outcome: Outcome, testcase: Path, source: str, worker: int) -> None:
        c = outcome.classification
        known = self.known.match(c.kind, c.signature)
        finding, new = self.store.record_hit(outcome, testcase, source, known)
        if not new:
            return
        print(f"[{time.strftime('%T')}] new {finding['class']} {finding['id']}: {c.kind}: {c.summary[:160]}", flush=True)
        if not known:
            finding = triage(self.store, finding["id"], outcome, self.target, self.reference, self.work / f"triage-{worker}", timeout=self.timeout)
            print(f"[{time.strftime('%T')}]   triaged {finding['id']}: {finding['class']} {finding.get('repro')}", flush=True)
        self.new_findings.append(finding)

    def worker(self, index: int) -> None:
        sources = itertools.cycle(self.sources[index % len(self.sources):] + self.sources[: index % len(self.sources)])
        root = self.work / f"w{index}"
        while not self.stop.is_set():
            source = next(sources)
            batch = root / "batch"
            shutil.rmtree(batch, ignore_errors=True)
            try:
                testcases = generators.generate(source, self.batch, batch)
            except Exception as error:
                print(f"generator {source} failed: {error}", flush=True)
                time.sleep(5)
                continue
            for testcase in testcases:
                if self.stop.is_set():
                    break
                outcome = run(self.target, testcase, root / "run", self.timeout)
                self.stats.add(source, outcome)
                if outcome.is_crash:
                    self.handle(outcome, testcase, source, index)
        shutil.rmtree(root, ignore_errors=True)

    def run(self, duration: float) -> None:
        threads = [threading.Thread(target=self.worker, args=(i,), daemon=True) for i in range(self.workers)]
        for thread in threads:
            thread.start()
        deadline = time.monotonic() + duration
        start_runs = sum(s.get("runs", 0) for s in self.stats.data.values())
        start = time.monotonic()
        try:
            while time.monotonic() < deadline and any(t.is_alive() for t in threads):
                time.sleep(min(60, max(1, deadline - time.monotonic())))
                self.stats.save()
                self.store.write_report(self.stats.data)
                runs = sum(s.get("runs", 0) for s in self.stats.data.values()) - start_runs
                rate = runs / (time.monotonic() - start)
                print(f"[{time.strftime('%T')}] {runs} runs, {rate:.1f}/s, {len(self.new_findings)} new findings", flush=True)
        except KeyboardInterrupt:
            pass
        self.stop.set()
        for thread in threads:
            thread.join()
        self.stats.save()
        self.store.write_report(self.stats.data)
