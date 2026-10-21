"""Triage of a new finding: reproduce it alone on the fuzzed build, then compare with the reference engine."""

import shutil
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .builds import Build
from .runner import Outcome, run
from .signature import engine_side
from .store import Store


def classify_pair(first: Outcome, target_runs: list[Outcome], reference_runs: list[Outcome]) -> str:
    if not any(o.key == first.key for o in target_runs):
        return "flaky"
    if any(o.key == first.key for o in reference_runs):
        return "servo"
    if any(o.is_crash for o in reference_runs):
        return "both-differ"
    return engine_side(first.classification)


def triage(store: Store, ident: str, first: Outcome, target: Build, reference: Build | None, workdir: Path, runs: int = 3, timeout: float = 15) -> dict:
    testcase = next(store.path(ident).glob("testcase.*"))
    builds = [(target, i) for i in range(runs)] + ([(reference, i) for i in range(runs)] if reference else [])
    with ThreadPoolExecutor(len(builds)) as pool:
        outcomes = list(pool.map(lambda b: run(b[0], testcase, workdir / f"{b[0].name}-{b[1]}", timeout), builds))
    shutil.rmtree(workdir, ignore_errors=True)
    target_runs = outcomes[:runs]
    reference_runs = outcomes[runs:]
    repro = {target.name: f"{sum(o.key == first.key for o in target_runs)}/{runs}"}
    fields = {"repro": repro, "builds": {target.name: target.describe()}}
    if reference:
        same = sum(o.key == first.key for o in reference_runs)
        crashes = sum(o.is_crash for o in reference_runs)
        repro[reference.name] = f"{same}/{runs}" + (f" (other crash {crashes - same})" if crashes > same else "")
        fields["builds"][reference.name] = reference.describe()
        fields["reference_outcomes"] = sorted({f"{o.kind}: {o.classification.summary}"[:300] for o in reference_runs})
        fields["class"] = classify_pair(first, target_runs, reference_runs)
    else:
        fields["class"] = "untriaged" if any(o.key == first.key for o in target_runs) else "flaky"
    directory = store.path(ident)
    for outcome in target_runs:
        if outcome.key == first.key:
            (directory / f"{target.name}.log").write_text(outcome.log)
            break
    for outcome in reference_runs:
        (directory / f"{reference.name}.log").write_text(outcome.log)
        if outcome.is_crash:
            break
    return store.update(ident, **fields)
