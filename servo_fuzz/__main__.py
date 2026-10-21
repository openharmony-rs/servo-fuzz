import argparse
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from . import builds as builds_module
from . import generators
from .fuzz import Fuzzer, Stats
from .runner import run
from .store import DATA, Known, Store
from .triage import triage

SELFTEST = Path(__file__).resolve().parent / "selftest"
# A null write is a segfault in release builds, and a panic where debug assertions check unsafe preconditions.
SELFTEST_EXPECTED = {"ok": ("ok",), "panic": ("panic",), "segv": ("signal", "panic"), "hang": ("timeout",), "throw": ("ok",)}


def duration(text: str) -> float:
    match = re.fullmatch(r"(\d+(?:\.\d+)?)([smhd]?)", text)
    if not match:
        raise argparse.ArgumentTypeError(f"bad duration {text}")
    return float(match[1]) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[match[2]]


def main() -> int:
    parser = argparse.ArgumentParser(prog="servo_fuzz")
    parser.add_argument("--target", default="qjs-asan", help="build to fuzz")
    parser.add_argument("--reference", default="sm-asan", help="build to compare crashes with")
    parser.add_argument("--timeout", type=float, default=10)
    sub = parser.add_subparsers(dest="command", required=True)

    fuzz = sub.add_parser("fuzz", help="generate and run testcases")
    fuzz.add_argument("--generators", default=",".join(generators.NAMES))
    fuzz.add_argument("--workers", type=int, default=12)
    fuzz.add_argument("--batch", type=int, default=10)
    fuzz.add_argument("--duration", type=duration, default=3600)

    one = sub.add_parser("run", help="run testcases once and print the outcome")
    one.add_argument("--build")
    one.add_argument("--log", action="store_true")
    one.add_argument("testcases", nargs="+")

    tri = sub.add_parser("triage", help="record testcases as findings and triage them")
    tri.add_argument("testcases", nargs="+")

    sub.add_parser("retriage", help="triage every finding again with the current builds")

    red = sub.add_parser("reduce", help="reduce a finding's testcase with Lithium into reduced.html, or reduce that further")
    red.add_argument("--build", help="build to reduce on (default: the target)")
    red.add_argument("--tries", type=int, default=1, help="runs per candidate, for crashes that don't always reproduce")
    red.add_argument("--lithium", default="", help="extra Lithium options, e.g. '--symbol --cut-after=;'")
    red.add_argument("finding")
    sub.add_parser("report", help="regenerate data/findings.md")
    sub.add_parser("selftest", help="check that each oracle is detected on every build")

    args = parser.parse_args()
    builds = builds_module.load()
    target = builds[args.target]
    reference = builds.get(args.reference)
    if reference and not reference.available:
        print(f"reference build {reference.name} not available, no differential triage", file=sys.stderr)
        reference = None

    if args.command == "fuzz":
        sources = args.generators.split(",")
        print(f"fuzzing {target.describe()} with {sources}, {args.workers} workers", flush=True)
        Fuzzer(target, reference, sources, args.workers, args.batch, args.timeout).run(args.duration)
        return 0

    if args.command == "run":
        build = builds[args.build] if args.build else target
        for testcase in args.testcases:
            outcome = run(build, Path(testcase), DATA / "work" / "run-cli", args.timeout)
            c = outcome.classification
            print(f"{testcase}: {c.kind} {c.summary} [{outcome.seconds:.1f}s]")
            if args.log:
                print(outcome.log)
        return 0

    store = Store()
    if args.command == "triage":
        known = Known()
        for testcase in args.testcases:
            outcome = run(target, Path(testcase), DATA / "work" / "run-cli", args.timeout)
            if not outcome.is_crash:
                print(f"{testcase}: {outcome.kind}, nothing to triage")
                continue
            c = outcome.classification
            finding, new = store.record_hit(outcome, Path(testcase), "manual", known.match(c.kind, c.signature))
            if new and finding["class"] != "known":
                finding = triage(store, finding["id"], outcome, target, reference, DATA / "work" / "triage-cli", timeout=args.timeout)
            print(f"{testcase}: {finding['id']} {finding['class']} {finding.get('repro', '')} {c.kind}: {c.summary}")
        store.write_report(Stats().data)
        return 0

    if args.command == "retriage":
        for finding in store.all():
            testcase = next(store.path(finding["id"]).glob("testcase.*"))
            outcome = run(target, testcase, DATA / "work" / "run-cli", args.timeout)
            if outcome.key != (finding["kind"], finding["signature"]):
                store.update(finding["id"], class_note=f"not reproduced on {target.name}: {outcome.kind}")
                print(f"{finding['id']}: no longer reproduces ({outcome.kind})")
                continue
            if finding["class"] != "known":
                finding = triage(store, finding["id"], outcome, target, reference, DATA / "work" / "triage-cli", timeout=args.timeout)
            print(f"{finding['id']}: {finding['class']} {finding.get('repro', '')}")
        store.write_report(Stats().data)
        return 0

    if args.command == "reduce":
        finding = store.load(args.finding)
        directory = store.path(args.finding)
        reduced = directory / "reduced.html"
        if not reduced.exists():
            shutil.copyfile(next(directory.glob("testcase.*")), reduced)
        tempdir = DATA / "work" / f"lithium-{args.finding}"
        shutil.rmtree(tempdir, ignore_errors=True)
        tempdir.mkdir(parents=True)
        command = [
            sys.executable, "-m", "lithium", *shlex.split(args.lithium), "--tempdir", str(tempdir), "servo_fuzz.interesting",
            "--build", args.build or target.name, "--kind", finding["kind"], "--signature", finding["signature"],
            "--tries", str(args.tries), "--timeout", str(args.timeout), str(reduced),
        ]
        with open(directory / "reduce.log", "a") as log:
            return subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, cwd=builds_module.ROOT).returncode

    if args.command == "report":
        print(store.write_report(Stats().data))
        return 0

    if args.command == "selftest":
        failures = 0
        for build in [b for b in (target, reference) if b]:
            for name, expected in SELFTEST_EXPECTED.items():
                outcome = run(build, SELFTEST / f"{name}.html", DATA / "work" / "selftest", 10, ["--pref=dom_servo_helpers_enabled=true"])
                status = "ok" if outcome.kind in expected else "FAIL"
                failures += status != "ok"
                print(f"{build.name:10} {name:6} expected {'/'.join(expected):13} got {outcome.kind:10} {status}  {outcome.classification.summary[:100]}")
        shutil.rmtree(DATA / "work" / "selftest", ignore_errors=True)
        return 1 if failures else 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
