"""Lithium condition: interesting if a run of `build` crashes with the given kind and signature.

python -m lithium servo_fuzz.interesting --build NAME --kind KIND --signature SIG [--tries N] [--timeout S] testcase
"""

import argparse
from pathlib import Path

from . import builds as builds_module
from .runner import run
from .store import DATA


def interesting(cli_args: list[str], temp_prefix: str) -> bool:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", required=True)
    parser.add_argument("--kind", required=True)
    parser.add_argument("--signature", required=True)
    parser.add_argument("--tries", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("testcase")
    args = parser.parse_args(cli_args)
    build = builds_module.load()[args.build]
    workdir = DATA / "work" / f"reduce-{Path(args.testcase).parent.name}"
    for _ in range(args.tries):
        if run(build, Path(args.testcase), workdir, args.timeout).key == (args.kind, args.signature):
            return True
    return False
