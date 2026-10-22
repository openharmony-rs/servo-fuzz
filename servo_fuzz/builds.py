"""Servo builds that the harness runs, from builds.toml."""

import os
import subprocess
import tomllib
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

ARGS = [
    "--headless",
    "--exit",
    "--hard-fail",
    "--temporary-storage",
    "--window-size=800x600",
    "--enable-experimental-web-platform-features",
    "--pref=dom_testutils_enabled=true",
]


@dataclass(frozen=True)
class Build:
    name: str
    engine: str
    binary: str
    servo_dir: str = ""
    asan: bool = True
    env: dict[str, str] = field(default_factory=dict)

    def environment(self, asan_log_prefix: str) -> dict[str, str]:
        env = dict(os.environ)
        env["RUST_BACKTRACE"] = "1"
        # llvm-symbolizer would ask debuginfod about every module in a report, seconds each (Ubuntu sets this).
        env.pop("DEBUGINFOD_URLS", None)
        if self.engine == "quickjs":
            env["QJS_VERIFY_TRACING"] = "1"
        if self.asan:
            env["ASAN_OPTIONS"] = ":".join(
                [
                    "detect_leaks=0",
                    "abort_on_error=1",
                    "allocator_may_return_null=1",
                    "hard_rss_limit_mb=3072",
                    # Fake stacks put locals on the heap, which trips stylo's stack-limit debug assertion
                    # (context.rs: distance_to_stack_bottom) on a quarter of the generated pages.
                    "detect_stack_use_after_return=0",
                    f"log_path={asan_log_prefix}",
                ]
            )
        env.update(self.env)
        return env

    @property
    def available(self) -> bool:
        return os.access(self.binary, os.X_OK)

    def describe(self) -> dict[str, str]:
        info = {"name": self.name, "engine": self.engine, "binary": self.binary}
        if self.servo_dir:
            info["servo"] = _git_head(self.servo_dir)
            if self.engine == "quickjs":
                config = Path(self.servo_dir, "support/quickjs/cargo-config.toml")
                if config.exists():
                    for line in config.read_text().splitlines():
                        if "rev =" in line:
                            info["shim"] = line.split('rev = "')[1].split('"')[0][:11]
        if self.available:
            info["built"] = str(int(os.stat(self.binary).st_mtime))
        return info


@cache
def _git_head(path: str) -> str:
    try:
        return subprocess.run(
            ["git", "-C", path, "rev-parse", "--short=11", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "?"


def load(path: Path = ROOT / "builds.toml") -> dict[str, Build]:
    if not path.exists():
        raise SystemExit(f"{path} is missing: copy builds.example.toml and set the paths")
    with open(path, "rb") as f:
        data = tomllib.load(f)
    return {name: Build(name=name, **values) for name, values in data.items()}
