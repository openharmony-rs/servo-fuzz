"""One-shot runs: one servoshell process per testcase, `--exit` after the page is stable."""

import glob
import os
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .builds import ARGS, Build
from .signature import Classification, classify
from .symbolize import symbolize

NOISE = (
    "XDG_RUNTIME_DIR",
    "amdgpu:",
    "If they do, bad things may happen",
    "ALSA lib",
    "pw.conf",
    "[ALSOFT]",
)


@dataclass
class Outcome:
    build: str
    classification: Classification
    returncode: int | None
    seconds: float
    log: str

    @property
    def kind(self) -> str:
        return self.classification.kind

    @property
    def key(self) -> tuple[str, str]:
        return (self.classification.kind, self.classification.signature)

    @property
    def is_crash(self) -> bool:
        return self.kind not in ("ok", "timeout")


def run(build: Build, testcase: Path, workdir: Path, timeout: float = 15, extra_args: list[str] = ()) -> Outcome:
    """Runs `testcase` (a file or URL) once; `workdir` receives the output and ASan reports."""
    workdir = workdir.resolve()
    shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True)
    url = str(testcase) if "://" in str(testcase) else Path(testcase).resolve().as_uri()
    log_path = workdir / "output.log"
    start = time.monotonic()
    timed_out = False
    with open(log_path, "wb") as log:
        process = subprocess.Popen(
            [build.binary, *ARGS, *extra_args, url],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=build.environment(str(workdir / "asan")),
            cwd=workdir,
            start_new_session=True,
        )
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
    seconds = time.monotonic() - start
    output = log_path.read_text(errors="replace")
    output = "\n".join(line for line in output.splitlines() if not any(noise in line for noise in NOISE))
    report_paths = sorted(glob.glob(str(workdir / "asan.*")))
    reports = [symbolize(Path(p).read_text(errors="replace"), build.binary) for p in report_paths]
    returncode = None if timed_out else process.returncode
    classification = classify(output, reports, returncode, timed_out)
    log = output + "".join(f"\n==== {Path(name).name}\n{text}" for name, text in zip(report_paths, reports))
    return Outcome(build.name, classification, returncode, seconds, log)
