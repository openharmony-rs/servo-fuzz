"""Testcase generators: Domato, Freedom and Minerva as they are, run from `generators/`."""

import os
import subprocess
import sys
from pathlib import Path

from .builds import ROOT

GENERATORS_DIR = ROOT / "generators"
PYTHON = str(ROOT / ".venv/bin/python") if (ROOT / ".venv/bin/python").exists() else sys.executable


def _command(name: str, count: int, out: Path) -> tuple[list[str], Path, dict[str, str]]:
    env = dict(os.environ)
    if name == "domato":
        return [PYTHON, "generator.py", "-o", str(out), "-n", str(count)], GENERATORS_DIR / "domato", env
    if name == "freedom":
        return [PYTHON, "main.py", "-i", "1", "-m", "generate", "-n", str(count), "-o", str(out)], GENERATORS_DIR / "freedom", env
    if name == "minerva":
        env["MEM_DEP_JSON_PATH"] = str(GENERATORS_DIR / "Minerva/mod_ref_helper/mem_dep.json")
        return [PYTHON, "generator.py", "--output_dir", str(out), "--no_of_files", str(count)], GENERATORS_DIR / "Minerva", env
    raise ValueError(f"unknown generator {name}")


NAMES = ["domato", "freedom", "minerva"]


def version(name: str) -> str:
    directory = GENERATORS_DIR / ("Minerva" if name == "minerva" else name)
    result = subprocess.run(["git", "-C", str(directory), "rev-parse", "--short", "HEAD"], capture_output=True, text=True)
    return result.stdout.strip() or "?"


def generate(name: str, count: int, out: Path) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    command, cwd, env = _command(name, count, out)
    subprocess.run(command, cwd=cwd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    return sorted(out.glob("*.html"))
