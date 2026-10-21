"""Symbolizes ASan reports written with `symbolize=0` from the binary's symbol table.

llvm-symbolizer takes minutes per report on a 400 MB servoshell without DWARF; `nm` takes under a second
once per binary.
"""

import bisect
import os
import re
import subprocess
import threading

FRAME_RE = re.compile(r"^(?P<prefix>\s*#\d+ 0x[0-9a-f]+)\s+\((?P<module>[^()+]+)\+0x(?P<offset>[0-9a-f]+)\)(?P<rest>.*)$")

_tables: dict[tuple[str, float], tuple[list[int], list[str]]] = {}
_lock = threading.Lock()


def _table(binary: str) -> tuple[list[int], list[str]]:
    key = (binary, os.stat(binary).st_mtime)
    with _lock:
        if key not in _tables:
            output = subprocess.run(
                ["nm", "-C", "--defined-only", binary], capture_output=True, text=True, errors="replace"
            ).stdout
            rows = []
            for line in output.splitlines():
                parts = line.split(" ", 2)
                if len(parts) == 3 and parts[1] in "TtWw":
                    rows.append((int(parts[0], 16), parts[2]))
            rows.sort()
            _tables[key] = ([r[0] for r in rows], [r[1] for r in rows])
        return _tables[key]


def symbolize(report: str, binary: str) -> str:
    addresses, names = _table(binary)
    lines = []
    for line in report.splitlines():
        match = FRAME_RE.match(line)
        if match and match["module"] == binary:
            offset = int(match["offset"], 16)
            index = bisect.bisect_right(addresses, offset) - 1
            name = names[index] if index >= 0 else "??"
            line = f"{match['prefix']} in {name} ({os.path.basename(binary)}+0x{match['offset']})"
        elif match:
            line = f"{match['prefix']} in {os.path.basename(match['module'])}+0x{match['offset']} ({match['module']}+0x{match['offset']})"
        lines.append(line)
    return "\n".join(lines)
