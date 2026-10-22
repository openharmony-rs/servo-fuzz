"""Classification of a servoshell run from its output and ASan reports."""

import re
from dataclasses import dataclass, field

# Crash kinds in order of precedence: a run with an ASan report and a panic is an `asan` crash.
CRASH_KINDS = [
    "asan",
    "verifier",
    "qjs-assert",
    "oom",
    "stack-overflow",
    "unimplemented",
    "panic",
    "signal",
    "exit",
]

PANIC_RE = re.compile(r"^(?P<msg>.*) \(thread (?P<thread>[^,]+), at (?P<file>.+?):(?P<line>\d+)\)$")
FRAME_RE = re.compile(r"^\s*\d+: (?P<func>.+)$")
ASAN_ERROR_RE = re.compile(r"ERROR: AddressSanitizer: (?P<type>[\w-]+)")
# The location is a file (with line tables), a codegen unit (symbol table only) or a module offset.
ASAN_FRAME_RE = re.compile(
    r"^\s*#\d+ 0x[0-9a-f]+ in (?P<func>.+?)"
    r"(?: (?P<loc>\(\S+\+0x[0-9a-f]+\)|\S+:\d+(?::\d+)?|\S+-cgu\.\d+|/\S+))?(?: \(BuildId: [0-9a-f]+\))?$"
)
VERIFIER_RE = re.compile(r"QuickJS tracing verifier: (?P<text>.+)")
ASSERT_RE = re.compile(r": (?P<func>[\w$]+): Assertion `(?P<expr>.+)' failed")
STACK_OVERFLOW_RE = re.compile(r"thread '(?P<thread>[^']+)' has overflowed its stack")
SIGNAL_RE = re.compile(r"Caught signal (?P<signal>\d+)")
OOM_RE = re.compile(
    r"memory allocation of \d+ bytes failed|AddressSanitizer: (?:requested allocation size|out of memory|"
    r"allocation-size-too-big|calloc-overflow|rss-limit-exceeded)|RSS limit|hard rss limit exhausted",
    re.I,
)
UNIMPLEMENTED_RE = re.compile(r"`(?P<name>\w+)` is not implemented")

# Frames that say nothing about where a bug is.
UNINTERESTING_FRAME_RE = re.compile(
    r"^(?:__asan|__interceptor|__sanitizer|__lsan|__rust_|__libc|__GI_|__restore_rt|_ZL17asan|asan_|"
    r"malloc|free|calloc|realloc|operator new|operator delete|abort|raise|gsignal|"
    r"alloc::|<alloc::|core::|<core::|std::|<std::|servoshell::backtrace|servoshell::panic_hook|"
    r"servoshell::crash_handler|backtrace::|<unknown>|rust_begin_unwind|sigaction|"
    r"mozjs::panic::wrap_panic|__rustc::|[\w.+-]+\.so[.\d]*\+0x)"
)
# Inlined frames have short names with line tables only, so the standard library is recognized by its source path.
RUST_LIBRARY_RE = re.compile(r"/rustlib/src/rust/library/|^/rustc/")


@dataclass
class Classification:
    kind: str
    signature: str = ""
    summary: str = ""
    frames: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)


def _normalize(text: str) -> str:
    text = re.sub(r"0x[0-9a-fA-F]+", "X", text)
    text = re.sub(r"\d+", "N", text)
    return text.strip()


def _short_path(path: str) -> str:
    path = re.sub(r"^.*/(?:registry/src/[^/]+|git/checkouts/[^/]+/[^/]+)/", "", path)
    path = re.sub(r"^([\w-]+?)-\d+\.\d+\.\d+[^/]*/", r"\1/", path)
    path = re.sub(r"^/.*?/(components|ports|third_party|support)/", r"\1/", path)
    return path


def _clean_func(func: str) -> str:
    func = re.sub(r"::h[0-9a-f]{16}$", "", func.strip())
    return func[:160]


def _interesting(frames: list[str], limit: int = 3) -> list[str]:
    return [f for f in frames if not UNINTERESTING_FRAME_RE.match(f)][:limit]


def _asan(report: str) -> Classification | None:
    error = ASAN_ERROR_RE.search(report)
    if not error:
        return None
    frames, files = [], []
    for line in report[error.end():].splitlines():
        if line.startswith("SUMMARY") or "is located" in line or "freed by thread" in line:
            break
        match = ASAN_FRAME_RE.match(line)
        if match:
            frames.append(_clean_func(match["func"]))
            files.append(match["loc"] or "")
    access = re.search(r"^(READ|WRITE) of size \d+", report, re.M)
    top = _interesting([f for f, path in zip(frames, files) if not RUST_LIBRARY_RE.search(path)])
    summary = f"{error['type']} {access.group(0) if access else ''} in {top[0] if top else '?'}".replace("  ", " ")
    return Classification(
        "asan",
        f"{error['type']}|{'|'.join(top)}",
        summary,
        frames,
        files,
    )


def _backtrace_after(lines: list[str], start: int) -> list[str]:
    frames = []
    for line in lines[start + 1:]:
        match = FRAME_RE.match(line)
        if match:
            frames.append(_clean_func(match["func"]))
        elif frames and not line.startswith(" "):
            break
    return frames


def classify(output: str, asan_reports: list[str], returncode: int | None, timed_out: bool) -> Classification:
    for report in asan_reports:
        if OOM_RE.search(report):
            return Classification("oom", "asan", OOM_RE.search(report).group(0))
        found = _asan(report)
        if found:
            return found

    if match := VERIFIER_RE.search(output):
        text = _normalize(match["text"])
        return Classification("verifier", text, match.group(0))

    if match := ASSERT_RE.search(output):
        return Classification("qjs-assert", f"{match['func']}|{match['expr']}", match.group(0).lstrip(": "))

    if match := OOM_RE.search(output):
        return Classification("oom", _normalize(match.group(0)), match.group(0))

    lines = output.splitlines()
    for line in lines:
        if match := STACK_OVERFLOW_RE.search(line):
            thread = re.sub(r"#\d+$", "", match["thread"])
            return Classification("stack-overflow", thread, match.group(0))

    for index, line in enumerate(lines):
        match = PANIC_RE.match(line)
        if not match:
            continue
        message = match["msg"] or (lines[index - 1] if index else "")
        if message.startswith("This indicates a bug in the program"):
            message = next((l for l in reversed(lines[max(0, index - 6):index]) if "unsafe precondition" in l), message)
        frames = _backtrace_after(lines, index)
        if unimplemented := UNIMPLEMENTED_RE.search(message):
            return Classification("unimplemented", unimplemented["name"], message, frames)
        path = _short_path(match["file"])
        return Classification(
            "panic",
            f"{path}|{_normalize(message)[:200]}",
            f"{message} ({path}:{match['line']}, {match['thread']})",
            frames,
            [path],
        )

    for index, line in enumerate(lines):
        if match := SIGNAL_RE.search(line):
            frames = _backtrace_after(lines, index)
            top = _interesting(frames, 2)
            return Classification("signal", f"{match['signal']}|{'|'.join(top)}", line.strip(), frames)

    if timed_out:
        return Classification("timeout")
    if returncode is not None and returncode < 0:
        return Classification("signal", str(-returncode), f"killed by signal {-returncode}")
    if returncode:
        return Classification("exit", str(returncode), f"exit code {returncode}")
    return Classification("ok")


def engine_side(classification: Classification) -> str:
    """For a QuickJS-only crash: whether QuickJS's C code, the shim or Servo is on top of the stack."""
    for func, path in zip(classification.frames, classification.files + [""] * len(classification.frames)):
        if UNINTERESTING_FRAME_RE.match(func):
            continue
        if "servo-quickjs/quickjs/" in path or "/quickjs.c" in path:
            return "qjs-engine"
        if "mozjs/src/engine/" in path or func.startswith(("mozjs::engine::", "<mozjs::engine::")):
            return "qjs-shim"
        if re.match(r"^(?:JS_|js_|__JS_|gc_|free_|mark_)\w*$", func):
            return "qjs-engine"
        break
    if any("mozjs::engine::" in f for f in classification.frames[:8]):
        return "qjs-shim"
    return "qjs-exposed"
