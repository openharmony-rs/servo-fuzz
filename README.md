# servo-fuzz

Fuzzes Servo with generated pages on the QuickJS build (`js-quickjs`, ASan, tracing verifier). Each new crash is re-run on a SpiderMonkey build of the same Servo commit to decide whether Servo, QuickJS or the shim owns it.

## Setup

Needs Linux x86_64, Python 3.11, [uv](https://github.com/astral-sh/uv), clang with its ASan runtime (`libclang-rt-<version>-dev` on Debian and Ubuntu), and a Servo checkout whose mach has `--js-engine quickjs`: the `ohos-main` branch of [servo-ohos](https://github.com/openharmony-rs/servo-ohos), which builds QuickJS through [servo-quickjs](https://github.com/openharmony-rs/servo-quickjs).

```sh
uv venv .venv && uv pip install --python .venv/bin/python cffi lithium-reducer
git clone --depth 1 https://github.com/googleprojectzero/domato generators/domato
git clone --depth 1 https://github.com/sslab-gatech/freedom generators/freedom
git clone --depth 1 https://github.com/ChijinZ/Minerva generators/Minerva
SERVO=/path/to/servo bin/build.sh
cp builds.example.toml builds.toml                          # then set the paths
```

- `bin/build.sh` builds `qjs-asan` and `sm-asan` (`checked-release`, ASan) into `$TARGET_DIR/fuzz-<build>`; `TARGET_DIR` defaults to `$SERVO/target`. `FUZZ_CC`/`FUZZ_CXX` set the compilers (default `clang`/`clang++`), `BUILDS` picks a subset, and other variables (e.g. `LIBCLANG_PATH`) pass through to mach.
- `builds.toml` (not in git) lists the binaries the harness runs.
- `bin/asan-cc` instruments the C/C++ of target crates, which `mach --with-asan` misses on native builds.
- The SpiderMonkey build compiles SpiderMonkey from source with ASan.

## Use

```sh
.venv/bin/python -m servo_fuzz selftest                     # each oracle detected on both builds
.venv/bin/python -m servo_fuzz fuzz --workers 12 --duration 8h
.venv/bin/python -m servo_fuzz run [--log] page.html        # one run on the target build
.venv/bin/python -m servo_fuzz triage page.html             # record and triage a testcase
.venv/bin/python -m servo_fuzz retriage                     # all findings again, e.g. on new builds
.venv/bin/python -m servo_fuzz reduce --build sm-asan ID   # Lithium into findings/ID/reduced.html; again with --lithium=--attrs or =--symbol
.venv/bin/python -m servo_fuzz report                       # regenerate data/findings.md
```

## How it works

- **Runs:** one process per testcase: `servoshell --headless --exit --hard-fail`, with a 10 s timeout. Each worker generates its own batches (Domato, Freedom, Minerva) and runs them.
- **Classification** (`signature.py`) into these kinds: `asan`, `verifier`, `qjs-assert`, `oom`, `stack-overflow`, `unimplemented` (a SpiderMonkey function the shim lacks), `panic`, `signal`, `exit`, `timeout` or `ok`. The signature is the kind plus the top frames, or the panic's file and normalized message.
- **ASan options:** reports are written unsymbolized, and `symbolize.py` resolves them from `nm`. llvm-symbolizer takes minutes per report on this binary, which has no DWARF. Fake stacks are off, because they trip stylo's stack-limit debug assertion.
- **Findings** (`data/findings/<id>/`): one per signature, with the first testcase, up to 5 more, logs and `finding.json`.
  - A new finding runs 3× alone on the target build and 3× on the reference build.
  - `servo` means the same signature on SpiderMonkey. `qjs-engine`, `qjs-shim` and `qjs-exposed` mean only QuickJS crashes, with QuickJS C code, the shim or Servo code on top of the stack. `flaky` means the crash didn't reproduce alone.
- **`known.toml`:** crashes with a known issue are counted but not triaged.
- **`data/findings.md`:** the index, regenerated every minute while fuzzing.

## License

MIT OR Apache-2.0. `known.toml` was seeded from the known-panic list of [fred-wang/servo-fuzzing](https://github.com/fred-wang/servo-fuzzing) (MIT). The generators are cloned separately and keep their own licenses.
