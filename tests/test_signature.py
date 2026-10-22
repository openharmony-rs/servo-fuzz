import unittest

from servo_fuzz.signature import classify, engine_side

ASAN_REPORT = """=================================================================
==4242==ERROR: AddressSanitizer: heap-use-after-free on address 0x60b0000fe1a0 at pc 0x55d0 bp 0x7ff sp 0x7fe
READ of size 8 at 0x60b0000fe1a0 thread T12 (Script#1)
    #0 0x55d0a1 in js_free_value_rt /home/u/.cargo/git/checkouts/servo-quickjs-e4f/cbf02ee/servo-quickjs/quickjs/quickjs.c:5530:13
    #1 0x55d0a2 in JS_FreeValue /home/u/.cargo/git/checkouts/servo-quickjs-e4f/cbf02ee/servo-quickjs/quickjs/quickjs.h:700:9
    #2 0x55d0a3 in mozjs::engine::heap::release_object::h0123456789abcdef /home/u/.cargo/git/checkouts/servo-quickjs-e4f/cbf02ee/mozjs/src/engine/heap.rs:80:5

0x60b0000fe1a0 is located 32 bytes inside of 104-byte region
freed by thread T12 (Script#1) here:
    #0 0x55d0b1 in free
SUMMARY: AddressSanitizer: heap-use-after-free quickjs.c:5530:13 in js_free_value_rt
"""


class ClassifyTest(unittest.TestCase):
    def test_asan(self):
        c = classify("", [ASAN_REPORT], -6, False)
        self.assertEqual(c.kind, "asan")
        self.assertEqual(c.signature, "heap-use-after-free|js_free_value_rt|JS_FreeValue|mozjs::engine::heap::release_object")
        self.assertIn("READ of size 8", c.summary)
        self.assertEqual(engine_side(c), "qjs-engine")

    def test_asan_frame_locations(self):
        report = """==1==ERROR: AddressSanitizer: SEGV on unknown address 0x03e8000614b8 (pc 0x7f13 bp 0x7ffe sp 0x7ffe T0)
    #0 0x7f135cf2f52d in getenv (/lib/x86_64-linux-gnu/libc.so.6+0x48806) (BuildId: a4a7992a8e66555c8141ab2a08a8465ff6e0ea65)
    #1 0x7ba27d991093  (/lib/x86_64-linux-gnu/libgallium.so+0x568093) (BuildId: 0123456789abcdef)
    #2 0x55a8477f09f4 in <gleam::gl::GlFns as gleam::gl::Gl>::shader_source gleam.bae54a1812ce0e60-cgu.03
    #3 0x55c0d603284d in wait_optional_timeout /home/u/.rustup/toolchains/1.97.1-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/std/src/sys/sync/condvar/futex.rs:49:17
    #4 0x55a8477b3eff in <webrender::device::gl::Device>::compile_shader /home/u/.cargo/git/checkouts/webrender-1/abc/webrender/src/device/gl.rs:2010:9
"""
        c = classify("", [report], -6, False)
        self.assertEqual(
            c.signature,
            "SEGV|getenv|<gleam::gl::GlFns as gleam::gl::Gl>::shader_source|<webrender::device::gl::Device>::compile_shader",
        )
        self.assertEqual(c.files[1], "gleam.bae54a1812ce0e60-cgu.03")

    def test_asan_oom(self):
        report = "==1==ERROR: AddressSanitizer: requested allocation size 0x10000000000 exceeds maximum supported size"
        self.assertEqual(classify("", [report], -6, False).kind, "oom")

    def test_asan_rss_limit(self):
        report = "==807879==AddressSanitizer: hard rss limit exhausted (3072Mb vs 3076Mb)"
        self.assertEqual(classify("Caught signal 6", [report], -6, False).kind, "oom")

    def test_verifier(self):
        output = "QuickJS tracing verifier: 0x7f00deadbeef (Document) marked 2 times in one GC, Rust holds 1 counted references"
        c = classify(output, [], -6, False)
        self.assertEqual(c.kind, "verifier")
        self.assertEqual(c.signature, "X (Document) marked N times in one GC, Rust holds N counted references")

    def test_assert(self):
        output = "servoshell: /x/quickjs.c:2567: JS_FreeRuntime: Assertion `list_empty(&rt->gc_obj_list)' failed."
        c = classify(output, [], -6, False)
        self.assertEqual((c.kind, c.signature), ("qjs-assert", "JS_FreeRuntime|list_empty(&rt->gc_obj_list)"))

    def test_stack_overflow(self):
        output = "\nthread 'Script#3' has overflowed its stack\nfatal runtime error: stack overflow, aborting"
        self.assertEqual(classify(output, [], -6, False).signature, "Script")

    def test_unimplemented(self):
        output = "`JS_GetFunctionScript` is not implemented (thread Script#1, at /x/mozjs/src/sys/generated.rs:12)\n   0: servoshell::backtrace::print"
        c = classify(output, [], -11, False)
        self.assertEqual((c.kind, c.signature), ("unimplemented", "JS_GetFunctionScript"))

    def test_panic_in_dependency(self):
        output = (
            "called `Option::unwrap()` on a `None` value (thread Layout#2, at "
            "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/euclid-0.22.14/src/size.rs:123)\n"
            "   0: servoshell::backtrace::print\n   1: servoshell::panic_hook::panic_hook\n   2: euclid::size::Size2D::new"
        )
        c = classify(output, [], -11, False)
        self.assertEqual(c.kind, "panic")
        self.assertEqual(c.signature, "euclid/src/size.rs|called `Option::unwrap()` on a `None` value")
        self.assertEqual(c.frames[-1], "euclid::size::Size2D::new")

    def test_panic_numbers_normalized(self):
        output = "index out of bounds: the len is 3 but the index is 7 (thread Script#1, at components/script/dom/x.rs:5)"
        self.assertEqual(classify(output, [], 1, False).signature, "components/script/dom/x.rs|index out of bounds: the len is N but the index is N")

    def test_signal(self):
        output = "Caught signal 11\n   0: servoshell::backtrace::print\n   1: servoshell::crash_handler::handler\n   2: __restore_rt\n   3: webrender::renderer::Renderer::render\n   4: servo::Servo::spin_event_loop"
        c = classify(output, [], -11, False)
        self.assertEqual((c.kind, c.signature), ("signal", "11|webrender::renderer::Renderer::render|servo::Servo::spin_event_loop"))

    def test_plain_outcomes(self):
        self.assertEqual(classify("", [], 0, False).kind, "ok")
        self.assertEqual(classify("", [], None, True).kind, "timeout")
        self.assertEqual(classify("", [], 3, False).kind, "exit")


if __name__ == "__main__":
    unittest.main()
