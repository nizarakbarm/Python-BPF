"""Two sections, one module, the same context annotation.

The kprobe + kretprobe pair is the natural shape for one BPF program, and it
used to be unsplittable: both functions annotate `ctx` with `struct_pt_regs`,
so the debug-info layer handed both of them one shared `DILocalVariable` node
and closed a cycle through its `DISubprogram`. Compile died with a
`RecursionError` inside llvmlite's metadata cache before `b.load()`.
"""

import logging
from ctypes import c_int64

from vmlinux import struct_pt_regs

from pythonbpf import bpf, bpfglobal, compile_to_ir, section


@bpf
@section("kprobe/do_unlinkat")
def unlink_entry(ctx: struct_pt_regs) -> c_int64:
    dfd = ctx.di
    print(f"dfd = {dfd}")
    return c_int64(0)


@bpf
@section("kretprobe/do_unlinkat")
def unlink_exit(ctx: struct_pt_regs) -> c_int64:
    ret = ctx.ax
    print(f"ret = {ret}")
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile_to_ir("ctx_two_sections.py", "ctx_two_sections.ll", loglevel=logging.INFO)
