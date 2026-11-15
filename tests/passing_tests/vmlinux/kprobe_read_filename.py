# Two-step kernel dereference on a kprobe: rsi holds `struct filename *`, so
# `ctx.si` is an i64 the compiler must inttoptr before handing it to a helper;
# the first 8 bytes at that address are the filename's `name` pointer, read
# with probe_read. The string itself needs a destination: `buf = c_char * 256`
# is a 256-byte stack buffer, and probe_read_str takes its size from it.
#
# `struct_trace_event_raw_sys_enter` is imported unused on purpose: its
# trailing `c_char * 0` gives the BTF regression test a zero-length array that
# exists on every kernel. Kernel layouts differ (`struct filename` on Ubuntu
# 6.12 carries only `iname`), so the fixture must not dereference that struct.
#
# The probe point is do_unlinkat(int dfd, struct filename *name); BTF says the
# module is static but kallsyms still exports T do_unlinkat on 6.12, where the
# register values were verified (ctx.di zero-extends an int, ctx.si is the
# pointer). See 01-defects/mem-01 and mem-02 in the fork plan.
from ctypes import c_char, c_int64, c_uint64
from pythonbpf import bpf, bpfglobal, compile, section
from pythonbpf.helper import probe_read, probe_read_str
from vmlinux import struct_pt_regs, struct_trace_event_raw_sys_enter  # noqa: F401


@bpf
@section("kprobe/do_unlinkat")
def unlink_entry(ctx: struct_pt_regs) -> c_int64:
    name_ptr = c_uint64(0)
    probe_read(name_ptr, 8, ctx.si)
    buf = c_char * 256
    n = probe_read_str(buf, name_ptr)
    print(f"name={buf} n={n}")
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
