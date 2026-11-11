# Two-step kernel dereference on a kprobe: rsi holds `struct filename *`, so
# `ctx.si` is an i64 the compiler must inttoptr before handing it to a helper,
# and `filename.name` is a second i64 read with probe_read. The string itself
# needs a destination: `buf = c_char * 256` is a 256-byte stack buffer, and
# probe_read_str takes its size from that declaration.
#
# The probe point is do_unlinkat(int dfd, struct filename *name); BTF says the
# module is static but kallsyms still exports T do_unlinkat on 6.12, where the
# register values were verified (ctx.di zero-extends an int, ctx.si is the
# pointer). See 01-defects/mem-01 and mem-02 in the fork plan.
from ctypes import c_char, c_int64
from pythonbpf import bpf, bpfglobal, compile, section
from pythonbpf.helper import probe_read_str
from vmlinux import struct_filename, struct_pt_regs


@bpf
@section("kprobe/do_unlinkat")
def unlink_entry(ctx: struct_pt_regs) -> c_int64:
    fname = struct_filename(ctx.si)
    name_ptr = fname.name
    buf = c_char * 256
    n = probe_read_str(buf, name_ptr)
    print(f"name={buf} n={n}")
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
