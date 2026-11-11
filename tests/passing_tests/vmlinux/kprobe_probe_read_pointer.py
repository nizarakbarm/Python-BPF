# probe_read with a register as the source: `ctx.si` is an i64 holding
# `struct filename *`, and the helper needs the pointed-to address, not the
# address of the stack slot that holds the i64. The first 8 bytes of the
# filename struct are its `name` pointer (BTF: name at offset 0), so a second
# read gets the string out of the 256-byte stack buffer.
from ctypes import c_char, c_int64, c_uint64
from pythonbpf import bpf, bpfglobal, compile, section, struct
from pythonbpf.helper import probe_read, probe_read_str
from vmlinux import struct_pt_regs


@bpf
@struct
class ptr_box:
    p: c_uint64


@bpf
@section("kprobe/do_unlinkat")
def unlink_entry(ctx: struct_pt_regs) -> c_int64:
    box = ptr_box()
    buf = c_char * 256
    probe_read(box.p, 8, ctx.si)
    probe_read_str(buf, box.p)
    print(f"name={buf}")
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
