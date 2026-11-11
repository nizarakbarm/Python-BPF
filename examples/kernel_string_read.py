"""Read a kernel string from a kprobe, loading and attaching from Python.

rsi holds `struct filename *`. Cast the register value to the struct, read its
`name` pointer, copy the string into a 256-byte stack buffer, print it. Both
steps that used to be missing are here: the i64 in the register is inttoptr'd
for the helper, and `buf = c_char * 256` is a real stack buffer.

Run as root on a host with bpftool/llc, then unlink a file:
    python examples/kernel_string_read.py
    rm /tmp/target
"""

from ctypes import c_char, c_int64
from pythonbpf import BPF, bpf, bpfglobal, section, trace_pipe
from pythonbpf.helper import probe_read_str
from vmlinux import struct_filename, struct_pt_regs


@bpf
@section("kprobe/do_unlinkat")
def unlink_entry(ctx: struct_pt_regs) -> c_int64:
    fname = struct_filename(ctx.si)
    buf = c_char * 256
    probe_read_str(buf, fname.name)
    print(f"name={buf}")
    return c_int64(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


b = BPF()
b.load()
b.attach_all()
print("attached: unlink a file to see its name", flush=True)
trace_pipe()
