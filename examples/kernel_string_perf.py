"""Read a kernel filename and deliver it through a perf event array.

Same two-step dereference as `kernel_string_read.py`, but the string leaves the
kernel in a struct through `events.output()` instead of `bpf_trace_printk`.
`probe_read` reads the first field of `struct filename` (the `name` pointer),
`probe_read_str` fills a stack buffer, and the buffer is copied into the perf
event struct.

Run as root on a kernel with BTF:
    python examples/kernel_string_perf.py
    rm /tmp/target
"""

from ctypes import c_int32, c_uint64
from pythonbpf import BPF, bpf, bpfglobal, map, section, struct
from pythonbpf.helper import probe_read, probe_read_str
from pythonbpf.maps import PerfEventArray
from vmlinux import struct_pt_regs


@bpf
@struct
class event_t:
    name: str(256)


@bpf
@map
def events() -> PerfEventArray:
    return PerfEventArray(key_size=c_int32, value_size=256)


@bpf
@section("kprobe/do_unlinkat")
def unlink_entry(ctx: struct_pt_regs) -> c_int32:
    event = event_t()
    name_ptr = c_uint64(0)
    probe_read(name_ptr, 8, ctx.si)  # struct filename.name
    probe_read_str(event.name, name_ptr)
    events.output(event)
    return c_int32(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


b = BPF()
b.load()
b.attach_all()


def handle(cpu, event):
    name = bytes(event.name).split(b"\x00", 1)[0].decode("utf-8", "replace")
    print(f"cpu={cpu} name={name}", flush=True)


events_map = b["events"]
events_map.open_perf_buffer(handle, struct_name="event_t")
print("attached: unlink a file to see its name", flush=True)
while True:
    events_map.poll(1000)
