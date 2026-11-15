# A char-array struct field passed as a helper pointer argument. The struct
# field is an [N x i8] alloca member, and the helper needs its address; it must
# not arrive as a (pointer, size) pair, because map helpers take one pointer.
#
# Before the fix this raised at IR generation:
#   AttributeError: 'tuple' object has no attribute 'type'
# from bpf_map_lookup_elem, map_update_elem and map_delete_elem.
from ctypes import c_int32, c_int64, c_uint64, c_void_p
from pythonbpf import bpf, bpfglobal, compile, map, section, struct
from pythonbpf.maps import HashMap


@bpf
@map
def counters() -> HashMap:
    return HashMap(key=c_int32, value=c_int64, max_entries=16)


@bpf
@struct
class rec:
    pid: c_uint64
    comm: str(16)


@bpf
@section("tracepoint/syscalls/sys_enter_clone")
def prog(ctx: c_void_p) -> c_int32:
    r = rec()
    r.pid = 1
    counters.lookup(r.comm)
    counters.update(r.comm, 1)
    counters.delete(r.comm)
    return c_int32(0)


@bpf
@bpfglobal
def LICENSE() -> str:
    return "GPL"


compile()
