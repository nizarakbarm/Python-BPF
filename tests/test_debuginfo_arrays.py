"""Array and pointer fields must not be typed as function pointers.

`debug_info_gen` used to test `callable(field.ctype_complex_type)` when
looking for a ctypes CFUNCTYPE, but `ctypes.Array` and `ctypes._Pointer`
are classes and therefore callable: every array and pointer field took the
function-pointer branch and became an 8-byte void pointer. A trailing
`c_char * 0` flexible array member then landed a pointer past the end of the
struct, and the kernel rejected the BTF section with

    Member exceeds struct_size

`is_function_pointer()` now requires the `_restype_`/`_argtypes_` pair that
only a CFUNCTYPE class carries.
"""

import ctypes
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from llvmlite import ir

from pythonbpf.debuginfo import DebugInfoGenerator
from pythonbpf.debuginfo import dwarf_constants as dc
from pythonbpf.vmlinux_parser.dependency_node import Field
from pythonbpf.vmlinux_parser.ir_gen.debug_info_gen import _get_field_debug_type

TESTS_DIR = Path(__file__).parent


def _generator():
    module = ir.Module(name="btf_arrays.ll")
    generator = DebugInfoGenerator(module)
    generator.generate_file_metadata("btf_arrays.py", "/tmp")
    generator.generate_debug_cu(dc.DW_LANG_C11, "pythonbpf test", False, True)
    return generator


def _field(name, **kwargs):
    return Field(name=name, **kwargs)


def test_zero_length_array_is_an_array_type_not_a_pointer():
    generator = _generator()
    field = _field(
        "iname",
        type=ctypes.c_char * 0,
        ctype_complex_type=ctypes.Array,
        containing_type=ctypes.c_char,
        type_size=0,
        offset=32,
        bitfield_size=None,
    )

    node, size_bits = _get_field_debug_type(
        "iname", field, generator, SimpleNamespace(name="struct_test"), []
    )

    assert dict(node.operands)["tag"] == dc.DW_TAG_array_type
    assert dict(node.operands)["size"] == 0
    assert size_bits == 0


def test_pointer_field_stays_a_64_bit_pointer():
    generator = _generator()
    field = _field(
        "name",
        type=ctypes.POINTER(ctypes.c_char),
        ctype_complex_type=ctypes._Pointer,
        containing_type=ctypes.c_char,
        type_size=None,
        offset=0,
        bitfield_size=None,
    )

    node, size_bits = _get_field_debug_type(
        "name", field, generator, SimpleNamespace(name="struct_test"), []
    )

    assert dict(node.operands)["tag"] == dc.DW_TAG_pointer_type
    assert size_bits == 64


def test_kprobe_read_filename_emits_a_zero_sized_array(tmp_path):
    """End to end: `struct filename` has a trailing `c_char * 0`."""
    pytest.importorskip("vmlinux")
    from tests.framework.compiler import run_ir_generation

    ll_path = tmp_path / "kprobe_read_filename.ll"
    run_ir_generation(
        TESTS_DIR / "passing_tests/vmlinux/kprobe_read_filename.py", ll_path
    )
    ir_text = ll_path.read_text()

    # llvmlite prints metadata tags numerically, so `DW_TAG_array_type` (0x01)
    # shows up as `tag: 1`. A pointer would be tag 15 and struct/union 19/23.
    array_types = [
        line for line in ir_text.splitlines() if re.search(r"tag: 1\b", line)
    ]
    zero_arrays = [line for line in array_types if "size: 0," in line]
    assert len(zero_arrays) == 1, zero_arrays


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
