"""Two functions, one context type: the debug-info layer must hand each of them
its own `DILocalVariable`.

`Module.add_debug_info` deduplicates by operand value, so equal operands return
one node. `add_scope_to_local_variable` then writes `scope` into that node after
it is cached, which makes

    DILocalVariable -> DISubprogram -> retainedNodes -> DILocalVariable

a cycle, and the next cache lookup hashes it until Python raises RecursionError.

This test needs no vmlinux: it drives `DebugInfoGenerator` the way
`functions/function_debug_info.py` does, twice with the same context type.
"""

import pytest
from llvmlite import ir

from pythonbpf.debuginfo import DebugInfoGenerator
from pythonbpf.debuginfo import dwarf_constants as dc


def _new_module():
    module = ir.Module(name="shared_ctx.ll")
    generator = DebugInfoGenerator(module)
    generator.generate_file_metadata("shared_ctx.py", "/tmp")
    generator.generate_debug_cu(dc.DW_LANG_C11, "pythonbpf test", False, True)
    return module, generator


def _add_function_debug_info(generator, name, context_type):
    pointer_to_context = generator.create_pointer_type(context_type, 64)
    subroutine_type = generator.create_subroutine_type(
        generator.get_int64_type(), pointer_to_context
    )
    ctx_local_variable = generator.create_local_variable_debug_info(
        "ctx", 1, pointer_to_context
    )
    subprogram = generator.create_subprogram(
        name, subroutine_type, [ctx_local_variable]
    )
    generator.add_scope_to_local_variable(ctx_local_variable, subprogram)
    return ctx_local_variable, subprogram


def _context_type(generator):
    """The distinct composite type the vmlinux parser hands out for
    `struct_pt_regs`; both functions receive the same object."""
    return generator.create_struct_type([], 1856, is_distinct=True)


def test_two_functions_sharing_a_context_get_their_own_local_variable():
    _module, generator = _new_module()
    context_type = _context_type(generator)

    first = _add_function_debug_info(generator, "unlink_entry", context_type)
    # Second function: same context annotation, different name. This used to
    # raise RecursionError while hashing the retainedNodes list.
    second = _add_function_debug_info(generator, "unlink_exit", context_type)

    assert first[0] is not second[0], "functions share one DILocalVariable node"
    assert first[1] is not second[1], "functions share one DISubprogram node"

    # Each local variable points at its own subprogram, so no cycle exists.
    for (local_variable, subprogram), expected_name in zip(
        (first, second), ("unlink_entry", "unlink_exit")
    ):
        assert dict(local_variable.operands)["scope"] is subprogram
        assert dict(subprogram.operands)["name"] == expected_name


def test_shared_context_nodes_stay_identical():
    """The pointer and subroutine types are still deduplicated: only the node
    that is later mutated has to be fresh."""
    _module, generator = _new_module()
    context_type = _context_type(generator)

    first = _add_function_debug_info(generator, "unlink_entry", context_type)
    second = _add_function_debug_info(generator, "unlink_exit", context_type)

    assert dict(first[1].operands)["type"] is dict(second[1].operands)["type"]
    assert dict(first[0].operands)["type"] is dict(second[0].operands)["type"]


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
