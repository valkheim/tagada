import functools
from typing import Callable, Dict, Iterator, Optional

import ida_bytes
import ida_entry
import ida_funcs
import ida_ida
import ida_idaapi
import ida_nalt
import ida_segment
import idaapi
import idautils
import idc

from tagada.utils import error

from .config import NAME
from .types import Enum, Function, Hooks, Insn, Segment


def get_instruction(ea: int) -> Insn:
    insn = idaapi.insn_t()
    idaapi.decode_insn(insn, ea)
    return insn


def get_imports():
    imports_qty = idaapi.get_import_module_qty()
    imports = []
    for idx in range(imports_qty):

        def walk_imports(ea: int, name: str, ordinal: int) -> bool:
            imports.append([ea, name, ordinal])
            return True

        ida_nalt.enum_import_names(idx, walk_imports)
        ea, name, ordinal = imports[-1]

    return imports


def get_exports():
    for idx in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(idx)
        name = ida_entry.get_entry_name(ordinal)
        ea = ida_entry.get_entry(ordinal)
        yield ea, name, ordinal


@functools.lru_cache(maxsize=None)
def get_function_ea_from_import(module_name: str, function_name: str) -> int:
    imports_qty = idaapi.get_import_module_qty()
    for idx in range(imports_qty):
        if module_name != idaapi.get_import_module_name(idx):
            continue

        function_ea = [idaapi.BADADDR]

        def find_function_ea(ea: int, name: str, ord: int) -> bool:
            if function_name != name:
                return True

            function_ea[0] = ea
            return False

        idaapi.enum_import_names(idx, find_function_ea)
        return function_ea[0]

    return idaapi.BADADDR


def get_function_ea_by_name(required_name: str) -> int:
    for ea in idautils.Functions():
        name = idaapi.get_func_name(ea)
        if name == required_name:
            return ea

    return idaapi.BADADDR


def get_function(file_name: str, function_name: str) -> Iterator[int]:
    opened_file = idaapi.get_root_filename()
    if opened_file == file_name:
        return get_function_ea_by_name(function_name)

    else:
        module_name = file_name.split(".")[0]
        return get_function_ea_from_import(module_name, function_name)


def get_functions(
    start_ea: Optional[int] = ida_ida.cvar.inf.min_ea,
    end_ea: Optional[int] = ida_ida.cvar.inf.max_ea,
) -> Iterator[Function]:
    """
    Tweaked version of the idautils `Functions` helper
    """

    chunk = ida_funcs.get_fchunk(start_ea)
    if not chunk:
        chunk = ida_funcs.get_next_fchunk(start_ea)

    while (
        chunk and chunk.start_ea < end_ea and (chunk.flags & ida_funcs.FUNC_TAIL) != 0
    ):
        chunk = ida_funcs.get_next_fchunk(chunk.start_ea)

    function = chunk
    while function and function.start_ea < end_ea:
        yield function
        function = ida_funcs.get_next_func(function.start_ea)


def get_enum(name: str) -> Enum:
    enum = f"{NAME}_{name}"
    enum = idaapi.get_enum(name)
    if enum != idaapi.BADADDR:
        return enum

    return idaapi.add_enum(0, name, idaapi.hex_flag())


def new_enum(name: str, values: Dict[int, str]) -> Enum:
    enum = get_enum(name)
    for value, label in values.items():
        add_enum_member(enum, label, value)

    return enum


def apply_enum(enum: Enum, value_ea: int) -> None:
    idaapi.op_enum(value_ea, 1, enum, 0)


def add_enum_member(enum: Enum, member_name: str, member_value: str) -> bool:
    member_name = f"{NAME}_{member_name}"
    value = idaapi.get_enum_member(enum, member_value, 0, 0)
    if value != idaapi.BADADDR:
        return True

    ret = idaapi.add_enum_member(enum, member_name, member_value)
    if ret != 0:
        reasons = {
            1: "already have member with this name (bad name) (CONST_ERROR_NAME)",
            2: "already have member with this value (CONST_ERROR_VALUE)",
            3: "bad enum id (CONST_ERROR_ENUM)",
            4: "bad bmask (CONST_ERROR_MASK)",
            5: "bad bmask and value combination (~bmask & value != 0) (CONST_ERROR_ILLV)",
        }
        reason = reasons.get(ret, "unknow reason")
        error(f"Cannot add enum member: {reason}")

    return ret == 0


def find_enum_values(enum: Enum, hooks: Hooks, callback: Callable[[Enum, int], None]):
    # 🛷
    for module_name, function_names in hooks.items():
        for function_name, arg_position in function_names:
            ea = get_function(module_name, function_name)
            for xref in idautils.XrefsTo(ea):
                args = idaapi.get_arg_addrs(xref.frm)
                if args is None:  # e.g. xref in a vtable
                    continue

                # Value may be fetched with the Hex-Rays API
                value_ea = args[arg_position - 1]
                callback(enum, value_ea)


def get_imm_value(insn: Insn, operand_position: int) -> int:
    """Get value when its immediate like `mov edx, 53646641h`"""
    return insn.ops[operand_position].value


def get_value(ea: int) -> int:
    insn = get_instruction(ea)
    if insn.itype == idaapi.NN_mov and insn.ops[1].type == idc.o_imm:
        return get_imm_value(insn, 1)

    if all(
        [
            insn.itype == idaapi.NN_xor,
            len(insn.ops) >= 2,
            insn.ops[0].reg == insn.ops[1].reg,
        ]
    ):
        return 0

    return None


def get_compared_value(ea: int, end_ea: int) -> int:
    insn = get_instruction(ea)
    # cmp r12d, 9876C04Ch
    if insn.itype == idaapi.NN_cmp and insn.ops[1].type == idc.o_imm:
        return get_imm_value(insn, 1)

    # mov edx, 9876C004h

    # cmp r12d, edx
    if insn.itype == idaapi.NN_mov:
        next_ea = ida_bytes.next_head(ea, end_ea)
        if next_ea >= end_ea or next_ea == ida_idaapi.BADADDR:
            return None

        next_insn = get_instruction(next_ea)
        if next_insn.itype == idaapi.NN_cmp:
            return get_imm_value(insn, 1)


def get_segments() -> Iterator[Segment]:
    for segment_id in range(ida_segment.get_segm_qty()):
        segment = ida_segment.getnseg(segment_id)
        if not segment:
            continue

        yield segment


def walk_forward(
    start: Optional[int] = ida_ida.cvar.inf.min_ea,
    end: Optional[int] = ida_ida.cvar.inf.max_ea,
):
    ea = start
    if not idc.is_head(ida_bytes.get_flags(ea)):
        ea = ida_bytes.next_head(ea, end)

    while ea < end and ea != ida_idaapi.BADADDR:
        yield ea
        ea = ida_bytes.next_head(ea, end)


def walk_backward(
    start: Optional[int] = ida_ida.cvar.inf.max_ea,
    end: Optional[int] = ida_ida.cvar.inf.min_ea,
):
    ea = start
    ea = ida_bytes.prev_head(start, end)
    ea = ida_bytes.prev_head(start, end)

    while ea >= end and ea != ida_idaapi.BADADDR:
        yield ea
        ea = ida_bytes.prev_head(ea, end)


def find_value(start_ea: int, register_name: str):
    """
    Try to statically find the value of `register_name` at `start_ea`
    """
    ea = start_ea
    for ea in walk_backward(ea):
        insn = get_instruction(ea)
        if insn.itype != idaapi.NN_mov:
            continue

        if all(
            [  # mov reg, value
                insn.itype == idaapi.NN_mov,
                insn.ops[0].type == idc.o_reg,
                insn.ops[0].reg == getattr(idautils.procregs, register_name).reg,
                insn.ops[1].type == idc.o_imm,
            ]
        ):
            return ea, get_imm_value(insn, 1)

        # mov reg1, reg2 -> find_value(ea, reg2)
        xrefs = [xref.frm for xref in idautils.XrefsTo(ea)]
        if len(xrefs) > 1:
            break

    return None, None
