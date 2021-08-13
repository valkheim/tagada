import functools
from typing import Dict, Iterator, Optional

import ida_funcs
import ida_ida
import ida_segment
import idaapi
import idautils
import idc

from .types import Enum, Function, Insn, Segment


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
    enum = idaapi.get_enum(name)
    if enum != idaapi.BADADDR:
        return enum

    return idaapi.add_enum(0, name, idaapi.hex_flag())


def new_enum(name: str, values: Dict[int, str]) -> Enum:
    enum = get_enum(name)
    for value, label in values.items():
        add_enum_member(enum, label, value)

    return enum


def add_enum_member(enum: Enum, member_name: str, member_value: str) -> bool:
    value = idaapi.get_enum_member(enum, member_value, 0, 0)
    if value != idaapi.BADADDR:
        return True

    return idaapi.add_enum_member(enum, member_name, member_value) == 0


def get_imm_value(insn: Insn) -> int:
    """Get value when its immediate like `mov edx, 53646641h`"""
    return insn.ops[1].value


def get_value(ea: int) -> int:
    insn = idaapi.insn_t()
    idaapi.decode_insn(insn, ea)
    if insn.itype == idaapi.NN_mov and insn.ops[1].type == idc.o_imm:
        return get_imm_value(insn)

    return None


def get_segments() -> Iterator[Segment]:
    for segment_id in range(ida_segment.get_segm_qty()):
        segment = ida_segment.getnseg(segment_id)
        if not segment:
            continue

        yield segment
