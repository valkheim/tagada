from typing import Iterator

import idaapi
import idautils
import idc

from .idautils import add_enum_member, find_import, get_enum, get_function_ea_by_name
from .utils import info, warning

ENUM_NAME = "MEMORY_TAGS"
ENUM_MEMBER_PREFIX = "MEMORY_TAG"


def yield_function_from_imports(module_name: str, function_name: str) -> Iterator[int]:
    ea = find_import(module_name, function_name)
    if ea != idaapi.BADADDR:
        yield ea


def yield_function(file_name: str, function_name: str) -> Iterator[int]:
    opened_file = idaapi.get_root_filename()
    if opened_file == file_name:
        yield get_function_ea_by_name(function_name)

    else:
        module_name = file_name.split(".")[0]
        yield from yield_function_from_imports(module_name, function_name)


def apply_tag(enum, tag_value_ea: int) -> None:
    insn = idaapi.insn_t()
    idaapi.decode_insn(insn, tag_value_ea)
    if (
        insn.itype == idaapi.NN_mov and insn.ops[1].type == idc.o_imm
    ):  # mov edx, 53646641h ; Tag
        tag_value = insn.ops[1].value
        tag_suffix = b"".fromhex(hex(tag_value)[2:])[::-1].decode("utf-8")  # unidecode
        tag_name = f"{ENUM_MEMBER_PREFIX}_{tag_suffix}"
        info(f"Tag set @{hex(tag_value_ea)} — {hex(tag_value)} — {tag_name}")
        add_enum_member(enum, tag_name, tag_value)
        idaapi.op_enum(tag_value_ea, 1, enum, 0)

    else:
        warning(f"cannot decode tag at {hex(tag_value_ea)}")


def run():
    enum = get_enum(ENUM_NAME)
    hooks = {
        "ntoskrnl.exe": [
            ("ExAllocatePool2", 3),
            ("ExAllocatePool3", 3),
            ("ExAllocatePoolPriorityUninitialized", 3),
            ("ExAllocatePoolPriorityZero", 3),
            ("ExAllocatePoolQuotaUninitialized", 3),
            ("ExAllocatePoolQuotaZero", 3),
            ("ExAllocatePoolUninitialized", 3),
            ("ExAllocatePoolWithQuotaTag", 3),
            ("ExAllocatePoolWithTag", 3),
            ("ExAllocatePoolWithTagPriority", 3),
            ("ExAllocatePoolZero", 3),
            ("ExCreatePool", 2),
            ("ExFreePool2", 2),
            ("ExFreePoolWithTag", 2),
            ("ObDereferenceObjectDeferDeleteWithTag", 2),
            ("ExInitializeLookasideListEx", 7),
            ("ExInitializeNPagedLookaside", 6),
            ("ExInitializePagedLookasideList", 6),
            ("ExSecurePoolUpdate", 2),
            ("ExSecurePoolValidate", 2),
        ],
        "afd.sys": [
            ("PplCreateLookasideList", 6),
            ("PplCreateLookasideList", 8),
        ],
    }
    for module_name, function_names in hooks.items():
        for function_name, tag_arg_position in function_names:
            for ea in yield_function(module_name, function_name):
                info(f"{module_name} — Tag used @{hex(ea)} in {function_name}")
                for xref in idautils.XrefsTo(ea):
                    args = idaapi.get_arg_addrs(xref.frm)
                    if args is None:  # e.g. xref in a vtable
                        continue

                    tag_value_ea = args[tag_arg_position - 1]
                    apply_tag(enum, tag_value_ea)
