import idaapi
import idautils
import idc

from .idautils import find_import
from .utils import debug, info, warning

ENUM_NAME = "MEMORY_TAGS"
ENUM_MEMBER_PREFIX = "MEMORY_TAG"


def get_enum(name: str = ENUM_NAME):
    enum = idaapi.get_enum(name)
    if enum != idaapi.BADADDR:
        return enum

    return idaapi.add_enum(0, name, idaapi.hex_flag())


def add_enum_member(enum, member_name: str, member_value: str):
    value = idaapi.get_enum_member(enum, member_value, 0, 0)
    if value != idaapi.BADADDR:
        return

    debug(f"add {member_name}")
    return idaapi.add_enum_member(enum, member_name, member_value)


def run():
    enum = get_enum()
    hooks = {
        "ntoskrnl": [
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
            ("ExAllocatePool", 3),
            ("ExCreatePool", 2),
            ("ExFreePool2", 2),
            ("ExFreePoolWithTag", 2),
            ("ObDereferenceObjectDeferDeleteWithTag", 2),
        ]
    }
    for module_name, function_names in hooks.items():
        for function_name, tag_arg_position in function_names:
            ea = find_import(module_name, function_name)
            if ea == idaapi.BADADDR:
                continue

            info(f"{module_name} — Tag used @{hex(ea)} in {function_name}")
            for xref in idautils.XrefsTo(ea):
                call_from = xref.frm
                info(f"  {hex(call_from)}")
                tag_value_ea = idaapi.get_arg_addrs(call_from)[tag_arg_position - 1]
                insn = idaapi.insn_t()
                idaapi.decode_insn(insn, tag_value_ea)
                if (
                    insn.itype == idaapi.NN_mov and insn.ops[1].type == idc.o_imm
                ):  # mov edx, 53646641h ; Tag
                    tag_value = insn.ops[1].value
                    tag_suffix = b"".fromhex(hex(tag_value)[2:])[::-1].decode(
                        "utf-8"
                    )  # unidecode
                    tag_name = f"{ENUM_MEMBER_PREFIX}_{tag_suffix}"
                    info(
                        f"Tag set @{hex(tag_value_ea)} — {hex(tag_value)} — {tag_name}"
                    )
                    add_enum_member(enum, tag_name, tag_value)
                    idaapi.op_enum(tag_value_ea, 1, enum, 0)

                else:
                    warning(
                        f"cannot decode tag at {hex(tag_value_ea)} of call {hex(call_from)}"
                    )
