import idaapi
import idautils
import idc

from .idautils import find_import
from .utils import info, warning


def run():
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

            info(f"{module_name} — {hex(ea)} — {tag_arg_position} — {function_name}")
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
                    tag_name = b"".fromhex(hex(tag_value)[2:])[::-1]  # unidecode
                    info(f"{hex(tag_value_ea)} — {hex(tag_value)} — {tag_name}")

                else:
                    warning(f"cannot decode tag at {hex(tag_value_ea)}")
