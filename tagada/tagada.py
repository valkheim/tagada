import idaapi

from .idautils import find_import
from .utils import log


def run():
    log("Tagada!")
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

            log(f"{module_name} — {hex(ea)} — {tag_arg_position} — {function_name}")
