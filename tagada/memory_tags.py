import idaapi
import idautils

from .idautils import add_enum_member, get_enum, get_function, get_value
from .utils import error, info


def apply_tag(enum, tag_value_ea: int) -> None:
    tag_value = get_value(tag_value_ea)
    if tag_value is None:
        error(f"Cannot decode tag at {tag_value_ea:#x}")
        return

    try:
        # Tag with printable chars
        tag_suffix = b"".fromhex(hex(tag_value)[2:])[::-1].decode("utf-8")  # unidecode

    except ValueError:
        # Fallback to a digits-based suffix
        tag_suffix = "{0:0{1}X}".format(tag_value, 8)

    except ValueError:
        error(f"Cannot get tag name for tag set at {tag_value_ea:#x}")
        return

    tag_name = f"MEMORY_TAG_{tag_suffix}"
    info(f"Tag {tag_name} ({tag_value:#08x}) set at {tag_value_ea:#x}")
    if add_enum_member(enum, tag_name, tag_value) is False:
        error(f"Cannot add tag to tags enum (name: {tag_name}, value: {tag_value:#x}")
        return

    idaapi.op_enum(tag_value_ea, 1, enum, 0)


def run():
    enum = get_enum("MEMORY_TAGS")
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
            ("PplGenericAllocateFunction", 3),  # Ppl
            ("PplCreateLookasideList", 6),
            ("PplCreateLookasideList", 8),
            ("PplDestroyLookasideList", 2),
            ("PplpCreateOneLookasideList", 6),  # Pplp
            ("PplpCreateOneLookasideList", 8),
            ("PplpFreeOneLookasideList", 2),
            ("PnlCreateLookasideList", 6),  # Pnl
            ("PnlCreateLookasideList", 8),
            ("AfdAllocateBuffer", 3),  # Afd
            ("AfdAllocateBufferTag", 3),
            ("AfdAllocateRemoteAddress", 3),
            ("AfdAllocateTpInfo", 3),
        ],
    }
    # 🛷
    for module_name, function_names in hooks.items():
        for function_name, tag_arg_position in function_names:
            ea = get_function(module_name, function_name)
            for xref in idautils.XrefsTo(ea):
                args = idaapi.get_arg_addrs(xref.frm)
                if args is None:  # e.g. xref in a vtable
                    continue

                tag_value_ea = args[tag_arg_position - 1]
                apply_tag(enum, tag_value_ea)
