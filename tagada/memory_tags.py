import idaapi

from .idautils import add_enum_member, find_enum_values, get_enum, get_value
from .types import Enum
from .utils import error, info


def apply_tag(enum: Enum, tag_value_ea: int) -> None:
    tag_value = get_value(tag_value_ea)
    if tag_value is None:
        error(f"Cannot decode memory tag at {tag_value_ea:#x}")
        return

    try:
        # Tag with printable chars
        tag_suffix = b"".fromhex(hex(tag_value)[2:])[::-1].decode("utf-8")  # unidecode

    except ValueError:
        # Fallback to a digit-based suffix
        tag_suffix = "{0:0{1}X}".format(tag_value, 8)

    except ValueError:
        error(f"Cannot craft memory tag name for tag set at {tag_value_ea:#x}")
        return

    tag_name = f"MEMORY_TAG_{tag_suffix}"
    info(f"Memory tag {tag_name} ({tag_value:#08x}) set at {tag_value_ea:#x}")
    if add_enum_member(enum, tag_name, tag_value) is False:
        error(f"Cannot add tag to tags enum (name: {tag_name}, value: {tag_value:#x}")
        return

    idaapi.op_enum(tag_value_ea, 1, enum, 0)


def run():
    enum = get_enum("MEMORY_TAGS")
    hooks = {
        "ntoskrnl.exe": [
            ("ExAllocateHeapPool", 3),
            ("ExCreatePool", 2),
            ("VfCheckPoolType", 3),
            ("ExAllocatePool2", 3),
            ("pXdvExAllocatePool2", 3),
            ("VerifierExAllocatePool2", 3),
            ("ExFreePool2", 2),
            ("ExAllocatePool3", 3),
            ("pXdvExAllocatePool3", 3),
            ("VerifierExAllocatePool3", 3),
            ("ExAllocatePoolMm", 3),
            ("ExAllocatePoolUninitialized", 3),
            ("ExAllocatePoolPriorityUninitialized", 3),
            ("ExAllocatePoolZero", 3),
            ("ExAllocatePoolPriorityZero", 3),
            ("ExAllocatePoolQuotaUninitialized", 3),
            ("ExAllocatePoolQuotaZero", 3),
            ("ExAllocatePoolWithTag", 3),
            ("ExAllocatePoolWithTagPriority", 3),
            ("pXdvExAllocatePoolWithTagPriority", 3),
            ("VeAllocatePoolWithTagPriority", 3),
            ("VerifierExAllocatePoolWithTagPriority", 3),
            ("VerifierPortExAllocatePoolWithTagPriority", 3),
            ("ExFreePoolWithTag", 2),
            ("ExAllocatePoolWithQuotaTag", 3),
            ("VerifierExAllocatePoolWithQuotaTag", 3),
            ("ExpAllocatePoolWithTagFromNode", 3),
            ("ObDereferenceObjectDeferDeleteWithTag", 2),
            ("ExInitializeLookasideListEx", 7),
            ("ExInitializeNPagedLookaside", 6),
            ("ExInitializePagedLookasideList", 6),
            ("ExSecurePoolUpdate", 2),
            ("ExSecurePoolValidate", 2),
            ("ObfReferenceObjectWithTag", 2),
            ("ObfDereferenceObjectWithTag", 2),
            ("ObReferenceObjectByHandleWithTag", 5),
            ("CmpAllocateTransientPoolWithTag", 3),
            ("ExAllocatePoolSanityChecks", 3),  # _Out_
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
    find_enum_values(enum, hooks, apply_tag)
