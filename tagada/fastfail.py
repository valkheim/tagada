import ida_allins

from .idautils import (
    add_enum_member,
    apply_enum,
    find_value,
    get_enum,
    get_functions,
    get_imm_value,
    get_instruction,
    walk_forward,
)
from .types import Enum
from .utils import error, info

FAST_FAIL = {
    0: "FAST_FAIL_LEGACY_GS_VIOLATION",
    1: "FAST_FAIL_VTGUARD_CHECK_FAILURE",
    2: "FAST_FAIL_STACK_COOKIE_CHECK_FAILURE",
    3: "FAST_FAIL_CORRUPT_LIST_ENTRY",
    4: "FAST_FAIL_INCORRECT_STACK",
    5: "FAST_FAIL_INVALID_ARG",
    6: "FAST_FAIL_GS_COOKIE_INIT",
    7: "FAST_FAIL_FATAL_APP_EXIT",
    8: "FAST_FAIL_RANGE_CHECK_FAILURE",
    9: "FAST_FAIL_UNSAFE_REGISTRY_ACCESS",
    10: "FAST_FAIL_GUARD_ICALL_CHECK_FAILURE",
    11: "FAST_FAIL_GUARD_WRITE_CHECK_FAILURE",
    12: "FAST_FAIL_INVALID_FIBER_SWITCH",
    13: "FAST_FAIL_INVALID_SET_OF_CONTEXT",
    14: "FAST_FAIL_INVALID_REFERENCE_COUNT",
    18: "FAST_FAIL_INVALID_JUMP_BUFFER",
    19: "FAST_FAIL_MRDATA_MODIFIED",
    20: "FAST_FAIL_CERTIFICATION_FAILURE",
    21: "FAST_FAIL_INVALID_EXCEPTION_CHAIN",
    22: "FAST_FAIL_CRYPTO_LIBRARY",
    23: "FAST_FAIL_INVALID_CALL_IN_DLL_CALLOUT",
    24: "FAST_FAIL_INVALID_IMAGE_BASE",
    25: "FAST_FAIL_DLOAD_PROTECTION_FAILURE",
    26: "FAST_FAIL_UNSAFE_EXTENSION_CALL",
    27: "FAST_FAIL_DEPRECATED_SERVICE_INVOKED",
    28: "FAST_FAIL_INVALID_BUFFER_ACCESS",
    29: "FAST_FAIL_INVALID_BALANCED_TREE",
    30: "FAST_FAIL_INVALID_NEXT_THREAD",
    31: "FAST_FAIL_GUARD_ICALL_CHECK_SUPPRESSED",
    32: "FAST_FAIL_APCS_DISABLED",
    33: "FAST_FAIL_INVALID_IDLE_STATE",
    34: "FAST_FAIL_MRDATA_PROTECTION_FAILURE",
    35: "FAST_FAIL_UNEXPECTED_HEAP_EXCEPTION",
    36: "FAST_FAIL_INVALID_LOCK_STATE",
    37: "FAST_FAIL_GUARD_JUMPTABLE",
    38: "FAST_FAIL_INVALID_LONGJUMP_TARGET",
    39: "FAST_FAIL_INVALID_DISPATCH_CONTEXT",
    40: "FAST_FAIL_INVALID_THREAD",
    41: "FAST_FAIL_INVALID_SYSCALL_NUMBER",
    42: "FAST_FAIL_INVALID_FILE_OPERATION",
    43: "FAST_FAIL_LPAC_ACCESS_DENIED",
    44: "FAST_FAIL_GUARD_SS_FAILURE",
    45: "FAST_FAIL_LOADER_CONTINUITY_FAILURE",
    46: "FAST_FAIL_GUARD_EXPORT_SUPPRESSION_FAILURE",
    47: "FAST_FAIL_INVALID_CONTROL_STACK",
    48: "FAST_FAIL_SET_CONTEXT_DENIED",
    49: "FAST_FAIL_INVALID_IAT",
    50: "FAST_FAIL_HEAP_METADATA_CORRUPTION",
    51: "FAST_FAIL_PAYLOAD_RESTRICTION_VIOLATION",
    52: "FAST_FAIL_LOW_LABEL_ACCESS_DENIED",
    53: "FAST_FAIL_ENCLAVE_CALL_FAILURE",
    54: "FAST_FAIL_UNHANDLED_LSS_EXCEPTON",
    55: "FAST_FAIL_ADMINLESS_ACCESS_DENIED",
    56: "FAST_FAIL_UNEXPECTED_CALL",
    57: "FAST_FAIL_CONTROL_INVALID_RETURN_ADDRESS",
    0xFFFFFFFF: "FAST_FAIL_INVALID_FAST_FAIL_CODE",
}


def apply_fast_fail(enum: Enum, ea: int, value: int) -> bool:
    if value not in FAST_FAIL:
        error(f"Cannot add FAST_FAIL, enum member name not found for value {value:#x}")
        return False

    enum_member_name = FAST_FAIL[value]
    if add_enum_member(enum, enum_member_name, int(value)) is False:
        error("Cannot add FAST_FAIL enum member")
        return False

    apply_enum(enum, ea)
    info(f"{enum_member_name} set at {ea:#x}")
    return True


def find_fast_fail_interrupts():
    for function in get_functions():
        for head in walk_forward(function.start_ea, function.end_ea):
            insn = get_instruction(head)
            if insn.itype != ida_allins.NN_int:
                continue

            interrupt_number = get_imm_value(insn, 0)
            if interrupt_number != 0x29:  # KiRaiseSecurityFailure / __fastfail
                continue

            ea, value = find_value(head, "ecx")
            if value is None:
                error(f"Cannot get FAST_FAIL value at {head:#x}")
                break

            yield ea, value


def run() -> None:
    enum = get_enum("FAST_FAIL")
    for ea, value in find_fast_fail_interrupts():
        apply_fast_fail(enum, ea, value)
