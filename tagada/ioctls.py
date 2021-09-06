"""
Search IOCTLs
* http://www.ioctls.net/
* https://doxygen.reactos.org/d4/d1b/xdk_2iotypes_8h.html#a9d923a767e087cfeea12cf91f62f4f7a
"""

import dataclasses
from typing import Dict, List

import idaapi
import idautils

from .idautils import (
    add_enum_member,
    apply_enum,
    get_compared_value,
    get_enum,
    get_functions,
    get_segments,
    get_value,
)
from .types import Enum
from .utils import error, find_enum_values, info

DEVICE_TYPES = {
    0x00000001: "FILE_DEVICE_BEEP",
    0x00000002: "FILE_DEVICE_CD_ROM",
    0x00000003: "FILE_DEVICE_CD_ROM_FILE_SYSTEM",
    0x00000004: "FILE_DEVICE_CONTROLLER",
    0x00000005: "FILE_DEVICE_DATALINK",
    0x00000006: "FILE_DEVICE_DFS",
    0x00000007: "FILE_DEVICE_DISK",
    0x00000008: "FILE_DEVICE_DISK_FILE_SYSTEM",
    0x00000009: "FILE_DEVICE_FILE_SYSTEM",
    0x0000000A: "FILE_DEVICE_INPORT_PORT",
    0x0000000B: "FILE_DEVICE_KEYBOARD",
    0x0000000C: "FILE_DEVICE_MAILSLOT",
    0x0000000D: "FILE_DEVICE_MIDI_IN",
    0x0000000E: "FILE_DEVICE_MIDI_OUT",
    0x0000000F: "FILE_DEVICE_MOUSE",
    0x00000010: "FILE_DEVICE_MULTI_UNC_PROVIDER",
    0x00000011: "FILE_DEVICE_NAMED_PIPE",
    0x00000012: "FILE_DEVICE_NETWORK",
    0x00000013: "FILE_DEVICE_NETWORK_BROWSER",
    0x00000014: "FILE_DEVICE_NETWORK_FILE_SYSTEM",
    0x00000015: "FILE_DEVICE_NULL",
    0x00000016: "FILE_DEVICE_PARALLEL_PORT",
    0x00000017: "FILE_DEVICE_PHYSICAL_NETCARD",
    0x00000018: "FILE_DEVICE_PRINTER",
    0x00000019: "FILE_DEVICE_SCANNER",
    0x0000001A: "FILE_DEVICE_SERIAL_MOUSE_PORT",
    0x0000001B: "FILE_DEVICE_SERIAL_PORT",
    0x0000001C: "FILE_DEVICE_SCREEN",
    0x0000001D: "FILE_DEVICE_SOUND",
    0x0000001E: "FILE_DEVICE_STREAMS",
    0x0000001F: "FILE_DEVICE_TAPE",
    0x00000020: "FILE_DEVICE_TAPE_FILE_SYSTEM",
    0x00000021: "FILE_DEVICE_TRANSPORT",
    0x00000022: "FILE_DEVICE_UNKNOWN",
    0x00000023: "FILE_DEVICE_VIDEO",
    0x00000024: "FILE_DEVICE_VIRTUAL_DISK",
    0x00000025: "FILE_DEVICE_WAVE_IN",
    0x00000026: "FILE_DEVICE_WAVE_OUT",
    0x00000027: "FILE_DEVICE_8042_PORT",
    0x00000028: "FILE_DEVICE_NETWORK_REDIRECTOR",
    0x00000029: "FILE_DEVICE_BATTERY",
    0x0000002A: "FILE_DEVICE_BUS_EXTENDER",
    0x0000002B: "FILE_DEVICE_MODEM",
    0x0000002C: "FILE_DEVICE_VDM",
    0x0000002D: "FILE_DEVICE_MASS_STORAGE",
    0x0000002E: "FILE_DEVICE_SMB",
    0x0000002F: "FILE_DEVICE_KS",
    0x00000030: "FILE_DEVICE_CHANGER",
    0x00000031: "FILE_DEVICE_SMARTCARD",
    0x00000032: "FILE_DEVICE_ACPI",
    0x00000033: "FILE_DEVICE_DVD",
    0x00000034: "FILE_DEVICE_FULLSCREEN_VIDEO",
    0x00000035: "FILE_DEVICE_DFS_FILE_SYSTEM",
    0x00000036: "FILE_DEVICE_DFS_VOLUME",
    0x00000037: "FILE_DEVICE_SERENUM",
    0x00000038: "FILE_DEVICE_TERMSRV",
    0x00000039: "FILE_DEVICE_KSEC",
    0x0000003A: "FILE_DEVICE_FIPS",
    0x0000003B: "FILE_DEVICE_INFINIBAND",
    0x0000003E: "FILE_DEVICE_VMBUS",
    0x0000003F: "FILE_DEVICE_CRYPT_PROVIDER",
    0x00000040: "FILE_DEVICE_WPD",
    0x00000041: "FILE_DEVICE_BLUETOOTH",
    0x00000042: "FILE_DEVICE_MT_COMPOSITE",
    0x00000043: "FILE_DEVICE_MT_TRANSPORT",
    0x00000044: "FILE_DEVICE_BIOMETRIC",
    0x00000045: "FILE_DEVICE_PMI",
    0x00000046: "FILE_DEVICE_EHSTOR",
    0x00000047: "FILE_DEVICE_DEVAPI",
    0x00000048: "FILE_DEVICE_GPIO",
    0x00000049: "FILE_DEVICE_USBEX",
    0x00000050: "FILE_DEVICE_CONSOLE",
    0x00000051: "FILE_DEVICE_NFP",
    0x00000052: "FILE_DEVICE_SYSENV",
    0x00000053: "FILE_DEVICE_VIRTUAL_BLOCK",
    0x00000054: "FILE_DEVICE_POINT_OF_SERVICE",
    0x00000055: "FILE_DEVICE_STORAGE_REPLICATION",
    0x00000056: "FILE_DEVICE_TRUST_ENV",
    0x00000057: "FILE_DEVICE_UCM",
    0x00000058: "FILE_DEVICE_UCMTCPCI",
    0x00000059: "FILE_DEVICE_PERSISTENT_MEMORY",
    0x0000005A: "FILE_DEVICE_NVDIMM",
    0x0000005B: "FILE_DEVICE_HOLOGRAPHIC",
    0x0000005C: "FILE_DEVICE_SDFXHCI",
    0x0000005d: "FILE_DEVICE_UCMUCSI",
    0x00000F60: "FILE_DEVICE_IRCLASS",
}

ACCESS_CHECKS = {
    0x0000: "FILE_ANY_ACCESS",
    0x0001: "FILE_READ_ACCESS",
    0x0002: "FILE_WRITE_ACCESS",
    0x0003: "FILE_READ_ACCESS | FILE_WRITE_ACCESS",
}

IO_METHODS = {
    0x0: "METHOD_BUFFERED",
    0x1: "METHOD_IN_DIRECT",
    0x2: "METHOD_OUT_DIRECT",
    0x3: "METHOD_NEITHER",
}


def ioctl_get_device_type(
    io_control_code: int, device_types: Dict[int, str] = DEVICE_TYPES
) -> str:
    index = (io_control_code & 0xFFFF0000) >> 16
    return device_types.get(index, f"DEVICE_UNKNOWN_{index:X}")


def ioctl_get_function_code(io_control_code: int) -> int:
    try:
        function_code = bin(io_control_code)[2:][-14:-2]
        function_code = int(function_code, 2)
        return function_code

    except ValueError:
        return -1


def ioctl_get_access_check(
    io_control_code: int, access_checks: Dict[int, str] = ACCESS_CHECKS
) -> str:
    index = (io_control_code & 0x0000FFFF) >> 14
    return access_checks.get(index, f"ACCESS_CHECK_UNKNOWN_{index:X}")


def ioctl_get_io_method(
    io_control_code: int, io_methods: Dict[int, str] = IO_METHODS
) -> str:
    index = bin(io_control_code)[2:][-2:]
    index = int(index, 2)
    return io_methods.get(index, f"METHOD_UNKNOWN_{index:X}")


@dataclasses.dataclass(frozen=True)
class IOCTL:
    io_control_code: int

    def __post_init__(self):
        object.__setattr__(
            self, "device_type", ioctl_get_device_type(self.io_control_code)
        )
        object.__setattr__(
            self, "function_code", ioctl_get_function_code(self.io_control_code)
        )
        object.__setattr__(
            self, "access_check", ioctl_get_access_check(self.io_control_code)
        )
        object.__setattr__(self, "io_method", ioctl_get_io_method(self.io_control_code))

    def __repr__(self) -> str:
        return (
            f"IOCTL(io_control_code={self.io_control_code:#08x}, "
            f"function_code={self.function_code:#08x}, "
            f"device_type={self.device_type}, "
            f"access_check={self.access_check}, "
            f"io_method={self.io_method})"
        )


def create_ioctl(enum: Enum, value_ea: int, value: int) -> None:
    name = "IOCTL_{0:0{1}X}".format(value, 16)
    if add_enum_member(enum, name, value) is False:
        error(f"Cannot add ioctl enum member (name: {name}, value: {value:#x}")
        return


def ioctl_hooks_callback(enum: Enum, value_ea: int) -> None:
    value = get_value(value_ea)
    if value is None:
        error(f"Cannot decode IOCTL at {value_ea:#x}")
        return

    create_ioctl(enum, value_ea, value)
    apply_enum(enum, value_ea)
    info(f"{IOCTL(value)} set at {value_ea:#x}")


def find_ioctls_in_range(enum: Enum, start_ea: int, end_ea: int) -> List[int]:
    """
    https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes
    Check common/custom bit for vendor-assigned values
    Check against known values (e.g. http://www.ioctls.net/)
    """
    for head in idautils.Heads(start_ea, end_ea):
        value = get_compared_value(head, end_ea)
        if value is None:
            continue

        value &= 0xFFFFFFFF
        if value in (0xFFFFFFFF, 0x80000000, 0x00000000):
            continue

        # device type > 0x8000
        if ((value & 0xFFFF0000) >> 16) < 0x8000:
            continue

        # try to skip extreme value, nt status value
        if value >> 24 in (0xFF, 0xC0):
            continue

        info(f"{IOCTL(value)} set at {head:#x}")
        create_ioctl(enum, head, value)
        apply_enum(enum, head)


def find_enum_values_in_memory(enum: Enum):
    for segment in get_segments():
        if idaapi.segtype(segment.start_ea) != idaapi.SEG_CODE:
            continue

        for function in get_functions(segment.start_ea, segment.end_ea):
            find_ioctls_in_range(enum, function.start_ea, function.end_ea)


def run():
    enum = get_enum("IOCTLS")
    hooks = {
        "ntoskrnl.exe": [
            ("IoBuildDeviceIoControlRequest", 1),
            ("FsRtlIssueDeviceIoControl", 1),
            ("NtDeviceIoControlFile", 6),
            ("ZwDeviceIoControlFile", 6),
            ("IopXxxControlFile", 6),
        ],
        "api-ms-win-core-io-l1-1-0.dll": [  # ApiSet Stub DLL
            ("DeviceIoControl", 2),
        ],
        "ntdll.dll": [  #  NT Layer DLL
            ("NtDeviceIoControlFile", 6),
            ("ZwDeviceIoControlFile", 6),
        ],
        "kernel32.dll": [  # Windows NT BASE API Client DLL
            ("DeviceIoControlImplementation", 2),
            ("BasepDoTapeOperation", 2),
        ],
        "Ws2_32.dll": [  # Windows Socket 2.0 32-bit DLL
            ("WSAIoctl", 2),
            ("WSANSPIoctl", 2),
            ("NSQUERY::Ioctl", 2),
            ("TransferSocketIoctl", 2),
            ("ioctlsocket", 2),
        ],
    }
    find_enum_values(enum, hooks, ioctl_hooks_callback)
    find_enum_values_in_memory(enum)
