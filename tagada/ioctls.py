"""
Search IOCTLs
* http://www.ioctls.net/
"""

import dataclasses
from typing import Dict

import idaapi

from .idautils import add_enum_member, get_enum, get_value
from .types import Enum
from .utils import error, find_enum_values, info

DEVICE_TYPES = {
    0x00000001: "DEVICE_BEEP",
    0x00000002: "DEVICE_CD_ROM",
    0x00000003: "DEVICE_CD_ROM_FILE_SYSTEM",
    0x00000004: "DEVICE_CONTROLLER",
    0x00000005: "DEVICE_DATALINK",
    0x00000006: "DEVICE_DFS",
    0x00000007: "DEVICE_DISK",
    0x00000008: "DEVICE_DISK_FILE_SYSTEM",
    0x00000009: "DEVICE_FILE_SYSTEM",
    0x0000000A: "DEVICE_INPORT_PORT",
    0x0000000B: "DEVICE_KEYBOARD",
    0x0000000C: "DEVICE_MAILSLOT",
    0x0000000D: "DEVICE_MIDI_IN",
    0x0000000E: "DEVICE_MIDI_OUT",
    0x0000000F: "DEVICE_MOUSE",
    0x00000010: "DEVICE_MULTI_UNC_PROVIDER",
    0x00000011: "DEVICE_NAMED_PIPE",
    0x00000012: "DEVICE_NETWORK",
    0x00000013: "DEVICE_NETWORK_BROWSER",
    0x00000014: "DEVICE_NETWORK_FILE_SYSTEM",
    0x00000015: "DEVICE_NULL",
    0x00000016: "DEVICE_PARALLEL_PORT",
    0x00000017: "DEVICE_PHYSICAL_NETCARD",
    0x00000018: "DEVICE_PRINTER",
    0x00000019: "DEVICE_SCANNER",
    0x0000001A: "DEVICE_SERIAL_MOUSE_PORT",
    0x0000001B: "DEVICE_SERIAL_PORT",
    0x0000001C: "DEVICE_SCREEN",
    0x0000001D: "DEVICE_SOUND",
    0x0000001E: "DEVICE_STREAMS",
    0x0000001F: "DEVICE_TAPE",
    0x00000020: "DEVICE_TAPE_FILE_SYSTEM",
    0x00000021: "DEVICE_TRANSPORT",
    0x00000022: "DEVICE_UNKNOWN",
    0x00000023: "DEVICE_VIDEO",
    0x00000024: "DEVICE_VIRTUAL_DISK",
    0x00000025: "DEVICE_WAVE_IN",
    0x00000026: "DEVICE_WAVE_OUT",
    0x00000027: "DEVICE_8042_PORT",
    0x00000028: "DEVICE_NETWORK_REDIRECTOR",
    0x00000029: "DEVICE_BATTERY",
    0x0000002A: "DEVICE_BUS_EXTENDER",
    0x0000002B: "DEVICE_MODEM",
    0x0000002C: "DEVICE_VDM",
    0x0000002D: "DEVICE_MASS_STORAGE",
    0x0000002E: "DEVICE_SMB",
    0x0000002F: "DEVICE_KS",
    0x00000030: "DEVICE_CHANGER",
    0x00000031: "DEVICE_SMARTCARD",
    0x00000032: "DEVICE_ACPI",
    0x00000033: "DEVICE_DVD",
    0x00000034: "DEVICE_FULLSCREEN_VIDEO",
    0x00000035: "DEVICE_DFS_FILE_SYSTEM",
    0x00000036: "DEVICE_DFS_VOLUME",
    0x00000037: "DEVICE_SERENUM",
    0x00000038: "DEVICE_TERMSRV",
    0x00000039: "DEVICE_KSEC",
    0x0000003A: "DEVICE_FIPS",
    0x0000003B: "DEVICE_INFINIBAND",
    0x0000003E: "DEVICE_VMBUS",
    0x0000003F: "DEVICE_CRYPT_PROVIDER",
    0x00000040: "DEVICE_WPD",
    0x00000041: "DEVICE_BLUETOOTH",
    0x00000042: "DEVICE_MT_COMPOSITE",
    0x00000043: "DEVICE_MT_TRANSPORT",
    0x00000044: "DEVICE_BIOMETRIC",
    0x00000045: "DEVICE_PMI",
    0x00000046: "DEVICE_EHSTOR",
    0x00000047: "DEVICE_DEVAPI",
    0x00000048: "DEVICE_GPIO",
    0x00000049: "DEVICE_USBEX",
    0x00000050: "DEVICE_CONSOLE",
    0x00000051: "DEVICE_NFP",
    0x00000052: "DEVICE_SYSENV",
    0x00000053: "DEVICE_VIRTUAL_BLOCK",
    0x00000054: "DEVICE_POINT_OF_SERVICE",
    0x00000055: "DEVICE_STORAGE_REPLICATION",
    0x00000056: "DEVICE_TRUST_ENV",
    0x00000057: "DEVICE_UCM",
    0x00000058: "DEVICE_UCMTCPCI",
    0x00000059: "DEVICE_PERSISTENT_MEMORY",
    0x0000005A: "DEVICE_NVDIMM",
    0x0000005B: "DEVICE_HOLOGRAPHIC",
    0x0000005C: "DEVICE_SDFXHCI",
    0x00000F60: "DEVICE_IRCLASS",
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
    return device_types.get(index, "DEVICE_UNKNOWN")


def ioctl_get_function_code(io_control_code: int) -> int:
    function_code = bin(io_control_code)[2:][-14:-2]
    function_code = int(function_code, 2)
    return function_code


def ioctl_get_access_check(
    io_control_code: int, access_checks: Dict[int, str] = ACCESS_CHECKS
) -> str:
    index = (io_control_code & 0x0000FFFF) >> 14
    return access_checks.get(index, "ACCESS_CHECK_UNKNOWN")


def ioctl_get_io_method(
    io_control_code: int, io_methods: Dict[int, str] = IO_METHODS
) -> str:
    index = bin(io_control_code)[2:][-2:]
    index = int(index, 2)
    return io_methods.get(index, "METHOD_UNKNOWN")


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


def apply_ioctl(enum: Enum, value_ea: int) -> None:
    value = get_value(value_ea)
    if value is None:
        error(f"Cannot decode IOCTL at {value_ea:#x}")
        return

    name = "IOCTL_{0:0{1}X}".format(value, 16)
    info(f"{IOCTL(value)} set at {value_ea:#x}")
    if add_enum_member(enum, name, value) is False:
        error(f"Cannot add tag to tags enum (name: {name}, value: {value:#x}")
        return

    idaapi.op_enum(value_ea, 1, enum, 0)


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
    find_enum_values(enum, hooks, apply_ioctl)
