"""
Search IOCTLs
* http://www.ioctls.net/
"""

import idaapi
import idautils

from .idautils import add_enum_member, get_enum, get_function, get_value
from .utils import error, info


def apply_ioctl(enum, value_ea: int) -> None:
    value = get_value(value_ea)
    if value is None:
        error(f"Cannot decode IOCTL at {value_ea:#x}")
        return

    name = "IOCTL_{0:0{1}X}".format(value, 16)
    info(f"IOCTL {name} ({value:#016x}) set at {value_ea:#x}")
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
    # 🛷
    for module_name, function_names in hooks.items():
        for function_name, tag_arg_position in function_names:
            ea = get_function(module_name, function_name)
            for xref in idautils.XrefsTo(ea):
                args = idaapi.get_arg_addrs(xref.frm)
                if args is None:  # e.g. xref in a vtable
                    continue

                tag_value_ea = args[tag_arg_position - 1]
                apply_ioctl(enum, tag_value_ea)
