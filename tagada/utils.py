from typing import Callable, Optional

import idaapi
import idautils

from .idautils import get_function
from .types import Enum, Hooks


def log(message: str, scope: Optional[str] = None) -> None:
    if scope is None:
        idaapi.msg(f"{message}\n")

    else:
        idaapi.msg(f"[{scope}] {message}\n")


def info(message: str) -> None:
    log(message, scope="INFO")


def debug(message: str) -> None:
    log(message, scope="DEBUG")


def warning(message: str) -> None:
    log(message, scope="WARNING")


def error(message: str) -> None:
    log(message, scope="ERROR")


def find_enum_values(enum: Enum, hooks: Hooks, callback: Callable[[Enum, int], None]):
    # 🛷
    for module_name, function_names in hooks.items():
        for function_name, arg_position in function_names:
            ea = get_function(module_name, function_name)
            for xref in idautils.XrefsTo(ea):
                args = idaapi.get_arg_addrs(xref.frm)
                if args is None:  # e.g. xref in a vtable
                    continue

                # Value may be fetched with the Hex-Rays API
                value_ea = args[arg_position - 1]
                callback(enum, value_ea)
