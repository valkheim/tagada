import functools

import idaapi
import idautils


@functools.lru_cache(maxsize=None)
def find_import(module_name: str, function_name: str) -> int:
    imports_qty = idaapi.get_import_module_qty()
    for idx in range(imports_qty):
        if module_name != idaapi.get_import_module_name(idx):
            continue

        function_ea = [idaapi.BADADDR]

        def find_function_ea(ea: int, name: str, ord: int) -> bool:
            if function_name != name:
                return True

            function_ea[0] = ea
            return False

        idaapi.enum_import_names(idx, find_function_ea)
        return function_ea[0]

    return idaapi.BADADDR


def get_enum(name: str):
    enum = idaapi.get_enum(name)
    if enum != idaapi.BADADDR:
        return enum

    return idaapi.add_enum(0, name, idaapi.hex_flag())


def add_enum_member(enum, member_name: str, member_value: str):
    value = idaapi.get_enum_member(enum, member_value, 0, 0)
    if value != idaapi.BADADDR:
        return

    return idaapi.add_enum_member(enum, member_name, member_value)


def get_function_ea_by_name(required_name: str) -> int:
    for ea in idautils.Functions():
        name = idaapi.get_func_name(ea)
        if name == required_name:
            return ea

    return idaapi.BADADDR
