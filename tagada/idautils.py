import functools
import idaapi

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
