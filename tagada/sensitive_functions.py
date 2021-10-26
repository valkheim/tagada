import idaapi
import idautils

# https://www.researchgate.net/publication/325272020_An_Automated_Vulnerability_Detection_and_Remediation_Method_for_Software_Security
SENSITIVE_MARKERS = [
    "memcpy",
    "memset",
    "memmove",
    "strcpy",
    "wcwcpy",
    "stpcpy",
    "wcpcpy",
    "strecpy",
    "strcat",
    "wcscat",
    "streadd",
    "strtrns",
    "printf",
    "sprintf",
    "snprintf",
    "fprintf",
    "vsprintf",
    "vsnprintf",
    "vprintf",
    "vfprintf",
    "asprintf",
    "vasprintf",
    "vdprintf",
    "dprintf",
    "gets",
    "getwd",
    "getpw",
    "realpath",
    "syslog",
    "vsyslog",
    "strtok",
    "wcstok",
    "itoa",
    "makepath",
    "scanf",
    "fscanf",
    "vscanf",
    "vsscanf",
    "sscanf",
    "vfscanf",
    "snscanf",
    "strlen",
]


def is_sensitive(name: str) -> bool:
    name = name.casefold()
    for marker in SENSITIVE_MARKERS:
        if name.endswith("_s"):  # e.g memset != memset_s
            continue

        if marker == "gets" and name != "gets":  # GetSystem...
            continue

        if marker in name:
            return True

    return False


def check_function(ea: int, name: str) -> bool:
    if not is_sensitive(name):
        return False

    xrefs = [xref.frm for xref in idautils.XrefsTo(ea) if xref.iscode]
    if xrefs == []:
        return False

    print(f"{ea:#x} -- {name}")
    for xref in xrefs:
        print(f"  {xref:#x}")

    return True


def run():
    for ea in idautils.Functions():
        name = idaapi.get_func_name(ea)
        # for ea, name, _ in get_imports():
        check_function(ea, name)
