from . import bugcheck, fastfail, ioctls, memory_tags, ntstatus, sensitive_functions


def run() -> None:
    fastfail.run()
    ntstatus.run()
    memory_tags.run()
    ioctls.run()
    bugcheck.run()
    sensitive_functions.run()
