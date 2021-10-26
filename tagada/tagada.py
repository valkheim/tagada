from . import bugcheck, ioctls, memory_tags, ntstatus, sensitive_functions


def run() -> None:
    ntstatus.run()
    memory_tags.run()
    ioctls.run()
    bugcheck.run()
    sensitive_functions.run()
