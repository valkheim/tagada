from . import bugcheck, ioctls, memory_tags, ntstatus


def run() -> None:
    ntstatus.run()
    memory_tags.run()
    ioctls.run()
    bugcheck.run()
