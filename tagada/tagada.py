from . import bugcheck, ioctls, memory_tags


def run() -> None:
    memory_tags.run()
    ioctls.run()
    bugcheck.run()
