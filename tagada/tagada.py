from . import ioctls, memory_tags


def run() -> None:
    memory_tags.run()
    ioctls.run()
