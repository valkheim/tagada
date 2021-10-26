from typing import Optional

import idaapi


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
