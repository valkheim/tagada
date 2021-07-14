import os

from .tagada import run  # noqa: F401
from .utils import debug, error, info, log, warning  # noqa: F401

NAME = os.path.basename(os.path.dirname(os.path.realpath(__file__))).capitalize()
