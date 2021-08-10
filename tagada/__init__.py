import os

from .tagada import *  # noqa: F401,F403
from .utils import *  # noqa: F401,F403

NAME = os.path.basename(os.path.dirname(os.path.realpath(__file__))).capitalize()
