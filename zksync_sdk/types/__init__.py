from enum import IntEnum
from typing import Union

from .responses import *
from .signatures import *
from .transactions import *

TokenLike = Union[str, int]


class ChainId(IntEnum):
    MAINNET = 1
    RINKEBY = 4
    ROPSTEN = 3
    LOCALHOST = 9
