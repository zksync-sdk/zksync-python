from enum import IntEnum

from .responses import *
from .signatures import *
from .transactions import *
from .auth_types import *


class ChainId(IntEnum):
    MAINNET = 1
    RINKEBY = 4
    ROPSTEN = 3
    GOERLI = 420
    SEPOLIA = 11155111
    LOCALHOST = 9
