from dataclasses import dataclass

from zksync_sdk.types import ChainId


@dataclass
class Network:
    zksync_url: str
    chain_id: ChainId


rinkeby = Network(zksync_url="https://rinkeby-api.zksync.io/jsrpc", chain_id=ChainId.RINKEBY)
