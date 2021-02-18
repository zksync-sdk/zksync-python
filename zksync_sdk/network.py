from dataclasses import dataclass

from zksync_sdk.types import ChainId


@dataclass
class Network:
    zksync_url: str
    zksync_contract_address: str
    chain_id: ChainId


rinkeby = Network(zksync_url="https://rinkeby-api.zksync.io/jsrpc",
                  zksync_contract_address="0x82F67958A5474e40E1485742d648C0b0686b6e5D",
                  chain_id=ChainId.RINKEBY)
