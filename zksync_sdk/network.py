from dataclasses import dataclass

from zksync_sdk.types import ChainId


@dataclass
class Network:
    zksync_url: str
    chain_id: ChainId


rinkeby = Network(zksync_url="https://rinkeby-api.zksync.io/jsrpc", chain_id=ChainId.RINKEBY)
ropsten = Network(zksync_url="https://ropsten-api.zksync.io/jsrpc", chain_id=ChainId.ROPSTEN)
mainnet = Network(zksync_url="https://api.zksync.io/jsrpc", chain_id=ChainId.MAINNET)
localhost = Network(zksync_url="http://localhost:3030/jsrpc", chain_id=ChainId.LOCALHOST)
