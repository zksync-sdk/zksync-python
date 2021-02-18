from zksync_sdk.ethereum_provider import EthereumProvider
from zksync_sdk.signer import EthereumSigner, ZkSyncSigner
from zksync_sdk.zksyncprovider import ZkSyncProvider


class Wallet:
    def __init__(self, ethereum_provider: EthereumProvider, zk_signer: ZkSyncSigner,
                 eth_signer: EthereumSigner, provider: ZkSyncProvider):
        self.ethereum_provider = ethereum_provider
        self.zk_signer = zk_signer
        self.eth_signer = eth_signer
        self.zk_provider = provider
