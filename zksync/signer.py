from zksync import ZkSyncLibrary
from zksync.types import ChainId


class ZkSyncSigner:
    MESSAGE = "Access zkSync account.\n\nOnly sign this message for a trusted client!"

    def __init__(self, eth_signer, library: ZkSyncLibrary, chain_id: ChainId):
        self.library = library
        message = self.MESSAGE
        if chain_id != ChainId.MAINNET:
            message = f"{message}\nChain ID: {chain_id}"

        message = message.encode()
        signature = eth_signer.sign(message)
        self.private_key = self.library.private_key_from_seed(signature)
