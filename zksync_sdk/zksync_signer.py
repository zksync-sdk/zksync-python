from eth_account.messages import encode_defunct
from eth_account.signers.base import BaseAccount

from zksync_sdk import ZkSyncLibrary
from zksync_sdk.types import ChainId, EncodedTx, TxSignature


def derive_private_key(library: ZkSyncLibrary, message: str, account: BaseAccount,
                       chain_id: ChainId):
    if chain_id != ChainId.MAINNET:
        message = f"{message}\nChain ID: {chain_id}."
    signable_message = encode_defunct(message.encode())
    signature = account.sign_message(signable_message)
    private_key = library.private_key_from_seed(signature.signature)
    return private_key


class ZkSyncSigner:
    MESSAGE = "Access zkSync account.\n\nOnly sign this message for a trusted client!"

    def __init__(self, library: ZkSyncLibrary, private_key: bytes):
        self.library = library
        self.private_key = private_key
        self.public_key = self.library.get_public_key(self.private_key)

    @classmethod
    def from_account(cls, account: BaseAccount, library: ZkSyncLibrary, chain_id: ChainId):
        private_key = derive_private_key(library, cls.MESSAGE, account, chain_id)
        return cls(
            library=library,
            private_key=private_key,
        )

    @classmethod
    def from_seed(cls, library: ZkSyncLibrary, seed: bytes):
        private_key = library.private_key_from_seed(seed)
        return cls(
            library=library,
            private_key=private_key,
        )

    def pubkey_hash_str(self):
        return f"sync:{self.pubkey_hash().hex()}"

    def pubkey_hash(self):
        return self.library.get_pubkey_hash(self.public_key)

    def sign_tx(self, message: EncodedTx) -> TxSignature:
        signature = self.library.sign(self.private_key, message.encoded_message())
        return TxSignature(signature=signature, public_key=self.public_key)
