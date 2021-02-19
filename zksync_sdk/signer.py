from eth_account.messages import encode_defunct
from eth_account.signers.base import BaseAccount
from eth_account.signers.local import LocalAccount

from zksync_sdk import ZkSyncLibrary
from zksync_sdk.types import ChainId, EncodedTx, TxEthSignature, TxSignature


class ZkSyncSigner:
    MESSAGE = "Access zkSync account.\n\nOnly sign this message for a trusted client!"

    def __init__(self, account: LocalAccount, library: ZkSyncLibrary, chain_id: ChainId):
        self.library = library
        self.private_key = self.derive_private_key(account, chain_id)
        self.public_key = self.library.get_public_key(self.private_key)
        self.account = account
        self.chain_id = chain_id

    def derive_private_key(self, account: LocalAccount, chain_id: ChainId):
        message = self.MESSAGE
        if chain_id != ChainId.MAINNET:
            message = f"{message}\nChain ID: {chain_id}."
        message = encode_defunct(message.encode())
        signature = account.sign_message(message)
        private_key = self.library.private_key_from_seed(signature.signature)
        return private_key

    def sign_tx(self, message: EncodedTx) -> TxSignature:
        signature = self.library.sign(self.private_key, message.encoded_message())
        return TxSignature(signature=signature, public_key=self.public_key)


class EthereumSigner:
    def __init__(self, account: BaseAccount):
        self.account = account

    def sign(self, tx: EncodedTx) -> TxEthSignature:
        message = tx.human_readable_message()
        message = encode_defunct(message.encode())
        signature = self.account.sign_message(message)
        return TxEthSignature(signature=signature.signature, type="EthereumSignature")
