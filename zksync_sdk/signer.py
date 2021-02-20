from eth_account.messages import encode_defunct
from eth_account.signers.base import BaseAccount

from zksync_sdk import ZkSyncLibrary
from zksync_sdk.types import ChainId, EncodedTx, SignatureType, TxEthSignature, TxSignature


class ZkSyncSigner:
    MESSAGE = "Access zkSync account.\n\nOnly sign this message for a trusted client!"

    def __init__(self, account: BaseAccount, library: ZkSyncLibrary, chain_id: ChainId):
        self.library = library
        self.private_key = self.derive_private_key(account, chain_id)
        self.public_key = self.library.get_public_key(self.private_key)
        self.account = account
        self.chain_id = chain_id

    def pubkey_hash(self):
        return f"sync:{self.library.get_pubkey_hash(self.public_key).hex()}"

    def derive_private_key(self, account: BaseAccount, chain_id: ChainId):
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

    def sign_tx(self, tx: EncodedTx) -> TxEthSignature:
        message = tx.human_readable_message()
        return self.sign(message.encode())

    def sign(self, message: bytes):
        signature = self.account.sign_message(encode_defunct(message))
        return TxEthSignature(signature=signature.signature, type=SignatureType.ethereum_signature)
