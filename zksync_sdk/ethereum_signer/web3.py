from eth_account.messages import encode_defunct
from eth_account.signers.base import BaseAccount
from zksync_sdk.ethereum_signer.interface import EthereumSignerInterface
from zksync_sdk.types import EncodedTx, SignatureType, TxEthSignature

__all__ = ['EthereumSignerWeb3']


class EthereumSignerWeb3(EthereumSignerInterface):
    def __init__(self, account: BaseAccount):
        self.account = account

    def sign_tx(self, tx: EncodedTx) -> TxEthSignature:
        message = tx.human_readable_message()
        return self.sign(message.encode())

    def sign(self, message: bytes) -> TxEthSignature:
        signature = self.account.sign_message(encode_defunct(message))
        return TxEthSignature(signature=signature.signature, sig_type=SignatureType.ethereum_signature)

    def address(self) -> str:
        return self.account.address
