from eth_account.messages import encode_defunct, defunct_hash_message
from eth_account.signers.base import BaseAccount
from web3.eth import Account
from web3.auto import w3

from zksync_sdk.ethereum_signer.interface import EthereumSignerInterface, TxEthValidatorInterface
from zksync_sdk.types import EncodedTx, SignatureType, TxEthSignature

__all__ = ['EthereumSignerWeb3', 'TxEthValidator']


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

    def recovery_message(self, tx: TxEthSignature, message: bytes) -> str:
        encoded_message = encode_defunct(message)
        # INFO: remove prefix 0x
        sig = bytes.fromhex(tx.signature[2:])
        return w3.eth.account.recover_message(encoded_message, signature=sig)


class TxEthValidator(TxEthValidatorInterface):

    def is_valid_signature(self, eth_signature: TxEthSignature, tx: EncodedTx) -> bool:
        msg = tx.human_readable_message().encode()
        address = self.signer.address()
        address2 = self.signer.recovery_message(eth_signature, msg)
        return address == address2
