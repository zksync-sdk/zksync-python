from eth_account.messages import encode_defunct, defunct_hash_message
from eth_account.signers.base import BaseAccount
from web3.auto import w3
from typing import Optional
from zksync_sdk.ethereum_signer.interface import EthereumSignerInterface, TxEthValidatorInterface
from zksync_sdk.types import EncodedTx, SignatureType, TxEthSignature, Order

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


class TxEthValidator(TxEthValidatorInterface):

    def is_valid_signature(self, tx: Order) -> bool:
        msg = tx.human_readable_message().encode()

        def get_sig(opt_value: Optional[TxEthSignature]) -> TxEthSignature:
            if opt_value is None:
                raise ValueError()
            return opt_value

        address = self.recover_signer_address(get_sig(tx.eth_signature), msg)
        return self.signer_address == address

    @staticmethod
    def recover_signer_address(tx: TxEthSignature, message: bytes) -> str:
        encoded_message = encode_defunct(message)
        # INFO: remove prefix 0x
        sig = bytes.fromhex(tx.signature[2:])
        return w3.eth.account.recover_message(encoded_message, signature=sig)
