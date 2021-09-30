from abc import ABC, abstractmethod

from zksync_sdk.types import EncodedTx, TxEthSignature

__all__ = ['EthereumSignerInterface', 'TxEthValidatorInterface']


class EthereumSignerInterface(ABC):

    @abstractmethod
    def sign_tx(self, tx: EncodedTx) -> TxEthSignature:
        raise NotImplementedError

    @abstractmethod
    def sign(self, message: bytes) -> TxEthSignature:
        raise NotImplementedError

    @abstractmethod
    def address(self) -> str:
        raise NotImplementedError

    def recovery_message(self, tx: TxEthSignature, message: bytes) -> str:
        raise NotImplementedError


class TxEthValidatorInterface(ABC):
    def __init__(self, signer: EthereumSignerInterface):
        self.signer = signer

    @abstractmethod
    def is_valid_signature(self, eth_signature: TxEthSignature, tx: EncodedTx) -> bool:
        raise NotImplementedError
