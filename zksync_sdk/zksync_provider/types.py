from enum import Enum

from zksync_sdk.types import EncodedTx, SignatureType

__all__ = ['Transaction', 'EthSignature', 'TxType', 'ZkSyncProviderError', 'AccountDoesNotExist']


class Transaction:
    tx: EncodedTx
    signature: bytes


class EthSignature:
    type: SignatureType
    signature: str


class TxType(Enum):
    withdraw = "Withdraw"
    transfer = "Transfer"
    fast_withdraw = "FastWithdraw"
    change_pub_key_onchain = {"ChangePubKey": "Onchain"}
    change_pub_key_ecdsa = {"ChangePubKey": "ECDSA"}


class ZkSyncProviderError(Exception):
    pass


class AccountDoesNotExist(ZkSyncProviderError):
    def __init__(self, address, *args):
        self.address = address
        super().__init__(*args)
