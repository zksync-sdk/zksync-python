from dataclasses import dataclass
from enum import Enum

__all__ = ['FeeTxType']

from zksync_sdk.types import EncodedTx, TxEthSignature


@dataclass
class TransactionWithSignature:
    tx: EncodedTx
    signature: TxEthSignature

    def dict(self):
        return {
            'tx':        self.tx.dict(),
            'signature': self.signature.dict(),
        }


class FeeTxType(Enum):
    withdraw = "Withdraw"
    transfer = "Transfer"
    fast_withdraw = "FastWithdraw"
    change_pub_key_onchain = {"ChangePubKey": "Onchain"}
    change_pub_key_ecdsa = {"ChangePubKey": "ECDSA"}
