from enum import Enum
from dataclasses import dataclass
from typing import Optional
from zksync_sdk.types.signatures import TxEthSignature


class ChangePubKeyTypes(Enum):
    onchain = "Onchain"
    ecdsa = "ECDSA"
    create2 = "CREATE2"


@dataclass
class ChangePubKeyEcdsa:
    batch_hash: bytes = b"\x00" * 32

    def encode_message(self) -> bytes:
        return self.batch_hash

    def dict(self, signature: str):
        return {"type": "ECDSA",
                "ethSignature": signature,
                "batchHash": f"0x{self.batch_hash.hex()}"}


@dataclass
class ChangePubKeyCREATE2:
    creator_address: str
    salt_arg: bytes
    code_hash: bytes

    def encode_message(self) -> bytes:
        return self.salt_arg

    def dict(self):
        return {"type": "CREATE2",
                "saltArg": f"0x{self.salt_arg.hex()}",
                "codeHash": f"0x{self.code_hash.hex()}"}


@dataclass
class Toggle2FA:
    enable: bool
    account_id: int
    time_stamp_milliseconds: int
    signature: TxEthSignature
    pub_key_hash: Optional[str]

    def dict(self):
        if self.pub_key_hash is not None:
            return {
                "enable": self.enable,
                "accountId": self.account_id,
                "timestamp": self.time_stamp_milliseconds,
                "signature": self.signature.dict(),
                "pubKeyHash": self.pub_key_hash
            }
        else:
            return {
                "enable": self.enable,
                "accountId": self.account_id,
                "timestamp": self.time_stamp_milliseconds,
                "signature": self.signature.dict(),
            }


def get_toggle_message(require_2fa: bool, time_stamp: int) -> str:
    if require_2fa:
        msg = f"By signing this message, you are opting into Two-factor Authentication protection by the zkSync " \
              f"Server.\n" \
              f"Transactions now require signatures by both your L1 and L2 private key.\n" \
              f"Timestamp: {time_stamp}"
    else:
        msg = f"You are opting out of Two-factor Authentication protection by the zkSync Server.\n" \
              f"Transactions now only require signatures by your L2 private key.\n" \
              f"BY SIGNING THIS MESSAGE, YOU ARE TRUSTING YOUR WALLET CLIENT TO KEEP YOUR L2 PRIVATE KEY SAFE!\n" \
              f"Timestamp: {time_stamp}"
    return msg


def get_toggle_message_with_pub(require_2fa: bool, time_stamp: int, pub_key_hash: str) -> str:
    msg = get_toggle_message(require_2fa, time_stamp)
    msg += f"\nPubKeyHash: {pub_key_hash}"
    return msg
