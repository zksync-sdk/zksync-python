import abc
from dataclasses import dataclass
from decimal import Decimal
from enum import IntEnum
from typing import Dict

from eth_typing import Address

from zksync_sdk.serialize_utils import (int_to_bytes, packed_amount_checked, packed_fee_checked,
                                        serialize_account_id,
                                        serialize_address, serialize_nonce, serialize_timestamp,
                                        serialize_token_id, )


@dataclass
class Token:
    address: str
    id: int
    symbol: str
    decimals: int
    DefaultAddress = "0x0000000000000000000000000000000000000000"

    @classmethod
    def eth(cls):
        return cls(id=0,
                   address=Token.DefaultAddress,
                   symbol="ETH",
                   decimals=18)

    def to_decimal(self, amount: int):
        return Decimal(amount).scaleb(-self.decimals)

    def to_decimal_str(self, amount: int):
        d = self.to_decimal(amount)
        if d != Decimal(0):
            return str(d).rstrip("0")
        else:
            return str(d)


@dataclass
class TxSignature:
    public_key: str
    signature: str

    def __init__(self, public_key: bytes, signature: bytes):
        self.public_key = public_key.hex()
        self.signature = signature.hex()

    def dict(self):
        return {
            "pubKey":    self.public_key,
            "signature": self.signature
        }


class EncodedTx(abc.ABC):
    @abc.abstractmethod
    def encoded_message(self) -> bytes:
        pass

    @abc.abstractmethod
    def human_readable_message(self) -> str:
        pass

    @abc.abstractmethod
    def tx_type(self) -> int:
        pass

    @abc.abstractmethod
    def dict(self):
        pass


class ChainId(IntEnum):
    MAINNET = 1
    RINKEBY = 4
    ROPSTEN = 3
    LOCALHOST = 9


@dataclass
class ChangePubKey(EncodedTx):
    account_id: int
    account: Address
    new_pk_hash: str
    fee_token: int
    fee: int
    nonce: int
    valid_from: int
    valid_until: int
    eth_auth_data: str

    def human_readable_message(self) -> str:
        message = f"Set signing key: {self.new_pk_hash.replace('sync:', '').toLowerCase()}"

    def encoded_message(self) -> bytes:
        return b"".join([
            int_to_bytes(self.tx_type(), 1),
            serialize_account_id(self.account_id),
            self.account,
            serialize_address(self.new_pk_hash),
            serialize_token_id(self.fee_token),
            packed_fee_checked(self.fee),
            serialize_nonce(self.nonce),
            serialize_timestamp(self.valid_from),
            serialize_timestamp(self.valid_until)
        ])

    @classmethod
    def tx_type(cls):
        return 7


@dataclass
class Transfer(EncodedTx):
    account_id: int
    from_address: str
    to_address: str
    token: Token
    amount: int
    fee: int
    nonce: int
    valid_from: int
    valid_until: int
    signature: TxSignature = None

    def tx_type(self) -> int:
        return 5

    def human_readable_message(self) -> str:
        message = f"Transfer {self.token.to_decimal_str(self.amount)} {self.token.symbol} to: {self.to_address.lower()}\nFee: {self.token.to_decimal_str(self.fee)} {self.token.symbol}\nNonce: {self.nonce}"
        return message

    def encoded_message(self) -> bytes:
        return b"".join([
            int_to_bytes(self.tx_type(), 1),
            serialize_account_id(self.account_id),
            serialize_address(self.from_address),
            serialize_address(self.to_address),
            serialize_token_id(self.token.id),
            packed_amount_checked(self.amount),
            packed_fee_checked(self.fee),
            serialize_nonce(self.nonce),
            # serialize_timestamp(self.valid_from),
            # serialize_timestamp(self.valid_until)
        ])

    def dict(self):
        return {
            "accountId": self.account_id,
            "from":      self.from_address,
            "to":        self.to_address,
            "token":     self.token.id,
            "fee":       self.fee,
            "nonce":     self.nonce,
            "type":      "Transfer",
            "signature": self.signature.dict(),
            "amount":    self.amount,

        }


@dataclass
class Withdraw(EncodedTx):
    account_id: int
    from_address: Address
    eth_address: Address
    token_id: int
    amount: int
    fee: int
    nonce: int
    valid_from: int
    valid_until: int
    string_token: str

    def tx_type(self) -> int:
        return 3

    def human_readable_message(self) -> str:
        tx_type = "Withdraw"
        message = ""
        if self.amount:
            message = f"{tx_type} {self.amount} {self.string_token} to: 0x{self.eth_address.hex().lower()}"
        if self.fee:
            if message:
                message += "\n"
            message += f"Fee: {self.fee} {self.string_token}"
        return message

    def encoded_message(self) -> bytes:
        return b"".join([
            int_to_bytes(self.tx_type(), 1),
            serialize_account_id(self.account_id),
            self.from_address,
            self.eth_address,
            serialize_token_id(self.token_id),
            int_to_bytes(self.amount, length=16),
            packed_fee_checked(self.fee),
            serialize_nonce(self.nonce),
            serialize_timestamp(self.valid_from),
            serialize_timestamp(self.valid_until)
        ])


@dataclass
class ForcedExit(EncodedTx):
    initiator_account_id: int
    target: Address
    token_id: int
    fee: int
    nonce: int
    valid_from: int
    valid_until: int

    def tx_type(self) -> int:
        return 8

    def encoded_message(self) -> bytes:
        return b"".join([
            int_to_bytes(self.tx_type(), 1),
            serialize_account_id(self.initiator_account_id),
            self.target,
            serialize_token_id(self.token_id),
            packed_fee_checked(self.fee),
            serialize_nonce(self.nonce),
            serialize_timestamp(self.valid_from),
            serialize_timestamp(self.valid_until)
        ])


class ContractAddress:
    main_contract: str
    gov_contract: str


@dataclass
class Tokens:
    tokens: Dict[str, Token]


@dataclass
class SignedTransaction:
    transaction: EncodedTx
    eth_signature: bytes


@dataclass
class TxEthSignature:
    # type: 'EthereumSignature' | 'EIP1271Signature'
    type: str
    signature: str

    def __init__(self, type: str, signature: bytes):
        self.signature = signature.hex()
        self.type = type

    def dict(self):
        return {
            "type":      self.type,
            "signature": self.signature
        }
