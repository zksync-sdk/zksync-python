import abc
from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
from enum import Enum, IntEnum
from typing import List, Optional, Union, Tuple

from pydantic import BaseModel
from zksync_sdk.lib import ZkSyncLibrary
from zksync_sdk.serializers import (int_to_bytes, packed_amount_checked, packed_fee_checked,
                                    serialize_account_id,
                                    serialize_address, serialize_content_hash,
                                    serialize_nonce, serialize_timestamp,
                                    serialize_token_id, serialize_ratio_part)
from zksync_sdk.types.signatures import TxEthSignature, TxSignature
from zksync_sdk.types.auth_types import ChangePubKeyCREATE2, ChangePubKeyEcdsa

DEFAULT_TOKEN_ADDRESS = "0x0000000000000000000000000000000000000000"

TokenLike = Union[str, int]

TRANSACTION_VERSION = 0x01


class EncodedTxType(IntEnum):
    CHANGE_PUB_KEY = 7
    TRANSFER = 5
    WITHDRAW = 3
    FORCED_EXIT = 8
    SWAP = 11
    MINT_NFT = 9
    WITHDRAW_NFT = 10


class RatioType(Enum):
    # ratio that represents the lowest denominations of tokens (wei for ETH, satoshi for BTC etc.)
    wei = 'Wei',
    # ratio that represents tokens themselves
    token = 'Token'


class Token(BaseModel):
    address: str
    id: int
    symbol: str
    decimals: int

    @classmethod
    def eth(cls):
        return cls(id=0,
                   address=DEFAULT_TOKEN_ADDRESS,
                   symbol="ETH",
                   decimals=18)

    def is_eth(self) -> bool:
        return self.symbol == "ETH" and self.address == DEFAULT_TOKEN_ADDRESS

    def decimal_amount(self, amount: int) -> Decimal:
        return Decimal(amount).scaleb(-self.decimals)

    def from_decimal(self, amount: Decimal) -> int:
        return int(amount.scaleb(self.decimals))

    def decimal_str_amount(self, amount: int) -> str:
        d = self.decimal_amount(amount)

        # Creates a string with `self.decimals` numbers after decimal point.
        # Prevents scientific notation (string values like '1E-8').
        # Prevents integral numbers having no decimal point in the string representation.
        d_str = f"{d:.{self.decimals}f}"

        d_str = d_str.rstrip("0")
        if d_str[-1] == ".":
            return d_str + "0"

        if '.' not in d_str:
            return d_str + '.0'

        return d_str


def token_ratio_to_wei_ratio(token_ratio: Fraction, token_sell: Token, token_buy: Token) -> Fraction:
    num = token_sell.from_decimal(Decimal(token_ratio.numerator))
    den = token_buy.from_decimal(Decimal(token_ratio.denominator))
    return Fraction(num, den, _normalize = False)


class Tokens(BaseModel):
    tokens: List[Token]

    def find_by_address(self, address: str) -> Optional[Token]:
        found_token = [token for token in self.tokens if token.address == address]
        if found_token:
            return found_token[0]
        else:
            return None

    def find_by_id(self, token_id: int) -> Optional[Token]:
        found_token = [token for token in self.tokens if token.id == token_id]
        if found_token:
            return found_token[0]
        else:
            return None

    def find_by_symbol(self, symbol: str) -> Optional[Token]:
        found_token = [token for token in self.tokens if token.symbol == symbol]
        if found_token:
            return found_token[0]
        else:
            return None

    def find(self, token: TokenLike) -> Optional[Token]:
        result = None
        if isinstance(token, int):
            result = self.find_by_id(token)

        if isinstance(token, str):
            result = self.find_by_address(address=token)
            if result is None:
                result = self.find_by_symbol(symbol=token)
        return result


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

    @abc.abstractmethod
    def batch_message_part(self) -> str:
        pass


@dataclass
class ChangePubKey(EncodedTx):
    account_id: int
    account: str
    new_pk_hash: str
    token: Token
    fee: int
    nonce: int
    valid_from: int
    valid_until: int
    eth_auth_data: Union[ChangePubKeyCREATE2, ChangePubKeyEcdsa, None] = None
    eth_signature: Optional[TxEthSignature] = None
    signature: Optional[TxSignature] = None

    def human_readable_message(self) -> str:
        message = f"Set signing key: {self.new_pk_hash.replace('sync:', '').lower()}"
        if self.fee:
            message += f"\nFee: {self.fee} {self.token.symbol}"
        return message

    def batch_message_part(self) -> str:
        message = f"Set signing key: {self.new_pk_hash.replace('sync:', '').lower()}\n"
        if self.fee:
            message += f"Fee: {self.token.decimal_str_amount(self.fee)} {self.token.symbol}\n"
        return message

    def encoded_message(self) -> bytes:
        return b"".join([
            int_to_bytes(0xff - self.tx_type(), 1),
            int_to_bytes(TRANSACTION_VERSION, 1),
            serialize_account_id(self.account_id),
            serialize_address(self.account),
            serialize_address(self.new_pk_hash),
            serialize_token_id(self.token.id),
            packed_fee_checked(self.fee),
            serialize_nonce(self.nonce),
            serialize_timestamp(self.valid_from),
            serialize_timestamp(self.valid_until)
        ])

    def get_eth_tx_bytes(self) -> bytes:
        data = b"".join([
            serialize_address(self.new_pk_hash),
            serialize_nonce(self.nonce),
            serialize_account_id(self.account_id),
        ])
        if self.eth_auth_data is not None:
            data += self.eth_auth_data.encode_message()
        return data

    def get_auth_data(self, signature: str):
        if self.eth_auth_data is None:
            return {"type": "Onchain"}
        elif isinstance(self.eth_auth_data, ChangePubKeyEcdsa):
            return self.eth_auth_data.dict(signature)
        elif isinstance(self.eth_auth_data, ChangePubKeyCREATE2):
            return self.eth_auth_data.dict()

    def dict(self):
        return {
            "type": "ChangePubKey",
            "accountId": self.account_id,
            "account": self.account,
            "newPkHash": self.new_pk_hash,
            "fee_token": self.token.id,
            "fee": str(self.fee),
            "nonce": self.nonce,
            "ethAuthData": self.eth_auth_data,
            "signature": self.signature.dict(),
            "validFrom": self.valid_from,
            "validUntil": self.valid_until,
        }

    @classmethod
    def tx_type(cls):
        return EncodedTxType.CHANGE_PUB_KEY


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
    signature: Optional[TxSignature] = None

    def tx_type(self) -> int:
        return EncodedTxType.TRANSFER

    def human_readable_message(self) -> str:
        msg = ""

        if self.amount != 0:
            msg += f"Transfer {self.token.decimal_str_amount(self.amount)} {self.token.symbol} to: {self.to_address.lower()}\n"
        if self.fee != 0:
            msg += f"Fee: {self.token.decimal_str_amount(self.fee)} {self.token.symbol}\n"

        return msg + f"Nonce: {self.nonce}"

    def batch_message_part(self) -> str:
        msg = ""
        if self.amount != 0:
            msg += f"Transfer {self.token.decimal_str_amount(self.amount)} {self.token.symbol} to: {self.to_address.lower()}\n"
        if self.fee != 0:
            msg += f"Fee: {self.token.decimal_str_amount(self.fee)} {self.token.symbol}\n"
        return msg

    def encoded_message(self) -> bytes:
        return b"".join([
            int_to_bytes(0xff - self.tx_type(), 1),
            int_to_bytes(TRANSACTION_VERSION, 1),
            serialize_account_id(self.account_id),
            serialize_address(self.from_address),
            serialize_address(self.to_address),
            serialize_token_id(self.token.id),
            packed_amount_checked(self.amount),
            packed_fee_checked(self.fee),
            serialize_nonce(self.nonce),
            serialize_timestamp(self.valid_from),
            serialize_timestamp(self.valid_until)
        ])

    def dict(self):
        return {
            "type": "Transfer",
            "accountId": self.account_id,
            "from": self.from_address,
            "to": self.to_address,
            "token": self.token.id,
            "fee": str(self.fee),
            "nonce": self.nonce,
            "signature": self.signature.dict(),
            "amount": str(self.amount),
            "validFrom": self.valid_from,
            "validUntil": self.valid_until,
        }


@dataclass
class Withdraw(EncodedTx):
    account_id: int
    from_address: str
    to_address: str
    amount: int
    fee: int
    nonce: int
    valid_from: int
    valid_until: int
    token: Token
    signature: Optional[TxSignature] = None

    def tx_type(self) -> int:
        return EncodedTxType.WITHDRAW

    def human_readable_message(self) -> str:
        msg = ""
        if self.amount != 0:
            msg += f"Withdraw {self.token.decimal_str_amount(self.amount)} {self.token.symbol} to: {self.to_address.lower()}\n"
        if self.fee != 0:
            msg += f"Fee: {self.token.decimal_str_amount(self.fee)} {self.token.symbol}\n"
        return msg + f"Nonce: {self.nonce}"

    def batch_message_part(self) -> str:
        msg = ""
        if self.amount != 0:
            msg += f"Withdraw {self.token.decimal_str_amount(self.amount)} {self.token.symbol} to: {self.to_address.lower()}\n"
        if self.fee != 0:
            msg += f"Fee: {self.token.decimal_str_amount(self.fee)} {self.token.symbol}\n"
        return msg

    def encoded_message(self) -> bytes:
        return b"".join([
            int_to_bytes(0xff - self.tx_type(), 1),
            int_to_bytes(TRANSACTION_VERSION, 1),
            serialize_account_id(self.account_id),
            serialize_address(self.from_address),
            serialize_address(self.to_address),
            serialize_token_id(self.token.id),
            int_to_bytes(self.amount, length=16),
            packed_fee_checked(self.fee),
            serialize_nonce(self.nonce),
            serialize_timestamp(self.valid_from),
            serialize_timestamp(self.valid_until)
        ])

    def dict(self):
        return {
            "type": "Withdraw",
            "accountId": self.account_id,
            "from": self.from_address,
            "to": self.to_address,
            "token": self.token.id,
            "fee": str(self.fee),
            "nonce": self.nonce,
            "signature": self.signature.dict(),
            "amount": str(self.amount),
            "validFrom": self.valid_from,
            "validUntil": self.valid_until,
        }


@dataclass
class ForcedExit(EncodedTx):
    initiator_account_id: int
    target: str
    token: Token
    fee: int
    nonce: int
    valid_from: int
    valid_until: int
    signature: Optional[TxSignature] = None

    def tx_type(self) -> int:
        return EncodedTxType.FORCED_EXIT

    def encoded_message(self) -> bytes:
        return b"".join([
            int_to_bytes(0xff - self.tx_type(), 1),
            int_to_bytes(TRANSACTION_VERSION, 1),
            serialize_account_id(self.initiator_account_id),
            serialize_address(self.target),
            serialize_token_id(self.token.id),
            packed_fee_checked(self.fee),
            serialize_nonce(self.nonce),
            serialize_timestamp(self.valid_from),
            serialize_timestamp(self.valid_until)
        ])

    def human_readable_message(self) -> str:
        message = f"ForcedExit {self.token.symbol} to: {self.target.lower()}\nFee: {self.token.decimal_str_amount(self.fee)} {self.token.symbol}\nNonce: {self.nonce}"
        return message

    def batch_message_part(self) -> str:
        message = f"ForcedExit {self.token.symbol} to: {self.target.lower()}\n" \
                  f"Fee: {self.token.decimal_str_amount(self.fee)} {self.token.symbol}\n"
        return message

    def dict(self):
        return {
            "type": "ForcedExit",
            "initiatorAccountId": self.initiator_account_id,
            "target": self.target,
            "token": self.token.id,
            "fee": str(self.fee),
            "nonce": self.nonce,
            "signature": self.signature.dict(),
            "validFrom": self.valid_from,
            "validUntil": self.valid_until,
        }


@dataclass
class Order(EncodedTx):
    account_id: int
    recipient: str
    nonce: int
    token_sell: Token
    token_buy: Token
    amount: int
    ratio: Fraction
    valid_from: int
    valid_until: int
    signature: Optional[TxSignature] = None
    eth_signature: Optional[TxEthSignature] = None

    @classmethod
    def from_json(cls, json: dict, tokens: Tokens):

        def from_optional(value: Optional[Token]) -> Token:
            if value is None:
                raise ValueError(f"Token None value should not be used")
            return value

        token_sell_id: int = json["tokenSell"]
        token_buy_id: int = json["tokenBuy"]
        token_sell = from_optional(tokens.find_by_id(token_sell_id))
        token_buy = from_optional(tokens.find_by_id(token_buy_id))
        ratio = json["ratio"]

        # INFO: could be None
        signature = json.get("signature")
        if signature is not None:
            signature = TxSignature.from_dict(signature)
        ether_sig = json.get("ethSignature")
        if ether_sig is not None:
            ether_sig = TxEthSignature.from_dict(ether_sig)
        return cls(
            account_id=json["accountId"],
            recipient=json["recipient"],
            nonce=json["nonce"],
            token_sell=token_sell,
            token_buy=token_buy,
            amount=int(json["amount"]),
            ratio=Fraction(int(ratio[0]), int(ratio[1]), _normalize=False),
            valid_from=json["validFrom"],
            valid_until=json["validUntil"],
            signature=signature,
            eth_signature=ether_sig
        )

    def tx_type(self) -> int:
        raise NotImplementedError

    def msg_type(self) -> int:
        return b'o'[0]

    def encoded_message(self) -> bytes:
        return b"".join([
            int_to_bytes(self.msg_type(), 1),
            int_to_bytes(TRANSACTION_VERSION, 1),
            serialize_account_id(self.account_id),
            serialize_address(self.recipient),
            serialize_nonce(self.nonce),
            serialize_token_id(self.token_sell.id),
            serialize_token_id(self.token_buy.id),
            serialize_ratio_part(self.ratio.numerator),
            serialize_ratio_part(self.ratio.denominator),
            packed_amount_checked(self.amount),
            serialize_timestamp(self.valid_from),
            serialize_timestamp(self.valid_until)
        ])

    def batch_message_part(self) -> str:
        pass

    def human_readable_message(self) -> str:
        if self.amount == 0:
            header = f'Limit order for {self.token_sell.symbol} -> {self.token_buy.symbol}'
        else:
            amount = self.token_sell.decimal_str_amount(self.amount)
            header = f'Order for {amount} {self.token_sell.symbol} -> {self.token_buy.symbol}'

        message = '\n'.join([
            header,
            f'Ratio: {self.ratio.numerator}:{self.ratio.denominator}',
            f'Address: {self.recipient.lower()}',
            f'Nonce: {self.nonce}'
        ])
        return message

    def dict(self):
        return {
            "accountId": self.account_id,
            "recipient": self.recipient,
            "nonce": self.nonce,
            "tokenSell": self.token_sell.id,
            "tokenBuy": self.token_buy.id,
            "amount": str(self.amount),
            "ratio": (str(self.ratio.numerator), str(self.ratio.denominator)),
            "validFrom": self.valid_from,
            "validUntil": self.valid_until,
            "signature": self.signature.dict() if self.signature else None,
            "ethSignature": self.eth_signature.dict() if self.eth_signature else None,
        }

    def is_valid_eth_signature(self, signer_address: str) -> bool:
        address = self._recover_signer_address()
        return signer_address == address

    def _recover_signer_address(self) -> str:
        """
        INFO: particular case implementation with dependency from Web3 interface
              if it's needed to generelize for all Obejct type(Transfer, Swap etc) move to etherium_signer module
              with interface & implemnetation for Web3 as Validator class( Visitor pattern )
        """
        from web3.auto import w3
        from eth_account.messages import encode_defunct

        msg = self.human_readable_message().encode()
        encoded_message = encode_defunct(msg)

        def get_sig(opt_value: Optional[TxEthSignature]) -> TxEthSignature:
            if opt_value is None:
                raise ValueError()
            return opt_value

        # INFO: remove prefix 0x
        eth_sig = get_sig(self.eth_signature)
        sig = bytes.fromhex(eth_sig.signature[2:])
        return w3.eth.account.recover_message(encoded_message, signature=sig)


@dataclass
class Swap(EncodedTx):
    submitter_id: int
    submitter_address: str
    amounts: Tuple[int, int]
    orders: Tuple[Order, Order]
    fee_token: Token
    fee: int
    nonce: int
    signature: Optional[TxSignature] = None

    def tx_type(self) -> int:
        return EncodedTxType.SWAP

    def human_readable_message(self) -> str:
        if self.fee != 0:
            message = f'Swap fee: {self.fee_token.decimal_str_amount(self.fee)} {self.fee_token.symbol}\n'
        else:
            message = ''
        message += f'Nonce: {self.nonce}'
        return message

    def batch_message_part(self) -> str:
        if self.fee != 0:
            message = f'Swap fee: {self.fee_token.decimal_str_amount(self.fee)} {self.fee_token.symbol}\n'
        else:
            message = ''
        return message

    def encoded_message(self) -> bytes:
        order_bytes = b''.join([
            self.orders[0].encoded_message(),
            self.orders[1].encoded_message(),
        ])
        return b"".join([
            int_to_bytes(0xff - self.tx_type(), 1),
            int_to_bytes(TRANSACTION_VERSION, 1),
            serialize_account_id(self.submitter_id),
            serialize_address(self.submitter_address),
            serialize_nonce(self.nonce),
            ZkSyncLibrary().hash_orders(order_bytes),
            serialize_token_id(self.fee_token.id),
            packed_fee_checked(self.fee),
            packed_amount_checked(self.amounts[0]),
            packed_amount_checked(self.amounts[1]),
        ])

    def dict(self):
        return {
            "type": "Swap",
            "submitterId": self.submitter_id,
            "submitterAddress": self.submitter_address,
            "feeToken": self.fee_token.id,
            "fee": str(self.fee),
            "nonce": self.nonce,
            "signature": self.signature.dict() if self.signature else None,
            "amounts": (str(self.amounts[0]), str(self.amounts[1])),
            "orders": (self.orders[0].dict(), self.orders[1].dict())
        }


@dataclass
class MintNFT(EncodedTx):
    creator_id: int
    creator_address: str
    content_hash: str
    recipient: str
    fee: int
    fee_token: Token
    nonce: int
    signature: Optional[TxSignature] = None

    def tx_type(self) -> int:
        return EncodedTxType.MINT_NFT

    def encoded_message(self) -> bytes:
        return b"".join([
            int_to_bytes(0xff - self.tx_type(), 1),
            int_to_bytes(TRANSACTION_VERSION, 1),
            serialize_account_id(self.creator_id),
            serialize_address(self.creator_address),
            serialize_content_hash(self.content_hash),
            serialize_address(self.recipient),
            serialize_token_id(self.fee_token.id),
            packed_fee_checked(self.fee),
            serialize_nonce(self.nonce),
        ])

    def human_readable_message(self) -> str:
        message = f"MintNFT {self.content_hash} for: {self.recipient.lower()}\n" \
                  f"Fee: {self.fee_token.decimal_str_amount(self.fee)} {self.fee_token.symbol}\nNonce: {self.nonce}"
        return message

    def batch_message_part(self) -> str:
        message = f"MintNFT {self.content_hash} for: {self.recipient.lower()}\n" \
                  f"Fee: {self.fee_token.decimal_str_amount(self.fee)} {self.fee_token.symbol}\n"
        return message

    def dict(self):
        return {
            "type": "MintNFT",
            "creatorId": self.creator_id,
            "creatorAddress": self.creator_address,
            "contentHash": self.content_hash,
            "recipient": self.recipient,
            "feeToken": self.fee_token.id,
            "fee": str(self.fee),
            "nonce": self.nonce,
            "signature": self.signature.dict(),
        }


@dataclass
class WithdrawNFT(EncodedTx):
    account_id: int
    from_address: str
    to_address: str
    fee_token: Token
    fee: int
    nonce: int
    valid_from: int
    valid_until: int
    token_id: int
    signature: Optional[TxSignature] = None

    def tx_type(self) -> int:
        return EncodedTxType.WITHDRAW_NFT

    def encoded_message(self) -> bytes:
        return b"".join([
            int_to_bytes(0xff - self.tx_type(), 1),
            int_to_bytes(TRANSACTION_VERSION, 1),
            serialize_account_id(self.account_id),
            serialize_address(self.from_address),
            serialize_address(self.to_address),
            serialize_token_id(self.token_id),
            serialize_token_id(self.fee_token.id),
            packed_fee_checked(self.fee),
            serialize_nonce(self.nonce),
            serialize_timestamp(self.valid_from),
            serialize_timestamp(self.valid_until)
        ])

    def human_readable_message(self) -> str:
        message = f"WithdrawNFT {self.token_id} to: {self.to_address.lower()}\nFee: {self.fee_token.decimal_str_amount(self.fee)} {self.fee_token.symbol}\nNonce: {self.nonce}"
        return message

    def batch_message_part(self) -> str:
        message = f"WithdrawNFT {self.token_id} to: {self.to_address.lower()}\n" \
                  f"Fee: {self.fee_token.decimal_str_amount(self.fee)} {self.fee_token.symbol}\n"
        return message

    def dict(self):
        return {
            "type": "WithdrawNFT",
            "accountId": self.account_id,
            "from": self.from_address,
            "to": self.to_address,
            "feeToken": self.fee_token.id,
            "fee": str(self.fee),
            "nonce": self.nonce,
            "validFrom": self.valid_from,
            "validUntil": self.valid_until,
            "token": self.token_id,
            "signature": self.signature.dict(),
        }


class EncodedTxValidator:
    def __init__(self, library: ZkSyncLibrary):
        self.library = library

    def is_valid_signature(self, tx):
        zk_sync_signature: TxSignature = tx.signature
        if zk_sync_signature is None:
            return False
        bytes_signature = bytes.fromhex(zk_sync_signature.signature)
        pubkey = bytes.fromhex(zk_sync_signature.public_key)
        return self.library.is_valid_signature(tx.encoded_message(), pubkey, bytes_signature)


@dataclass
class TransactionWithSignature:
    tx: EncodedTx
    signature: TxEthSignature

    def dict(self):
        return {
            'tx': self.tx.dict(),
            'signature': self.signature.dict(),
        }


@dataclass()
class TransactionWithOptionalSignature:
    tx: EncodedTx
    signature: Union[None, TxEthSignature, List[TxSignature]] = None

    def dict(self):
        if self.signature is None:
            null_value = None
            return {
                'signature': null_value,
                'tx': self.tx.dict()
            }
        else:
            if isinstance(self.signature, list):
                null_value = None
                value = []
                for sig in self.signature:
                    if sig is None:
                        value.append(null_value)
                    else:
                        value.append(sig.dict())
                return {
                    'signature': value,
                    'tx': self.tx.dict()
                }
            else:
                return {
                    'signature': self.signature.dict(),
                    'tx': self.tx.dict()
                }
