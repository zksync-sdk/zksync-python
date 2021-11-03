from typing import Any, Dict, Optional
from enum import Enum
from decimal import Decimal
from zksync_sdk.types.transactions import Token

from pydantic import BaseModel


def to_camel(string: str) -> str:
    first, *others = string.split('_')
    return ''.join([first.lower(), *map(str.title, others)])


class Balance(BaseModel):
    amount: int
    expected_accept_block: int

    class Config:
        alias_generator = to_camel


class Depositing(BaseModel):
    balances: Dict[str, Balance]


class NFT(Token):
    creator_id: int
    content_hash: str
    creator_address: str
    serial_id: int
    decimals = 0

    def decimal_amount(self, amount: int) -> Decimal:
        return Decimal(amount)

    class Config:
        alias_generator = to_camel


class State(BaseModel):
    nonce: int
    pub_key_hash: str
    balances: Dict[str, int]
    nfts: Dict[str, NFT]
    minted_nfts: Dict[str, NFT]

    class Config:
        alias_generator = to_camel


class AccountTypes(str, Enum):
    OWNED = "Owned",
    CREATE2 = "CREATE2",
    NO_2FA = "No2FA"


class AccountState(BaseModel):
    address: str
    id: Optional[int]
    account_type: Optional[AccountTypes]
    depositing: Optional[Depositing]
    committed: Optional[State]
    verified: Optional[State]

    class Config:
        alias_generator = to_camel

    def get_nonce(self) -> int:
        assert self.committed is not None, "`get_nonce` needs `committed` to be set"
        return self.committed.nonce


class Fee(BaseModel):
    fee_type: Any
    gas_tx_amount: int
    gas_price_wei: int
    gas_fee: int
    zkp_fee: int
    total_fee: int

    class Config:
        alias_generator = to_camel


class ContractAddress(BaseModel):
    main_contract: str
    gov_contract: str

    class Config:
        alias_generator = to_camel


class BlockInfo(BaseModel):
    block_number: int
    committed: bool
    verified: bool

    class Config:
        alias_generator = to_camel


class EthOpInfo(BaseModel):
    executed: bool
    block: BlockInfo


class TransactionDetails(BaseModel):
    executed: bool
    success: bool
    fail_reason: Optional[str] = None
    block: BlockInfo

    class Config:
        alias_generator = to_camel
