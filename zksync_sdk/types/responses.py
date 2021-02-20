from typing import Any, Dict, Optional

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


class State(BaseModel):
    nonce: int
    pub_key_hash: str
    balances: Dict[str, int]

    class Config:
        alias_generator = to_camel


class AccountState(BaseModel):
    address: str
    id: int
    depositing: Depositing
    committed: State
    verified: State

    class Config:
        alias_generator = to_camel

    def get_nonce(self) -> int:
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
