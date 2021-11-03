from abc import ABC, abstractmethod
from decimal import Decimal
from typing import List, Optional, Union
from zksync_sdk.transport import JsonRPCTransport
from zksync_sdk.types import (AccountState, ContractAddress, EncodedTx, EthOpInfo, Fee, Token,
                              TokenLike, Tokens, TransactionDetails, TransactionWithSignature,
                              TransactionWithOptionalSignature,
                              TxEthSignature, Toggle2FA, )
from zksync_sdk.zksync_provider.types import FeeTxType
from zksync_sdk.zksync_provider.transaction import Transaction

__all__ = ['ZkSyncProviderInterface']


class ZkSyncProviderInterface(ABC):
    def __init__(self, provider: JsonRPCTransport):
        self.provider = provider

    @abstractmethod
    async def submit_tx(self, tx: EncodedTx, signature: Union[Optional[TxEthSignature], List[Optional[TxEthSignature]]],
                        fast_processing: bool = False) -> Transaction:
        raise NotImplementedError

    @abstractmethod
    async def get_tokens(self) -> Tokens:
        raise NotImplementedError

    @abstractmethod
    async def submit_txs_batch(self, transactions: List[TransactionWithSignature],
                               signatures: Optional[
                                   Union[List[TxEthSignature], TxEthSignature]
                               ] = None) -> List[Transaction]:
        raise NotImplementedError

    @abstractmethod
    async def submit_batch_builder_txs_batch(self, transactions: List[TransactionWithOptionalSignature],
                                             signature: TxEthSignature) -> List[Transaction]:
        raise NotImplementedError

    @abstractmethod
    async def get_contract_address(self) -> ContractAddress:
        raise NotImplementedError

    @abstractmethod
    async def get_state(self, address: str) -> AccountState:
        raise NotImplementedError

    @abstractmethod
    async def get_confirmations_for_eth_op_amount(self) -> int:
        raise NotImplementedError

    @abstractmethod
    async def get_account_nonce(self, address: str) -> int:
        raise NotImplementedError

    @abstractmethod
    async def get_tx_receipt(self, address: str) -> TransactionDetails:
        raise NotImplementedError

    @abstractmethod
    async def get_eth_tx_for_withdrawal(self, withdrawal_hash: str) -> str:
        raise NotImplementedError

    @abstractmethod
    async def get_priority_op_status(self, serial_id: int) -> EthOpInfo:
        raise NotImplementedError

    @abstractmethod
    async def get_transactions_batch_fee(self, tx_types: List[FeeTxType], addresses: List[str],
                                         token_like) -> int:
        raise NotImplementedError

    @abstractmethod
    async def get_transaction_fee(self, tx_type: FeeTxType, address: str,
                                  token_like: TokenLike) -> Fee:
        raise NotImplementedError

    @abstractmethod
    async def get_token_price(self, token: Token) -> Decimal:
        raise NotImplementedError

    @abstractmethod
    async def toggle_2fa(self, toggle2fa: Toggle2FA) -> bool:
        raise NotImplementedError
