from abc import ABC, abstractmethod
from decimal import Decimal
from typing import List, Optional, Tuple, Union

from eth_typing import Address

from zksync_sdk.transport import JsonRPCTransport
from zksync_sdk.types import (AccountState, ContractAddress, EncodedTx, EthOpInfo, Fee,
                              Token, TokenLike, Tokens, TransactionDetails,
                              TxEthSignature, )
from zksync_sdk.zksync_provider.types import FeeTxType, TransactionWithSignature

__all__ = ['ZkSyncProviderInterface']


class ZkSyncProviderInterface(ABC):
    def __init__(self, provider: JsonRPCTransport):
        self.provider = provider

    @abstractmethod
    async def submit_tx(self, tx: EncodedTx, signature: Optional[TxEthSignature],
                        fast_processing: bool = False) -> str:
        raise NotImplementedError

    @abstractmethod
    async def get_tokens(self) -> Tokens:
        raise NotImplementedError

    @abstractmethod
    async def submit_txs_batch(self, transactions: List[TransactionWithSignature],
                               signatures: Optional[
                                   Union[List[TxEthSignature], TxEthSignature]
                               ] = None) -> List[str]:
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
    async def get_account_nonce(self, address: str) -> Tuple[int, int]:
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
    async def get_transactions_batch_fee(self, tx_types: List[FeeTxType], addresses: List[Address],
                                         token_like) -> Fee:
        raise NotImplementedError

    @abstractmethod
    async def get_transaction_fee(self, tx_type: FeeTxType, address: str,
                                  token_like: TokenLike) -> Fee:
        raise NotImplementedError

    @abstractmethod
    async def get_token_price(self, token: Token) -> Decimal:
        raise NotImplementedError
