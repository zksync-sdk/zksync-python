from enum import Enum
from typing import List, Optional, Union

from eth_typing import Address

from zksync_sdk.providers import JsonRPCProvider
from zksync_sdk.types import EncodedTx, TxEthSignature


class SignatureType(Enum):
    EthereumSignature = 1
    EIP1271Signature = 2


class Transaction:
    tx: EncodedTx
    signature: bytes


class EthSignature:
    type: SignatureType
    signature: str


class TxType(Enum):
    pass


class ZkSyncProvider:
    def __init__(self, provider: JsonRPCProvider):
        self.provider = provider

    async def submit_tx(self, tx: EncodedTx, signature: TxEthSignature,
                        fast_processing: bool = False):
        return await self.provider.request("tx_submit",
                                           [tx.dict(), signature.dict(), fast_processing])

    async def get_tokens(self):
        return await self.provider.request("tokens", None)

    async def submit_txs_batch(self, transactions: List[Transaction],
                               signatures: Optional[
                                   Union[List[EthSignature], EthSignature]
                               ] = None):
        if signatures is None:
            signatures = []
        elif isinstance(signatures, EthSignature):
            signatures = [signatures]

        return await self.provider.request("submit_txs_batch", [transactions, signatures])

    async def get_contract_address(self):
        return await self.provider.request("contract_address", None)

    async def get_state(self, address: str):
        return await self.provider.request("account_info", [address])

    async def get_tx_receipt(self, address: str):
        return await self.provider.request("tx_info", [address])

    async def get_priority_op_status(self, serial_id: int):
        return await self.provider.request("ethop_info", [serial_id])

    async def get_transactions_batch_fee(self, tx_types: List[TxType], addresses: List[Address],
                                         token_like):

        return await self.provider.request('get_txs_batch_fee_in_wei',
                                           [tx_types, addresses, token_like])
