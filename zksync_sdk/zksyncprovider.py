from enum import Enum
from typing import List, Optional, Tuple, Union

from eth_typing import Address

from zksync_sdk.providers import JsonRPCProvider
from zksync_sdk.types import EncodedTx, Token, Tokens, TxEthSignature


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
    withdraw = "Withdraw"
    transfer = "Transfer"
    fast_withdraw = "FastWithdraw"
    change_pub_key = "ChangePubKeyOnchainAuth"


class ZkSyncProvider:
    def __init__(self, provider: JsonRPCProvider):
        self.provider = provider

    async def submit_tx(self, tx: EncodedTx, signature: Optional[TxEthSignature],
                        fast_processing: bool = False) -> str:
        signature = signature.dict() if signature is not None else None
        return await self.provider.request("tx_submit",
                                           [tx.dict(), signature, fast_processing])

    async def get_tokens(self) -> Tokens:
        tokens_resp = await self.provider.request("tokens", None)
        tokens = [Token(address=token['address'], id=token['id'], symbol=token['symbol'],
                        decimals=token['decimals']) for token in tokens_resp.values()]

        return Tokens(tokens=tokens)

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

    async def get_account_nonce(self, address: str) -> Tuple[int, int]:
        state = await self.provider.request("account_info", [address])
        return state['id'], state['committed']['nonce']

    async def get_tx_receipt(self, address: str):
        return await self.provider.request("tx_info", [address])

    async def get_priority_op_status(self, serial_id: int):
        return await self.provider.request("ethop_info", [serial_id])

    async def get_transactions_batch_fee(self, tx_types: List[TxType], addresses: List[Address],
                                         token_like):

        return await self.provider.request('get_txs_batch_fee_in_wei',
                                           [[tx_type.value for tx_type in tx_types],
                                            addresses, token_like])

    async def get_transaction_fee(self, tx_type: TxType, address: Address,
                                  token_like):

        return await self.provider.request('get_tx_fee', [tx_type.value, address, token_like])
