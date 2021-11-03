from dataclasses import asdict
from decimal import Decimal
from typing import List, Optional, Union
from web3 import Web3

from zksync_sdk.types import (AccountState, ContractAddress, EncodedTx, EthOpInfo, Fee, Token,
                              TokenLike, Tokens, TransactionDetails, TransactionWithSignature,
                              TransactionWithOptionalSignature,
                              TxEthSignature, Toggle2FA, )
from zksync_sdk.zksync_provider.error import AccountDoesNotExist
from zksync_sdk.zksync_provider.interface import ZkSyncProviderInterface
from zksync_sdk.zksync_provider.types import FeeTxType
from zksync_sdk.zksync_provider.transaction import Transaction

__all__ = ['ZkSyncProviderV01']


class ZkSyncProviderV01(ZkSyncProviderInterface):
    async def submit_tx(self, tx: EncodedTx, signature: Union[Optional[TxEthSignature], List[Optional[TxEthSignature]]],
                        fast_processing: bool = False) -> Transaction:
        if isinstance(signature, List):
            signature = [s.dict() if s is not None else None for s in signature]
        else:
            signature = signature.dict() if signature is not None else None
        trans_id = await self.provider.request("tx_submit",
                                               [tx.dict(), signature, fast_processing])
        return Transaction.build_transaction(self, trans_id)

    async def get_tokens(self) -> Tokens:
        data = await self.provider.request("tokens", None)
        tokens = [Token(address=Web3.toChecksumAddress(token['address']),
                        id=token['id'],
                        symbol=token['symbol'],
                        decimals=token['decimals']
                        ) for token in data.values()]
        return Tokens(tokens=tokens)

    async def submit_txs_batch(self, transactions: List[TransactionWithSignature],
                               signatures: Optional[
                                   Union[List[TxEthSignature], TxEthSignature]
                               ] = None) -> List[Transaction]:
        if signatures is None:
            signatures = []
        elif isinstance(signatures, TxEthSignature):
            signatures = [signatures]
        transactions = [tr.dict() for tr in transactions]
        signatures = [sig.dict() for sig in signatures]
        trans_ids: List[str] = await self.provider.request("submit_txs_batch", [transactions, signatures])
        return [Transaction.build_transaction(self, trans_id) for trans_id in trans_ids]

    async def submit_batch_builder_txs_batch(self, transactions: List[TransactionWithOptionalSignature],
                                             signature: TxEthSignature) -> List[Transaction]:
        trans = [tr.dict() for tr in transactions]
        params = [trans, signature.dict()]
        trans_ids: List[str] = await self.provider.request("submit_txs_batch", params)
        return [Transaction.build_transaction(self, trans_id) for trans_id in trans_ids]

    async def get_contract_address(self) -> ContractAddress:
        data = await self.provider.request("contract_address", None)
        return ContractAddress(**data)

    async def get_state(self, address: str) -> AccountState:
        data = await self.provider.request("account_info", [address])
        if data is None:
            raise AccountDoesNotExist(address=address)
        if "accountType" in data and isinstance(data["accountType"], dict) and \
                list(data["accountType"].keys())[0] == 'No2FA':
            data["accountType"] = 'No2FA'
        return AccountState(**data)

    async def get_confirmations_for_eth_op_amount(self) -> int:
        return await self.provider.request("get_confirmations_for_eth_op_amount", None)

    async def get_account_nonce(self, address: str) -> int:
        state = await self.get_state(address)
        return state.get_nonce()

    async def get_tx_receipt(self, address: str) -> TransactionDetails:
        return await self.provider.request("tx_info", [address])

    async def get_eth_tx_for_withdrawal(self, withdrawal_hash: str) -> str:
        return await self.provider.request("get_eth_tx_for_withdrawal", [withdrawal_hash])

    async def get_priority_op_status(self, serial_id: int) -> EthOpInfo:
        data = await self.provider.request("ethop_info", [serial_id])
        return EthOpInfo(**data)

    # Please note that the batch fee returns the fee of the transaction in int and not in Fee
    # This is a server-side feature
    async def get_transactions_batch_fee(self, tx_types: List[FeeTxType], addresses: List[str],
                                         token_like) -> int:

        data = await self.provider.request('get_txs_batch_fee_in_wei',
                                           [[tx_type.value for tx_type in tx_types],
                                            addresses, token_like])
        return int(data["totalFee"])

    async def get_transaction_fee(self, tx_type: FeeTxType, address: str,
                                  token_like: TokenLike) -> Fee:

        data = await self.provider.request('get_tx_fee', [tx_type.value, address, token_like])
        return Fee(**data)

    async def get_token_price(self, token: Token) -> Decimal:
        data = await self.provider.request('get_token_price', [token.symbol])
        return Decimal(data)

    async def toggle_2fa(self, toggle2fa: Toggle2FA) -> bool:
        data = await self.provider.request('toggle_2fa', [toggle2fa.dict()])
        return 'success' in data and data['success']
