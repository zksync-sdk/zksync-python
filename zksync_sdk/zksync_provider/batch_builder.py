from dataclasses import dataclass

from zksync_sdk.zksync_provider import FeeTxType
from zksync_sdk.wallet import Wallet, DEFAULT_VALID_FROM, DEFAULT_VALID_UNTIL, AmountsMissing
from zksync_sdk.types import (ChangePubKey, ChangePubKeyCREATE2, ChangePubKeyEcdsa,
                              ChangePubKeyTypes, EncodedTx, ForcedExit, TokenLike,
                              TransactionWithOptionalSignature,
                              Transfer, TxEthSignature,
                              Withdraw, MintNFT, WithdrawNFT, NFT, EncodedTxType, Order, Swap)
from typing import List, Union, Tuple, Optional
from decimal import Decimal


@dataclass
class BatchResult:
    transactions: list
    signature: TxEthSignature
    total_fees: dict


class BatchBuilder:
    IS_ENCODED_TRANSACTION = "is_encoded_trx"
    ENCODED_TRANSACTION_TYPE = "internal_type"

    TRANSACTIONS_ENTRY = "transactions"
    SIGNATURE_ENTRY = "signature"

    @classmethod
    def from_wallet(cls, wallet: Wallet, nonce: int, txs: Optional[List[EncodedTx]] = None):
        obj = BatchBuilder(wallet, nonce, txs)
        return obj

    def __init__(self, wallet: Wallet, nonce: int, txs: Optional[List[EncodedTx]] = None):
        if txs is None:
            txs = []
        self.wallet = wallet
        self.nonce = nonce
        self.batch_nonce = nonce
        self.transactions: List[dict] = []
        for tx in txs:
            value = tx.dict()
            value[self.IS_ENCODED_TRANSACTION] = True
            value[self.ENCODED_TRANSACTION_TYPE] = tx.tx_type()
            self.transactions.append(value)

    async def build(self) -> BatchResult:
        if not self.transactions:
            raise RuntimeError("Transaction batch cannot be empty")
        res = await self._process_transactions()
        trans = res["trans"]
        signature = self.wallet.eth_signer.sign(res["msg"].encode())
        return BatchResult(trans, signature, res["total_fee"])

    def add_withdraw(self,
                     eth_address: str,
                     token: TokenLike,
                     amount: Decimal,
                     fee: Optional[Decimal] = None,
                     valid_from=DEFAULT_VALID_FROM,
                     valid_until=DEFAULT_VALID_UNTIL
                     ):
        withdraw = {
            self.ENCODED_TRANSACTION_TYPE: EncodedTxType.WITHDRAW,
            self.IS_ENCODED_TRANSACTION: False,
            "eth_address": eth_address,
            "token": token,
            "amount": amount,
            "fee": fee,
            "valid_from": valid_from,
            "valid_until": valid_until
        }
        self.transactions.append(withdraw)

    def add_mint_nft(self,
                     content_hash: str,
                     recipient: str,
                     fee_token: TokenLike,
                     fee: Optional[Decimal] = None
                     ):
        mint_nft = {
            self.ENCODED_TRANSACTION_TYPE: EncodedTxType.MINT_NFT,
            self.IS_ENCODED_TRANSACTION: False,
            "content_hash": content_hash,
            "recipient": recipient,
            "fee_token": fee_token,
            "fee": fee
        }
        self.transactions.append(mint_nft)

    def add_withdraw_nft(self,
                         to_address: str,
                         nft_token: NFT,
                         fee_token: TokenLike,
                         fee: Optional[Decimal] = None,
                         valid_from=DEFAULT_VALID_FROM,
                         valid_until=DEFAULT_VALID_UNTIL
                         ):
        withdraw_nft = {
            self.ENCODED_TRANSACTION_TYPE: EncodedTxType.WITHDRAW_NFT,
            self.IS_ENCODED_TRANSACTION: False,
            "to_address": to_address,
            "nft_token": nft_token,
            "fee_token": fee_token,
            "fee": fee,
            "valid_from": valid_from,
            "valid_until": valid_until
        }
        self.transactions.append(withdraw_nft)

    def add_swap(self,
                 orders: Tuple[Order, Order],
                 fee_token: TokenLike,
                 amounts: Optional[Tuple[Decimal, Decimal]] = None,
                 fee: Optional[Decimal] = None
                 ):
        if amounts is None:
            if orders[0].amount == 0 or orders[1].amount == 0:
                raise AmountsMissing("in this case you must specify amounts explicitly")
        swap = {
            self.ENCODED_TRANSACTION_TYPE: EncodedTxType.SWAP,
            self.IS_ENCODED_TRANSACTION: False,
            "orders": orders,
            "fee_token": fee_token,
            "amounts": amounts,
            "fee": fee
        }
        self.transactions.append(swap)

    def add_transfer(self,
                     address_to: str,
                     token: TokenLike,
                     amount: Decimal,
                     fee: Optional[Decimal] = None,
                     valid_from=DEFAULT_VALID_FROM,
                     valid_until=DEFAULT_VALID_UNTIL
                     ):
        transfer = {
            self.ENCODED_TRANSACTION_TYPE: EncodedTxType.TRANSFER,
            self.IS_ENCODED_TRANSACTION: False,
            "from_address": self.wallet.address(),
            "to_address": address_to.lower(),
            "token": token,
            "amount": amount,
            "fee": fee,
            "valid_from": valid_from,
            "valid_until": valid_until
        }
        self.transactions.append(transfer)

    def add_change_pub_key(self,
                           fee_token: TokenLike,
                           eth_auth_type: Union[ChangePubKeyCREATE2, ChangePubKeyEcdsa, None],
                           fee: Optional[Decimal] = None,
                           valid_from=DEFAULT_VALID_FROM,
                           valid_until=DEFAULT_VALID_UNTIL
                           ):
        new_pubkey_hash = self.wallet.zk_signer.pubkey_hash_str()
        change_pub_key = {
            self.ENCODED_TRANSACTION_TYPE: EncodedTxType.CHANGE_PUB_KEY,
            self.IS_ENCODED_TRANSACTION: False,
            "account": self.wallet.address(),
            "new_pk_hash": new_pubkey_hash,
            "fee_token": fee_token,
            "fee": fee,
            "eth_auth_type": eth_auth_type,
            "valid_from": valid_from,
            "valid_until": valid_until
        }
        self.transactions.append(change_pub_key)

    def add_force_exit(self,
                       target_address: str,
                       token: TokenLike,
                       fee: Optional[Decimal] = None,
                       valid_from=DEFAULT_VALID_FROM,
                       valid_until=DEFAULT_VALID_UNTIL
                       ):
        forced_exit = {
            self.ENCODED_TRANSACTION_TYPE: EncodedTxType.FORCED_EXIT,
            self.IS_ENCODED_TRANSACTION: False,
            "target": target_address,
            "token": token,
            "fee": fee,
            "valid_from": valid_from,
            "valid_until": valid_until
        }
        self.transactions.append(forced_exit)

    async def _process_change_pub_key(self, obj: dict):
        if not obj[self.IS_ENCODED_TRANSACTION]:
            account_id = await self.wallet.get_account_id()
            token = await self.wallet.resolve_token(obj["fee_token"])
            eth_auth_type = obj["eth_auth_type"]
            if isinstance(eth_auth_type, ChangePubKeyEcdsa):
                eth_auth_type = ChangePubKeyTypes.ecdsa
            elif isinstance(eth_auth_type, ChangePubKeyCREATE2):
                eth_auth_type = ChangePubKeyTypes.create2
            else:
                eth_auth_type = ChangePubKeyTypes.onchain
            fee = obj["fee"]
            if fee is None:
                if eth_auth_type == ChangePubKeyTypes.ecdsa:
                    fee = await self.wallet.zk_provider.get_transaction_fee(FeeTxType.change_pub_key_ecdsa,
                                                                            self.wallet.address(),
                                                                            token.id)
                elif eth_auth_type == ChangePubKeyTypes.onchain:
                    fee = await self.wallet.zk_provider.get_transaction_fee(FeeTxType.change_pub_key_onchain,
                                                                            self.wallet.address(),
                                                                            token.id)
                elif eth_auth_type == ChangePubKeyTypes.create2:
                    fee = await self.wallet.zk_provider.get_transaction_fee(
                        FeeTxType.change_pub_key_create2,
                        self.wallet.address(),
                        token.id)
                fee = fee.total_fee
            else:
                fee = token.from_decimal(fee)
            change_pub_key = ChangePubKey(
                account=obj["account"],
                account_id=account_id,
                new_pk_hash=obj["new_pk_hash"],
                token=token,
                fee=fee,
                nonce=self.nonce,
                valid_from=obj["valid_from"],
                valid_until=obj["valid_until"],
                eth_auth_data=obj["eth_auth_type"]
            )
            eth_signature = self.wallet.eth_signer.sign(change_pub_key.get_eth_tx_bytes())
            eth_auth_data = change_pub_key.get_auth_data(eth_signature.signature)
            change_pub_key.eth_auth_data = eth_auth_data

            zk_signature = self.wallet.zk_signer.sign_tx(change_pub_key)
            change_pub_key.signature = zk_signature
        else:
            change_pub_key = ChangePubKey(
                account_id=obj["accountId"],
                account=obj["account"],
                new_pk_hash=obj["newPkHash"],
                token=obj["fee_token"],
                fee=obj["fee"],
                nonce=self.nonce,
                eth_auth_data=obj["ethAuthData"],
                signature=obj["signature"],
                valid_from=obj["validFrom"],
                valid_until=obj["validUntil"]
            )
        self.nonce += 1
        return change_pub_key

    async def _process_withdraw(self, obj: dict):
        if not obj[self.IS_ENCODED_TRANSACTION]:
            account_id = await self.wallet.get_account_id()
            token = await self.wallet.resolve_token(obj["token"])

            fee = obj["fee"]
            if fee is None:
                fee = await self.wallet.zk_provider.get_transaction_fee(FeeTxType.withdraw,
                                                                        obj["eth_address"],
                                                                        token.id)
                fee = fee.total_fee
            else:
                fee = token.from_decimal(fee)
            amount = token.from_decimal(obj["amount"])

            withdraw = Withdraw(account_id=account_id,
                                from_address=self.wallet.address(),
                                to_address=obj["eth_address"],
                                amount=amount,
                                fee=fee,
                                nonce=self.nonce,
                                valid_from=obj["valid_from"],
                                valid_until=obj["valid_until"],
                                token=token)
            zk_signature = self.wallet.zk_signer.sign_tx(withdraw)
            withdraw.signature = zk_signature
        else:
            token = await self.wallet.resolve_token(obj["token"])
            withdraw = Withdraw(account_id=obj["accountId"],
                                from_address=obj["from"],
                                to_address=obj["to"],
                                amount=obj["amount"],
                                fee=obj["fee"],
                                nonce=self.nonce,
                                valid_from=obj["validFrom"],
                                valid_until=obj["validUntil"],
                                token=token,
                                signature=obj["signature"]
                                )
        self.nonce += 1
        return withdraw

    async def _process_transfer(self, obj):
        if not obj[self.IS_ENCODED_TRANSACTION]:
            account_id = await self.wallet.get_account_id()
            token = await self.wallet.resolve_token(obj["token"])

            fee = obj["fee"]
            if fee is None:
                fee = await self.wallet.zk_provider.get_transaction_fee(FeeTxType.transfer,
                                                                        obj["to_address"],
                                                                        token.id)
                fee = fee.total_fee
            else:
                fee = token.from_decimal(fee)

            amount = token.from_decimal(obj["amount"])
            transfer = Transfer(
                account_id=account_id,
                from_address=obj["from_address"].lower(),
                to_address=obj["to_address"].lower(),
                token=token,
                amount=amount,
                fee=fee,
                nonce=self.nonce,
                valid_from=obj["valid_from"],
                valid_until=obj["valid_until"]
            )
            zk_signature = self.wallet.zk_signer.sign_tx(transfer)
            transfer.signature = zk_signature
        else:
            token = await self.wallet.resolve_token(obj["token"])
            transfer = Transfer(
                account_id=obj["accountId"],
                from_address=obj["from"],
                to_address=obj["to"],
                token=token,
                amount=obj["amount"],
                fee=obj["fee"],
                nonce=self.nonce,
                valid_from=obj["validFrom"],
                valid_until=obj["validUntil"],
                signature=obj["signature"]
            )
        self.nonce += 1
        return transfer

    async def _process_forced_exit(self, obj):
        if not obj[self.IS_ENCODED_TRANSACTION]:
            account_id = await self.wallet.get_account_id()
            token = await self.wallet.resolve_token(obj["token"])
            fee = obj["fee"]
            if fee is None:
                fee = await self.wallet.zk_provider.get_transaction_fee(FeeTxType.transfer,
                                                                        obj["to_address"],
                                                                        token.id)
                fee = fee.total_fee
            else:
                fee = token.from_decimal(fee)
            forced_exit = ForcedExit(initiator_account_id=account_id,
                                     target=obj["target"],
                                     fee=fee,
                                     nonce=self.nonce,
                                     valid_from=obj["valid_from"],
                                     valid_until=obj["valid_until"],
                                     token=token)
            zk_signature = self.wallet.zk_signer.sign_tx(forced_exit)
            forced_exit.signature = zk_signature
        else:
            token = await self.wallet.resolve_token(obj["token"])
            forced_exit = ForcedExit(initiator_account_id=obj["initiatorAccountId"],
                                     target=obj["target"],
                                     fee=obj["fee"],
                                     nonce=self.nonce,
                                     valid_from=obj["valid_from"],
                                     valid_until=obj["valid_until"],
                                     token=token,
                                     signature=obj["signature"])
        self.nonce += 1
        return forced_exit

    async def _process_swap(self, obj):
        if not obj[self.IS_ENCODED_TRANSACTION]:
            fee_token = await self.wallet.resolve_token(obj["fee_token"])
            fee = obj["fee"]
            if fee is None:
                fee = await self.wallet.zk_provider.get_transaction_fee(FeeTxType.swap,
                                                                        self.wallet.address(),
                                                                        fee_token.id)
                fee = fee.total_fee
            else:
                fee = fee_token.from_decimal(fee)

            amounts = obj["amounts"]
            orders = obj["orders"]
            if amounts is None:
                amounts = (orders[0].amount, orders[1].amount)
            else:
                amounts = (
                    orders[0].token_sell.from_decimal(amounts[0]),
                    orders[1].token_sell.from_decimal(amounts[1])
                )
            account_id = await self.wallet.get_account_id()
            swap = Swap(
                orders=orders,
                fee_token=fee_token,
                amounts=amounts,
                fee=fee,
                nonce=self.nonce,
                submitter_id=account_id,
                submitter_address=self.wallet.address()
            )
            swap.signature = self.wallet.zk_signer.sign_tx(swap)
        else:
            fee_token = await self.wallet.resolve_token(obj["feeToken"])
            swap = Swap(
                orders=obj["orders"],
                fee_token=fee_token,
                amounts=obj["amounts"],
                fee=obj["fee"],
                nonce=self.nonce,
                submitter_id=obj["submitterId"],
                submitter_address=obj["submitterAddress"],
                signature=obj["signature"]
            )
        self.nonce += 1
        return swap

    async def _process_mint_nft(self, obj):
        if not obj[self.IS_ENCODED_TRANSACTION]:
            fee_token = await self.wallet.resolve_token(obj["fee_token"])
            account_id = await self.wallet.get_account_id()

            fee = obj["fee"]
            if fee is None:
                fee = await self.wallet.zk_provider.get_transaction_fee(FeeTxType.mint_nft,
                                                                        obj["recipient"],
                                                                        fee_token.id)
                fee = fee.total_fee
            else:
                fee = fee_token.from_decimal(fee)
            mint_nft = MintNFT(creator_id=account_id,
                               creator_address=self.wallet.address(),
                               content_hash=obj["content_hash"],
                               recipient=obj["recipient"],
                               fee=fee,
                               fee_token=fee_token,
                               nonce=self.nonce)
            zk_signature = self.wallet.zk_signer.sign_tx(mint_nft)
            mint_nft.signature = zk_signature
        else:
            fee_token = await self.wallet.resolve_token(obj["fee_token"])
            mint_nft = MintNFT(creator_id=obj["creatorId"],
                               creator_address=obj["creatorAddress"],
                               content_hash=obj["content_hash"],
                               recipient=obj["recipient"],
                               fee=obj["fee"],
                               fee_token=fee_token,
                               nonce=self.nonce,
                               signature=obj["signature"]
                               )
        self.nonce += 1
        return mint_nft

    async def _process_withdraw_nft(self, obj):
        if not obj[self.IS_ENCODED_TRANSACTION]:
            fee_token = await self.wallet.resolve_token(obj["fee_token"])

            fee = obj["fee"]
            if fee is None:
                fee = await self.wallet.zk_provider.get_transaction_fee(FeeTxType.withdraw_nft,
                                                                        obj["to_address"],
                                                                        fee_token.id
                                                                        )
                fee = fee.total_fee
            else:
                fee = fee_token.from_decimal(fee)

            account_id = await self.wallet.get_account_id()

            withdraw_nft = WithdrawNFT(
                account_id=account_id,
                from_address=self.wallet.address(),
                to_address=obj["to_address"],
                fee_token=fee_token,
                fee=fee,
                nonce=self.nonce,
                valid_from=obj["valid_from"],
                valid_until=obj["valid_until"],
                token_id=obj["nft_token"].id
            )
            zk_signature = self.wallet.zk_signer.sign_tx(withdraw_nft)
            withdraw_nft.signature = zk_signature
        else:
            fee_token = await self.wallet.resolve_token(obj["feeToken"])
            withdraw_nft = WithdrawNFT(
                account_id=obj["accountId"],
                from_address=obj["from"],
                to_address=obj["to"],
                fee_token=fee_token,
                fee=obj["fee"],
                nonce=obj["nonce"],
                valid_from=obj["validFrom"],
                valid_until=obj["validUntil"],
                token_id=obj["nft_token"].id,
                signature=obj["signature"]
            )
        self.nonce += 1
        return withdraw_nft

    async def _process_transactions(self):
        message = ""
        trs = []
        total_fee_map = dict()
        for obj in self.transactions:
            if obj[self.ENCODED_TRANSACTION_TYPE] == EncodedTxType.CHANGE_PUB_KEY:
                tr = await self._process_change_pub_key(obj)

                prev_value = total_fee_map.get(tr.token.symbol, Decimal(0))
                dec_fee = tr.token.decimal_amount(tr.fee)
                total_fee_map[tr.token.symbol] = dec_fee + prev_value

                message += tr.batch_message_part()
                trs.append(TransactionWithOptionalSignature(tr))
            elif obj[self.ENCODED_TRANSACTION_TYPE] == EncodedTxType.TRANSFER:
                tr = await self._process_transfer(obj)

                prev_value = total_fee_map.get(tr.token.symbol, Decimal(0))
                dec_fee = tr.token.decimal_amount(tr.fee)
                total_fee_map[tr.token.symbol] = dec_fee + prev_value

                message += tr.batch_message_part()
                trs.append(TransactionWithOptionalSignature(tr))
            elif obj[self.ENCODED_TRANSACTION_TYPE] == EncodedTxType.WITHDRAW:
                tr = await self._process_withdraw(obj)

                prev_value = total_fee_map.get(tr.token.symbol, Decimal(0))
                dec_fee = tr.token.decimal_amount(tr.fee)
                total_fee_map[tr.token.symbol] = dec_fee + prev_value

                message += tr.batch_message_part()
                trs.append(TransactionWithOptionalSignature(tr))
            elif obj[self.ENCODED_TRANSACTION_TYPE] == EncodedTxType.FORCED_EXIT:
                tr = await self._process_forced_exit(obj)

                prev_value = total_fee_map.get(tr.token.symbol, Decimal(0))
                dec_fee = tr.token.decimal_amount(tr.fee)
                total_fee_map[tr.token.symbol] = dec_fee + prev_value

                message += tr.batch_message_part()
                trs.append(TransactionWithOptionalSignature(tr))
            elif obj[self.ENCODED_TRANSACTION_TYPE] == EncodedTxType.MINT_NFT:
                tr = await self._process_mint_nft(obj)

                prev_value = total_fee_map.get(tr.fee_token.symbol, Decimal(0))
                dec_fee = tr.fee_token.decimal_amount(tr.fee)
                total_fee_map[tr.fee_token.symbol] = dec_fee + prev_value

                message += tr.batch_message_part()
                trs.append(TransactionWithOptionalSignature(tr))
            elif obj[self.ENCODED_TRANSACTION_TYPE] == EncodedTxType.WITHDRAW_NFT:
                tr = await self._process_withdraw_nft(obj)

                prev_value = total_fee_map.get(tr.fee_token.symbol, Decimal(0))
                dec_fee = tr.fee_token.decimal_amount(tr.fee)
                total_fee_map[tr.fee_token.symbol] = dec_fee + prev_value

                message += tr.batch_message_part()
                trs.append(TransactionWithOptionalSignature(tr))
            elif obj[self.ENCODED_TRANSACTION_TYPE] == EncodedTxType.SWAP:
                tr = await self._process_swap(obj)

                prev_value = total_fee_map.get(tr.fee_token.symbol, Decimal(0))
                dec_fee = tr.fee_token.decimal_amount(tr.fee)
                total_fee_map[tr.fee_token.symbol] = dec_fee + prev_value
                message += tr.batch_message_part()
                trs.append(TransactionWithOptionalSignature(tr, [None,
                                                                 tr.orders[0].eth_signature,
                                                                 tr.orders[1].eth_signature]
                                                            ))
            else:
                raise TypeError("_process_transactions is trying to process unimplemented type")
        message += f"Nonce: {self.batch_nonce}"
        result = dict(trans=trs, msg=message, total_fee=total_fee_map)
        return result
