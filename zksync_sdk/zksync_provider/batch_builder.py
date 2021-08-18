from zksync_sdk.zksync_provider import FeeTxType
from zksync_sdk.zksync_provider.transaction import Transaction
from zksync_sdk.wallet import Wallet, DEFAULT_VALID_FROM, DEFAULT_VALID_UNTIL, AmountsMissing
from zksync_sdk.types import (ChangePubKey, ChangePubKeyCREATE2, ChangePubKeyEcdsa,
                              ChangePubKeyTypes, EncodedTx, ForcedExit, Token, TokenLike,
                              Tokens, TransactionWithSignature, Transfer, TxEthSignature,
                              Withdraw, MintNFT, WithdrawNFT, NFT, Order, Swap, RatioType, EncodedTxType)
from typing import List, Optional, Tuple, Union
from decimal import Decimal


class BatchBuilder:

    IS_ENCODED_TRANSACTION = "is_encoded_trx"
    ENCODED_TRANSACTION_TYPE = "internal_type"

    @classmethod
    def from_wallet(cls, wallet: Wallet, nonce: int, txs: List[EncodedTx] = None):
        obj = BatchBuilder(wallet, nonce, txs)
        return obj

    def __init__(self, wallet: Wallet, nonce: int, txs: List[EncodedTx] = None):
        if txs is None:
            txs = []
        self.wallet = wallet
        self.nonce = nonce
        self.transactions: List[dict] = []
        for tx in txs:
            value = tx.dict()
            value[self.IS_ENCODED_TRANSACTION] = True
            value[self.ENCODED_TRANSACTION_TYPE] = tx.tx_type()
            self.transactions.append(value)
        self.fee_token: TokenLike = None

    async def build(self, fee_token: TokenLike):
        # totalFee: Fee = None
        if not self.transactions:
            raise RuntimeError("Transaction batch cannot be empty")
        res = await self._process_transactions()
        return res
        # return [], None, totalFee

    def set_fee_token(self, fee_token: TokenLike):
        raise NotImplementedError

    def add_withdraw(self,
                     eth_address: str,
                     token: TokenLike,
                     amount: Decimal,
                     fee: int = None,
                     valid_from=DEFAULT_VALID_FROM,
                     valid_until=DEFAULT_VALID_UNTIL
                     ):
        # withdraw_coroutine = self.wallet.build_withdraw(eth_address, amount, token, fee, valid_from=valid_from,
        #                                                 valid_until=valid_until)
        withdraw = {
            self.ENCODED_TRANSACTION_TYPE: EncodedTxType.CHANGE_PUB_KEY,
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
                     fee: Decimal = None,
                     nonce: int = None
                     ):
        mint_nft = {
            "content_hash": content_hash,
            "recipient": recipient,
            "fee_token": fee_token,
            "fee": fee,
            "nonce": nonce
        }
        self.transactions.append(mint_nft)

    def add_withdraw_nft(self,
                         to_address: str,
                         nft_token: NFT,
                         fee_token: TokenLike,
                         fee: Decimal = None,
                         valid_from=DEFAULT_VALID_FROM,
                         valid_until=DEFAULT_VALID_UNTIL
                         ):
        withdraw_nft = {
            "to_address": to_address,
            "nft_token": nft_token,
            "fee_token": fee_token,
            "fee": fee,
            "valid_from": valid_from,
            "valid_until": valid_until
        }

        # withdraw_nft_coroutine = self.wallet.withdraw_nft(address_to, nft_token, fee_token, fee, valid_from,
        #                                                 valid_until)
        self.transactions.append(withdraw_nft)

    def add_swap(self,
                 orders: Tuple[Order, Order],
                 fee_token: TokenLike,
                 amounts: Tuple[Decimal, Decimal],
                 fee: Decimal = None
                 ):
        # swap_coroutine = self.wallet.swap(orders, fee_token, amounts, fee)
        if amounts is None:
            if orders[0].amount == 0 or orders[1].amount == 0:
                raise AmountsMissing("in this case you must specify amounts explicitly")
        swap = {
            self.ENCODED_TRANSACTION_TYPE: EncodedTxType.CHANGE_PUB_KEY,
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
                     fee: Decimal = None,
                     valid_from=DEFAULT_VALID_FROM,
                     valid_until=DEFAULT_VALID_UNTIL
                     ):
        # transfer_coroutine = self.wallet.transfer(address_to, amount, token, fee, valid_from, valid_until)
        transfer = {
            self.ENCODED_TRANSACTION_TYPE: EncodedTxType.CHANGE_PUB_KEY,
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
                           fee: Decimal = None,
                           valid_from=DEFAULT_VALID_FROM,
                           valid_until=DEFAULT_VALID_UNTIL
                           ):
        # self.wallet.build_change_pub_key()
        new_pubkey_hash = self.wallet.zk_signer.pubkey_hash_str()
        change_pub_key = {
            self.ENCODED_TRANSACTION_TYPE: EncodedTxType.CHANGE_PUB_KEY,
            self.IS_ENCODED_TRANSACTION: False,
            "account" : self.wallet.address(),
            "new_pk_hash" : new_pubkey_hash,
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
                       fee: Decimal = None,
                       valid_from=DEFAULT_VALID_FROM,
                       valid_until=DEFAULT_VALID_UNTIL
                       ):
        # self.wallet.build_forced_exit()
        forced_exit = {
            "target": target_address,
            "token": token,
            "fee": fee,
            "valid_from": valid_from,
            "valid_until": valid_until
        }
        self.transactions.append(forced_exit)

    async def _process_change_pub_key(self, obj: dict):
        if not obj[self.IS_ENCODED_TRANSACTION]:
            nonce = await self.wallet.zk_provider.get_account_nonce(self.wallet.address())
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
                # elif eth_auth_type == ChangePubKeyTypes.onchain:
                #     fee = await self.wallet.zk_provider.get_transaction_fee(
                #         FeeTxType.change_pub_key_onchain,
                #         self.wallet.address(),
                #         token.id)
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
                nonce=nonce,
                valid_from=obj["valid_from"],
                valid_until=obj["valid_until"],
                eth_auth_data=obj["eth_auth_type"]
            )
            eth_signature = self.wallet.eth_signer.sign(change_pub_key.get_eth_tx_bytes())
            eth_auth_data = change_pub_key.get_auth_data(eth_signature.signature)
            change_pub_key.eth_auth_data = eth_auth_data
            zk_signature = self.wallet.zk_signer.sign_tx(change_pub_key)
            change_pub_key.signature = zk_signature
            return change_pub_key, eth_signature
        else:
            change_pub_key = ChangePubKey(
                account_id=obj["accountId"],
                account=obj["account"],
                new_pk_hash=obj["newPkHash"],
                token=obj["fee_token"],
                fee=obj["fee"],
                nonce=obj["nonce"],
                eth_auth_data=obj["ethAuthData"],
                signature=obj["signature"],
                valid_from=obj["validFrom"],
                valid_until=obj["validUntil"]
            )
        zk_signature = self.wallet.zk_signer.sign_tx(change_pub_key)
        change_pub_key.signature = zk_signature
        # INFO: NEEDS CHECKING, Is it possible to get eth_signature from signature value
        return change_pub_key, change_pub_key.signature

    async def _process_withdraw(self, obj: dict):
        if not obj[self.IS_ENCODED_TRANSACTION]:
            nonce = await self.wallet.zk_provider.get_account_nonce(self.wallet.address())
            account_id = await self.wallet.get_account_id()
            token = await self.wallet.resolve_token(obj["token"])

            fee = obj["fee"]
            if fee is None:
                fee = await self.wallet.zk_provider.get_transaction_fee(FeeTxType.withdraw,
                                                                        obj["to_address"],
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
                                nonce=nonce,
                                valid_from=obj["valid_from"],
                                valid_until=obj["valid_until"],
                                token=token)
            eth_signature = self.wallet.eth_signer.sign_tx(withdraw)
            zk_signature = self.wallet.zk_signer.sign_tx(withdraw)
            withdraw.signature = zk_signature
            return withdraw, eth_signature
        else:
            token = await self.wallet.resolve_token(obj["token"])
            withdraw = Withdraw(account_id=obj["accountId"],
                                from_address=obj["from"],
                                to_address=obj["to"],
                                amount=obj["amount"],
                                fee=obj["fee"],
                                nonce=obj["nonce"],
                                valid_from=obj["validFrom"],
                                valid_until=obj["validUntil"],
                                token=token,
                                signature=obj["signature"]
                                )
            eth_signature = self.wallet.eth_signer.sign_tx(withdraw)
            return withdraw, eth_signature

    async def _process_transfer(self, obj):
        if not obj[self.IS_ENCODED_TRANSACTION]:
            nonce = await self.wallet.zk_provider.get_account_nonce(self.wallet.address())
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
                from_address=obj["from_address"],
                to_address=obj["to_address"],
                token=token,
                amount=amount,
                fee=fee,
                nonce=nonce,
                valid_from=obj["valid_from"],
                valid_until=obj["valid_until"]
            )
            eth_signature = self.wallet.eth_signer.sign_tx(transfer)
            zk_signature = self.wallet.zk_signer.sign_tx(transfer)
            transfer.signature = zk_signature
            return transfer, eth_signature
        else:
            token = await self.wallet.resolve_token(obj["token"])
            transfer = Transfer(
                account_id=obj["accountId"],
                from_address=obj["from"],
                to_address=obj["to"],
                token=token,
                amount=obj["amount"],
                fee=obj["fee"],
                nonce=obj["nonce"],
                valid_from=obj["validFrom"],
                valid_until=obj["validUntil"],
                signature=obj["signature"]
            )
            eth_signature = self.wallet.eth_signer.sign_tx(transfer)
            return transfer, eth_signature

    async def _process_forced_exit(self, obj):
        if not obj[self.IS_ENCODED_TRANSACTION]:
            nonce = await self.wallet.zk_provider.get_account_nonce(self.wallet.address())
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
                                     nonce=nonce,
                                     valid_from=obj["valid_from"],
                                     valid_until=obj["valid_until"],
                                     token=token)
            eth_signature = self.wallet.eth_signer.sign_tx(forced_exit)
            zk_signature = self.wallet.zk_signer.sign_tx(forced_exit)
            forced_exit.signature = zk_signature
            return forced_exit, eth_signature
        else:
            # account_id = await self.wallet.get_account_id()
            # nonce = await self.wallet.zk_provider.get_account_nonce(self.wallet.address())
            token = await self.wallet.resolve_token(obj["token"])
            forced_exit = ForcedExit(initiator_account_id=obj["initiatorAccountId"],
                                     target=obj["target"],
                                     fee=obj["fee"],
                                     nonce=obj["nonce"],
                                     valid_from=obj["valid_from"],
                                     valid_until=obj["valid_until"],
                                     token=token,
                                     signature=obj["signature"])
            eth_signature = self.wallet.eth_signer.sign_tx(forced_exit)
            return forced_exit, eth_signature

    async def _process_swap(self, obj):
        if not obj[self.IS_ENCODED_TRANSACTION]:
            nonce = await self.wallet.zk_provider.get_account_nonce(self.wallet.address())
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
                # INFO: validation is happening in add_swap method, should not raise exception
                amounts = (orders[0].amount, orders[1].amount)
            else:
                amounts = (
                    orders[0].token_sell.from_decimal(amounts[0]),
                    orders[1].token_sell.from_decimal(amounts[1])
                )
            if nonce is None:
                nonce = await self.wallet.zk_provider.get_account_nonce(self.wallet.address())
            account_id = await self.wallet.get_account_id()

            swap = Swap(
                orders=orders,
                fee_token=fee_token,
                amounts=amounts,
                fee=fee,
                nonce=nonce,
                submitter_id=account_id,
                submitter_address=self.wallet.address()
            )
            eth_signature = self.wallet.eth_signer.sign_tx(swap)
            swap.signature = self.wallet.zk_signer.sign_tx(swap)
            return swap, eth_signature
        else:
            fee_token = await self.wallet.resolve_token(obj["feeToken"])
            swap = Swap(
                orders=obj["orders"],
                fee_token=fee_token,
                amounts=obj["amounts"],
                fee=obj["fee"],
                nonce=obj["nonce"],
                submitter_id=obj["submitterId"],
                submitter_address=obj["submitterAddress"],
                signature=obj["signature"]
            )
            eth_signature = self.wallet.eth_signer.sign_tx(swap)
            return swap, eth_signature

    async def _process_mint_nft(self, obj):
        if not obj[self.IS_ENCODED_TRANSACTION]:
            nonce = obj["nonce"]
            if nonce is None:
                nonce = await self.wallet.zk_provider.get_account_nonce(self.wallet.address())
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
                               nonce=nonce)
            eth_signature = self.wallet.eth_signer.sign_tx(mint_nft)
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
                               nonce=obj["nonce"],
                               signature=obj["signature"]
                               )
            eth_signature = self.wallet.eth_signer.sign_tx(mint_nft)
            return mint_nft, eth_signature

    async def _process_withdraw_nft(self, obj):
        if not obj[self.IS_ENCODED_TRANSACTION]:
            nonce = await self.wallet.zk_provider.get_account_nonce(self.wallet.address())
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
                nonce=nonce,
                valid_from=obj["valid_from"],
                valid_until=obj["valid_until"],
                token_id=obj["nft_token"].id
            )
            eth_signature = self.wallet.eth_signer.sign_tx(withdraw_nft)
            zk_signature = self.wallet.zk_signer.sign_tx(withdraw_nft)
            withdraw_nft.signature = zk_signature
            return withdraw_nft, eth_signature
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
            eth_signature = self.wallet.eth_signer.sign_tx(withdraw_nft)
            return withdraw_nft, eth_signature

    async def _process_transactions(self):
        trs = []
        for obj in self.transactions:
            if obj[self.ENCODED_TRANSACTION_TYPE] == EncodedTxType.CHANGE_PUB_KEY:
                tr, sig = await self._process_change_pub_key(obj)
                trs.append(TransactionWithSignature(tr, sig))
            elif obj[self.ENCODED_TRANSACTION_TYPE] == EncodedTxType.TRANSFER:
                tr, sig = await self._process_transfer(obj)
                trs.append(TransactionWithSignature(tr, sig))
            elif obj[self.ENCODED_TRANSACTION_TYPE] == EncodedTxType.WITHDRAW:
                tr, sig = await self._process_withdraw(obj)
                trs.append(TransactionWithSignature(tr, sig))
            elif obj[self.ENCODED_TRANSACTION_TYPE] == EncodedTxType.FORCED_EXIT:
                tr, sig = await self._process_forced_exit(obj)
                trs.append(TransactionWithSignature(tr, sig))
            elif obj[self.ENCODED_TRANSACTION_TYPE] == EncodedTxType.SWAP:
                tr, sig = await self._process_swap(obj)
                trs.append(TransactionWithSignature(tr, sig))
            elif obj[self.ENCODED_TRANSACTION_TYPE] == EncodedTxType.MINT_NFT:
                tr, sig = await self._process_mint_nft(obj)
                trs.append(TransactionWithSignature(tr, sig))
            elif obj[self.ENCODED_TRANSACTION_TYPE] == EncodedTxType.WITHDRAW_NFT:
                tr, sig = await self._process_withdraw_nft(obj)
                trs.append(TransactionWithSignature(tr, sig))
            else:
                raise TypeError("_process_transactions is trying to process unimplemented type")
        res = await self.wallet.send_txs_batch(trs)
        return res

