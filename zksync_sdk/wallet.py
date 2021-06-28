from decimal import Decimal
from fractions import Fraction
from typing import List, Optional, Tuple, Union

from zksync_sdk.ethereum_provider import EthereumProvider
from zksync_sdk.ethereum_signer import EthereumSignerInterface
from zksync_sdk.types import (ChangePubKey, ChangePubKeyCREATE2, ChangePubKeyEcdsa,
                              ChangePubKeyTypes, EncodedTx, ForcedExit, Token, TokenLike,
                              Tokens, TransactionWithSignature, Transfer, TxEthSignature,
                              Withdraw, MintNFT, WithdrawNFT, NFT, Order, Swap, RatioType)
from zksync_sdk.zksync_provider import FeeTxType, ZkSyncProviderInterface
from zksync_sdk.zksync_signer import ZkSyncSigner

DEFAULT_VALID_FROM = 0
DEFAULT_VALID_UNTIL = 2 ** 32 - 1


class WalletError(Exception):
    pass


class TokenNotFoundError(WalletError):
    pass


class AmountsMissing(WalletError):
    pass

class Wallet:
    def __init__(self, ethereum_provider: EthereumProvider, zk_signer: ZkSyncSigner,
                 eth_signer: EthereumSignerInterface, provider: ZkSyncProviderInterface):
        self.ethereum_provider = ethereum_provider
        self.zk_signer = zk_signer
        self.eth_signer = eth_signer
        self.zk_provider = provider
        self.tokens = Tokens(tokens=[])

    async def send_signed_transaction(self, tx: EncodedTx, eth_signature: Union[Optional[TxEthSignature], List[Optional[TxEthSignature]]],
                                      fast_processing: bool = False) -> str:
        return await self.zk_provider.submit_tx(tx, eth_signature, fast_processing)

    async def send_txs_batch(self, transactions: List[TransactionWithSignature],
                             signatures: Optional[
                                 Union[List[TxEthSignature], TxEthSignature]
                             ] = None) -> List[str]:
        return await self.zk_provider.submit_txs_batch(transactions, signatures)

    async def set_signing_key(self, fee_token: TokenLike, *,
                              eth_auth_data: Union[ChangePubKeyCREATE2, ChangePubKeyEcdsa] = None,
                              fee: Decimal = None, nonce: int = None,
                              valid_from=DEFAULT_VALID_FROM, valid_until=DEFAULT_VALID_UNTIL):
        change_pub_key, eth_signature = await self.build_change_pub_key(fee_token,
                                                                        eth_auth_data=eth_auth_data,
                                                                        fee=fee, nonce=nonce,
                                                                        valid_from=valid_from,
                                                                        valid_until=valid_until)

        return await self.send_signed_transaction(change_pub_key, eth_signature)

    async def build_change_pub_key(
        self, fee_token: TokenLike, *,
        fee: Decimal = None, nonce: int = None,
        eth_auth_data: Union[ChangePubKeyCREATE2, ChangePubKeyEcdsa] = None,
        valid_from=DEFAULT_VALID_FROM, valid_until=DEFAULT_VALID_UNTIL
    ):
        account_id, new_nonce = await self.zk_provider.get_account_nonce(self.address())
        nonce = nonce or new_nonce
        token = await self.resolve_token(fee_token)
        if isinstance(eth_auth_data, ChangePubKeyEcdsa):
            eth_auth_type = ChangePubKeyTypes.ecdsa
        elif isinstance(eth_auth_data, ChangePubKeyCREATE2):
            eth_auth_type = ChangePubKeyTypes.create2
        else:
            eth_auth_type = ChangePubKeyTypes.onchain

        if fee is None:
            if eth_auth_type == ChangePubKeyTypes.ecdsa:
                fee = await self.zk_provider.get_transaction_fee(FeeTxType.change_pub_key_ecdsa,
                                                                 self.address(),
                                                                 fee_token)
            elif eth_auth_type == ChangePubKeyTypes.onchain:
                fee = await self.zk_provider.get_transaction_fee(FeeTxType.change_pub_key_onchain,
                                                                 self.address(),
                                                                 fee_token)
            elif eth_auth_type == ChangePubKeyTypes.create2:
                fee = await self.zk_provider.get_transaction_fee(FeeTxType.change_pub_key_create2,
                                                                 self.address(),
                                                                 fee_token)

            fee = fee.total_fee
        else:
            fee = token.from_decimal(fee)

        new_pubkey_hash = self.zk_signer.pubkey_hash_str()
        change_pub_key = ChangePubKey(
            account=self.address(),
            account_id=account_id,
            new_pk_hash=new_pubkey_hash,
            token=token,
            fee=fee,
            nonce=nonce,
            valid_until=valid_until,
            valid_from=valid_from,
            eth_auth_data=eth_auth_data
        )

        eth_signature = self.eth_signer.sign(change_pub_key.get_eth_tx_bytes())
        eth_auth_data = change_pub_key.get_auth_data(eth_signature.signature)

        change_pub_key.eth_auth_data = eth_auth_data
        zk_signature = self.zk_signer.sign_tx(change_pub_key)
        change_pub_key.signature = zk_signature

        return change_pub_key, eth_signature

    async def forced_exit(self, target: str, token: TokenLike, fee: Decimal = None,
                          valid_from=DEFAULT_VALID_FROM, valid_until=DEFAULT_VALID_UNTIL) -> str:
        transfer, eth_signature = await self.build_forced_exit(target, token, fee,
                                                               valid_from, valid_until)

        return await self.send_signed_transaction(transfer, eth_signature)

    async def build_forced_exit(
        self,
        target: str,
        token: TokenLike,
        fee: Decimal = None,
        valid_from=DEFAULT_VALID_FROM,
        valid_until=DEFAULT_VALID_UNTIL
    ) -> Tuple[ForcedExit, TxEthSignature]:
        account_id, nonce = await self.zk_provider.get_account_nonce(self.address())
        token = await self.resolve_token(token)
        if fee is None:
            fee = await self.zk_provider.get_transaction_fee(FeeTxType.withdraw, target, token.id)
            fee = fee.total_fee
        else:
            fee = token.from_decimal(fee)
        forced_exit = ForcedExit(initiator_account_id=account_id,
                                 target=target,
                                 fee=fee,
                                 nonce=nonce,
                                 valid_from=valid_from,
                                 valid_until=valid_until,
                                 token=token)
        eth_signature = self.eth_signer.sign_tx(forced_exit)
        zk_signature = self.zk_signer.sign_tx(forced_exit)
        forced_exit.signature = zk_signature

        return forced_exit, eth_signature

    async def mint_nft(self, content_hash: str, recipient: str,
                       token: TokenLike, fee: Decimal = None) -> str:
        mint_nft, eth_signature = await self.build_mint_nft(content_hash, recipient, token, fee)

        return await self.send_signed_transaction(mint_nft, eth_signature)

    async def build_mint_nft(
        self,
        content_hash: str,
        recipient: str,
        token: TokenLike,
        fee: Decimal = None
    ) -> Tuple[MintNFT, TxEthSignature]:
        account_id, nonce = await self.zk_provider.get_account_nonce(self.address())
        token = await self.resolve_token(token)
        if fee is None:
            fee = await self.zk_provider.get_transaction_fee(FeeTxType.mint_nft, recipient, token.id)
            fee = fee.total_fee
        else:
            fee = token.from_decimal(fee)
        mint_nft = MintNFT(creator_id=account_id,
                           creator_address=self.address(),
                           content_hash=content_hash,
                           recipient=recipient,
                           fee=fee,
                           fee_token=token,
                           nonce=nonce)
        eth_signature = self.eth_signer.sign_tx(mint_nft)
        zk_signature = self.zk_signer.sign_tx(mint_nft)
        mint_nft.signature = zk_signature

        return mint_nft, eth_signature

    async def withdraw_nft(self,
                           to_address: str,
                           nft_token: NFT,
                           fee_token: TokenLike,
                           fee: Decimal = None,
                           valid_from=DEFAULT_VALID_FROM,
                           valid_until=DEFAULT_VALID_UNTIL) -> str:
        withdraw_nft, eth_signature = await self.build_withdraw_nft(to_address, nft_token, fee_token, fee,
                                                                valid_from, valid_until)

        return await self.send_signed_transaction(withdraw_nft, eth_signature)

    async def build_withdraw_nft(self,
                                 to_address: str,
                                 nft_token: NFT,
                                 fee_token: TokenLike,
                                 fee: Decimal = None,
                                 valid_from=DEFAULT_VALID_FROM,
                                 valid_until=DEFAULT_VALID_UNTIL) -> Tuple[WithdrawNFT, TxEthSignature]:
        account_id, nonce = await self.zk_provider.get_account_nonce(self.address())
        fee_token = await self.resolve_token(fee_token)
        if fee is None:
            fee = await self.zk_provider.get_transaction_fee(FeeTxType.withdraw_nft, to_address, fee_token.id)
            fee = fee.total_fee
        else:
            fee = nft_token.from_decimal(fee)
        withdraw_nft = WithdrawNFT(
            account_id=account_id,
            from_address=self.address(),
            to_address=to_address,
            fee_token=fee_token,
            fee=fee,
            nonce=nonce,
            valid_from=valid_from,
            valid_until=valid_until,
            token_id=nft_token.id)
        eth_signature = self.eth_signer.sign_tx(withdraw_nft)
        zk_signature = self.zk_signer.sign_tx(withdraw_nft)
        withdraw_nft.signature = zk_signature

        return withdraw_nft, eth_signature


    def address(self):
        return self.eth_signer.address()

    async def build_transfer(self, to: str, amount: Decimal, token: TokenLike,
                             fee: Decimal = None,
                             valid_from=DEFAULT_VALID_FROM,
                             valid_until=DEFAULT_VALID_UNTIL) -> Tuple[Transfer, TxEthSignature]:
        account_id, nonce = await self.zk_provider.get_account_nonce(self.address())
        token = await self.resolve_token(token)
        if fee is None:
            fee = await self.zk_provider.get_transaction_fee(FeeTxType.transfer, to, token.id)
            fee = fee.total_fee
        else:
            fee = token.from_decimal(fee)
        transfer = Transfer(account_id=account_id, from_address=self.address(),
                            to_address=to,
                            amount=token.from_decimal(amount), fee=fee,
                            nonce=nonce,
                            valid_from=valid_from,
                            valid_until=valid_until,
                            token=token)
        eth_signature = self.eth_signer.sign_tx(transfer)
        zk_signature = self.zk_signer.sign_tx(transfer)
        transfer.signature = zk_signature
        return transfer, eth_signature

    async def transfer(self, to: str, amount: Decimal, token: TokenLike,
                       fee: Decimal = None,
                       valid_from=DEFAULT_VALID_FROM, valid_until=DEFAULT_VALID_UNTIL) -> str:
        transfer, eth_signature = await self.build_transfer(to, amount, token, fee,
                                                            valid_from, valid_until)

        return await self.send_signed_transaction(transfer, eth_signature)

    async def get_order(self, token_sell: TokenLike, token_buy: TokenLike,
                        ratio: Fraction, ratio_type: RatioType, amount: Decimal,
                        recipient: str = None,
                        valid_from=DEFAULT_VALID_FROM,
                        valid_until=DEFAULT_VALID_UNTIL) -> Order:
        account_id, nonce = await self.zk_provider.get_account_nonce(self.address())
        token_sell = await self.resolve_token(token_sell)
        token_buy = await self.resolve_token(token_buy)
        recipient = recipient or self.address()

        if ratio_type == RatioType.token:
            num = token_sell.from_decimal(Decimal(ratio.numerator))
            den = token_buy.from_decimal(Decimal(ratio.denominator))
            ratio = Fraction(num, den)

        order = Order(account_id=account_id, recipient=recipient,
                      token_sell=token_sell,
                      token_buy=token_buy,
                      ratio=ratio,
                      amount=token_sell.from_decimal(amount),
                      nonce=nonce,
                      valid_from=valid_from,
                      valid_until=valid_until)

        order.eth_signature = self.eth_signer.sign_tx(order)
        order.signature = self.zk_signer.sign_tx(order)
        return order

    async def get_limit_order(self, token_sell: TokenLike, token_buy: TokenLike,
                              ratio: Fraction, ratio_type: RatioType,
                              recipient: str = None,
                              valid_from=DEFAULT_VALID_FROM,
                              valid_until=DEFAULT_VALID_UNTIL):
        return await self.get_order(token_sell, token_buy, ratio, ratio_type, Decimal(0), recipient, valid_from, valid_until)

    async def build_swap(self, orders: Tuple[Order, Order], fee_token: TokenLike,
                         amounts: Tuple[Decimal, Decimal] = None, fee: Decimal = None):
        account_id, nonce = await self.zk_provider.get_account_nonce(self.address())
        fee_token = await self.resolve_token(fee_token)
        if fee is None:
            fee = await self.zk_provider.get_transaction_fee(FeeTxType.swap, self.address(), fee_token.id)
            fee = fee.total_fee
        else:
            fee = token.from_decimal(fee)
        if amounts is None:
            amounts = (orders[0].amount, orders[1].amount)
            if amounts[0] == 0 or amounts[1] == 0:
                raise AmountsMissing("in this case you must specify amounts explicitly")
        swap = Swap(
            orders=orders, fee_token=fee_token, amounts=amounts, fee=fee, nonce=nonce,
            submitter_id=account_id, submitter_address=self.address()
        )
        eth_signature = self.eth_signer.sign_tx(swap)
        swap.signature = self.zk_signer.sign_tx(swap)
        return swap, eth_signature

    async def swap(self, orders: Tuple[Order, Order], fee_token: TokenLike,
                         amounts: Tuple[Decimal, Decimal] = None, fee: Decimal = None):
        swap, eth_signature = await self.build_swap(orders, fee_token, amounts, fee)
        eth_signatures = [eth_signature, swap.orders[0].eth_signature, swap.orders[1].eth_signature]
        return await self.send_signed_transaction(swap, eth_signatures)

    async def build_withdraw(self, eth_address: str, amount: Decimal, token: TokenLike,
                             fee: Decimal = None, fast: bool = False,
                             valid_from=DEFAULT_VALID_FROM,
                             valid_until=DEFAULT_VALID_UNTIL) -> (Withdraw, TxEthSignature):
        account_id, nonce = await self.zk_provider.get_account_nonce(self.address())
        token = await self.resolve_token(token)
        if fee is None:
            tx_type = FeeTxType.fast_withdraw if fast else FeeTxType.withdraw
            fee = await self.zk_provider.get_transaction_fee(tx_type, eth_address, token.id)
            fee = fee.total_fee
        else:
            fee = token.from_decimal(fee)
        withdraw = Withdraw(account_id=account_id, from_address=self.address(),
                            to_address=eth_address,
                            amount=token.from_decimal(amount), fee=fee,
                            nonce=nonce,
                            valid_from=valid_from,
                            valid_until=valid_until,
                            token=token)
        eth_signature = self.eth_signer.sign_tx(withdraw)
        zk_signature = self.zk_signer.sign_tx(withdraw)
        withdraw.signature = zk_signature
        return withdraw, eth_signature

    async def withdraw(self, eth_address: str, amount: Decimal, token: TokenLike,
                       fee: Decimal = None, fast: bool = False,
                       valid_from=DEFAULT_VALID_FROM, valid_until=DEFAULT_VALID_UNTIL) -> str:

        withdraw, eth_signature = await self.build_withdraw(eth_address, amount, token, fee, fast,
                                                            valid_from, valid_until)
        return await self.send_signed_transaction(withdraw, eth_signature, fast)

    async def get_balance(self, token: TokenLike, type: str):
        account_state = await self.get_account_state()
        token = await self.resolve_token(token)

        if type == "committed":
            token_balance = account_state.committed.balances.get(token.symbol)
        else:
            token_balance = account_state.verified.balances.get(token.symbol)
        if token_balance is None:
            token_balance = 0
        return token_balance

    async def get_account_state(self):
        return await self.zk_provider.get_state(self.address())

    async def is_signing_key_set(self) -> bool:
        account_state = await self.get_account_state()
        signer_pub_key_hash = self.zk_signer.pubkey_hash_str()
        return account_state.id is not None and \
               account_state.committed.pub_key_hash == signer_pub_key_hash

    async def resolve_token(self, token: TokenLike) -> Token:
        resolved_token = self.tokens.find(token)
        if resolved_token is not None:
            return resolved_token
        self.tokens = await self.zk_provider.get_tokens()
        resolved_token = self.tokens.find(token)
        if resolved_token is None:
            raise TokenNotFoundError
        return resolved_token
