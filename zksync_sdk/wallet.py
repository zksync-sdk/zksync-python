from decimal import Decimal

from zksync_sdk.ethereum_provider import EthereumProvider
from zksync_sdk.signer import EthereumSigner, ZkSyncSigner
from zksync_sdk.types import (EncodedTx, ForcedExit, Token, TokenLike, Tokens, Transfer,
                              TxEthSignature,
                              Withdraw, )
from zksync_sdk.zksync_provider import TxType, ZkSyncProvider


class Wallet:
    def __init__(self, ethereum_provider: EthereumProvider, zk_signer: ZkSyncSigner,
                 eth_signer: EthereumSigner, provider: ZkSyncProvider):
        self.ethereum_provider = ethereum_provider
        self.zk_signer = zk_signer
        self.eth_signer = eth_signer
        self.zk_provider = provider
        self.tokens = Tokens()

    async def send_signed_transaction(self, tx: EncodedTx, eth_signature: TxEthSignature,
                                      fast_processing: bool) -> str:
        return await self.zk_provider.submit_tx(tx, eth_signature, fast_processing)

    async def change_pub_key(self, onchain_auth: bool, nonce: int = None,
                             fast_processing: bool = False):
        raise NotImplementedError

    async def forced_exit(self, target: str, token: TokenLike, fee: Decimal = None,
                          fast_processing: bool = False) -> str:
        account_id, nonce = await self.zk_provider.get_account_nonce(self.address())
        token = await self.resolve_token(token)
        if fee is None:
            fee = await self.zk_provider.get_transaction_fee(TxType.withdraw, target, token.id)
            fee = fee.total_fee
        else:
            fee = token.from_decimal(fee)
        transfer = ForcedExit(initiator_account_id=account_id,
                              target=target,
                              fee=fee,
                              nonce=nonce,
                              valid_from=0,
                              valid_until=2 ** 31,
                              token=token)
        eth_signature = self.eth_signer.sign(transfer)
        zk_signature = self.zk_signer.sign_tx(transfer)
        transfer.signature = zk_signature
        return await self.send_signed_transaction(transfer, eth_signature, fast_processing)

    def address(self):
        return self.eth_signer.account.address

    async def transfer(self, to: str, amount: Decimal, token: TokenLike, fast_processing: bool,
                       fee: Decimal = None) -> str:
        account_id, nonce = await self.zk_provider.get_account_nonce(self.address())
        token = await self.resolve_token(token)
        if fee is None:
            fee = await self.zk_provider.get_transaction_fee(TxType.transfer, to, token.id)
            fee = fee.total_fee
        else:
            fee = token.from_decimal(fee)
        transfer = Transfer(account_id=account_id, from_address=self.address(),
                            to_address=to,
                            amount=token.from_decimal(amount), fee=fee,
                            nonce=nonce,
                            valid_from=0,
                            valid_until=2 ** 31,
                            token=token)
        eth_signature = self.eth_signer.sign(transfer)
        zk_signature = self.zk_signer.sign_tx(transfer)
        transfer.signature = zk_signature
        return await self.send_signed_transaction(transfer, eth_signature, fast_processing)

    async def withdraw(self, eth_address: str, amount: Decimal, token: TokenLike,
                       fee: Decimal = None,
                       fast: bool = False) -> str:
        account_id, nonce = await self.zk_provider.get_account_nonce(self.address())
        token = await self.resolve_token(token)
        if fee is None:
            tx_type = TxType.fast_withdraw if fast else TxType.withdraw
            fee = await self.zk_provider.get_transaction_fee(tx_type, eth_address, token.id)
            fee = fee.total_fee
        else:
            fee = token.from_decimal(fee)
        transfer = Withdraw(account_id=account_id, from_address=self.address(),
                            to_address=eth_address,
                            amount=token.from_decimal(amount), fee=fee,
                            nonce=nonce,
                            valid_from=0,
                            valid_until=2 ** 31,
                            token=token)
        eth_signature = self.eth_signer.sign(transfer)
        zk_signature = self.zk_signer.sign_tx(transfer)
        transfer.signature = zk_signature
        return await self.send_signed_transaction(transfer, eth_signature, fast)

    async def get_balance(self, token: TokenLike, type: str):
        account_state = await self.zk_provider.get_state(self.address())
        token = await self.resolve_token(token)

        if type == "committed":
            token_balance = account_state.committed.balances.get(token.symbol)
        else:
            token_balance = account_state.verified.balances.get(token.symbol)
        if token_balance is None:
            token_balance = 0
        return token_balance

    async def resolve_token(self, token: TokenLike) -> Token:
        resolved_token = self._find_cached_tokens(token)
        if resolved_token is not None:
            return resolved_token
        self.tokens = await self.zk_provider.get_tokens()
        resolved_token = self._find_cached_tokens(token)
        if resolved_token is None:
            raise Exception
        return resolved_token

    def _find_cached_tokens(self, token: TokenLike) -> Token:
        result = None
        if isinstance(token, int):
            result = self.tokens.find_by_id(token)

        if isinstance(token, str):
            result = self.tokens.find_by_address(address=token)
            if result is None:
                result = self.tokens.find_by_symbol(symbol=token)
        return result
