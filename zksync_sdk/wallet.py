from decimal import Decimal

from zksync_sdk.ethereum_provider import EthereumProvider
from zksync_sdk.ethereum_signer import EthereumSignerInterface
from zksync_sdk.types import (ChangePubKey, ChangePubKeyTypes, EncodedTx, ForcedExit, Token,
                              TokenLike, Tokens,
                              Transfer,
                              TxEthSignature, Withdraw, )
from zksync_sdk.zksync_provider import TxType, ZkSyncProviderInterface
from zksync_sdk.zksync_signer import ZkSyncSigner


class WalletError(Exception):
    pass


class TokenNotFoundError(WalletError):
    pass


class Wallet:
    def __init__(self, ethereum_provider: EthereumProvider, zk_signer: ZkSyncSigner,
                 eth_signer: EthereumSignerInterface, provider: ZkSyncProviderInterface):
        self.ethereum_provider = ethereum_provider
        self.zk_signer = zk_signer
        self.eth_signer = eth_signer
        self.zk_provider = provider
        self.tokens = Tokens(tokens=[])

    async def send_signed_transaction(self, tx: EncodedTx, eth_signature: TxEthSignature,
                                      fast_processing: bool = False) -> str:
        return await self.zk_provider.submit_tx(tx, eth_signature, fast_processing)

    async def set_signing_key(self, fee_token: TokenLike, eth_auth_type: ChangePubKeyTypes,
                              fee: Decimal = None, nonce: int = None, batch_hash: bytes = None):

        account_id, new_nonce = await self.zk_provider.get_account_nonce(self.address())
        nonce = nonce or new_nonce
        token = await self.resolve_token(fee_token)
        if fee is None:
            if eth_auth_type == ChangePubKeyTypes.ecdsa:
                fee = await self.zk_provider.get_transaction_fee(TxType.change_pub_key_ecdsa,
                                                                 self.address(),
                                                                 fee_token)
            elif eth_auth_type == ChangePubKeyTypes.onchain:
                fee = await self.zk_provider.get_transaction_fee(TxType.change_pub_key_onchain,
                                                                 self.address(),
                                                                 fee_token)
            else:
                raise NotImplementedError

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
            valid_until=2 ** 31,
            valid_from=0,
        )
        if batch_hash is not None:
            change_pub_key.batch_hash = batch_hash

        if eth_auth_type == ChangePubKeyTypes.onchain:
            eth_auth_data = {"type": "Onchain"}
            eth_signature = self.eth_signer.sign(change_pub_key.get_eth_tx_bytes())

        elif eth_auth_type == ChangePubKeyTypes.ecdsa:
            eth_signature = self.eth_signer.sign(change_pub_key.get_eth_tx_bytes())
            eth_auth_data = {"type":         "ECDSA",
                             "ethSignature": eth_signature.signature,
                             "batchHash":    f"0x{change_pub_key.batch_hash.hex()}"}
        else:
            raise NotImplementedError

        change_pub_key.eth_auth_data = eth_auth_data
        zk_signature = self.zk_signer.sign_tx(change_pub_key)
        change_pub_key.signature = zk_signature

        return await self.send_signed_transaction(change_pub_key, eth_signature)

    async def forced_exit(self, target: str, token: TokenLike, fee: Decimal = None) -> str:
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
        eth_signature = self.eth_signer.sign_tx(transfer)
        zk_signature = self.zk_signer.sign_tx(transfer)
        transfer.signature = zk_signature
        return await self.send_signed_transaction(transfer, eth_signature)

    def address(self):
        return self.eth_signer.address()

    async def transfer(self, to: str, amount: Decimal, token: TokenLike,
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
        eth_signature = self.eth_signer.sign_tx(transfer)
        zk_signature = self.zk_signer.sign_tx(transfer)
        transfer.signature = zk_signature
        return await self.send_signed_transaction(transfer, eth_signature)

    async def withdraw(self, eth_address: str, amount: Decimal, token: TokenLike,
                       fee: Decimal = None, fast: bool = False) -> str:
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
        eth_signature = self.eth_signer.sign_tx(transfer)
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
        resolved_token = self.tokens.find(token)
        if resolved_token is not None:
            return resolved_token
        self.tokens = await self.zk_provider.get_tokens()
        resolved_token = self.tokens.find(token)
        if resolved_token is None:
            raise TokenNotFoundError
        return resolved_token
