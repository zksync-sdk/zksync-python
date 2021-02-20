from decimal import Decimal

from web3 import Web3

from zksync_sdk.types import Token
from zksync_sdk.zksync import ERC20Contract, ZkSync


class EthereumProvider:
    def __init__(self, web3: Web3, zksync: ZkSync):
        self.web3 = web3
        self.zksync = zksync

    async def approve_deposit(self, token: Token, limit=None):
        contract = ERC20Contract(self.web3, self.zksync.contract_address, token.address,
                                 self.zksync.account)
        return contract.approve_deposit(limit)

    async def deposit(self, token: Token, amount: Decimal, address):
        if token.is_eth():
            self.zksync.deposit_eth(address, token.from_decimal(amount))
        else:
            self.zksync.deposit_erc20(token.address, address, token.from_decimal(amount))

    async def full_exit(self, token, account_id):
        return self.zksync.full_exit(token.address, account_id)

    async def set_auth_pubkey_hash(self, pubkey_hash: bytes, nonce: int):
        return self.zksync.set_auth_pub_key_hash(pubkey_hash, nonce)

    async def is_deposit_approved(self, token, threshold=None) -> bool:
        contract = ERC20Contract(self.web3, self.zksync.contract_address, token.address,
                                 self.zksync.account)
        return contract.is_deposit_approved(threshold)

    async def is_onchain_auth_pubkey_hash_set(self, nonce) -> bool:
        facts = self.zksync.auth_facts(self.zksync.account.address, nonce)
        return bool(facts)
