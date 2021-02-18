from web3 import Web3

from zksync_sdk.zksync import ZkSync


class EthereumProvider:
    def __init__(self, web3: Web3, zksync: ZkSync):
        self.web3 = web3
        self.zksync = zksync

    async def approve_deposit(self, token: str, limit=None):
        pass

    async def transfer(self, token, amount, to):
        pass

    async def transfer_eth(self, amount, to):
        pass

    async def transfer_erc20(self, token, amount, to):
        pass

    async def deposit(self, token, amount, address):
        pass

    async def full_exit(self, token, account_id):
        pass

    async def set_auth_pubkey_hash(self, pubkey_hash, nonce):
        pass

    async def is_deposit_approved(self, token, threshold=None):
        pass

    async def get_balance(self):
        pass

    async def get_nonce(self):
        pass

    async def is_onchain_auth_pubkey_hash_set(self, nonce):
        pass
