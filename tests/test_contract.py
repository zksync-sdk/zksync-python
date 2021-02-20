from unittest import TestCase

from eth_account import Account
from web3 import HTTPProvider, Web3

from zksync_sdk.network import rinkeby
from zksync_sdk.zksync import ZkSync


class TestZkSyncContract(TestCase):
    private_key = "0x53c833656351c686dc66d2454b48665554212f4fa71db4f07d59c3be87d894dd"

    def setUp(self) -> None:
        self.account = Account.from_key(self.private_key)
        w3 = Web3(HTTPProvider(
            endpoint_uri=rinkeby.zksync_url))
        self.zksync = ZkSync(account=self.account,
                             web3=w3, network=rinkeby)

    def test_deposit_eth(self):
        tx = self.zksync.deposit_eth(self.account.address, 2 * 10 ** 15)
        assert tx['transactionHash']

    def test_deposit_erc20(self):
        tx = self.zksync.deposit_erc20("0xeb8f08a975Ab53E34D8a0330E0D34de942C95926",
                                       self.account.address, 2 * 10 ** 15)
        assert tx['transactionHash']

    def test_full_exit(self):
        pass

    def test_auth_facts(self):
        tx = self.zksync.auth_facts(self.account.address, 2)
        assert tx
