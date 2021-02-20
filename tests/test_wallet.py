from decimal import Decimal
import os
from unittest import IsolatedAsyncioTestCase

from eth_account import Account
from web3 import HTTPProvider, Web3

from zksync_sdk import ZkSyncLibrary
from zksync_sdk.ethereum_provider import EthereumProvider
from zksync_sdk.network import rinkeby
from zksync_sdk.providers.http import HttpJsonRPCProvider
from zksync_sdk.signer import EthereumSigner, ZkSyncSigner
from zksync_sdk.types import Token
from zksync_sdk.wallet import Wallet
from zksync_sdk.zksync import ZkSync
from zksync_sdk.zksync_provider import ZkSyncProvider


class TestWallet(IsolatedAsyncioTestCase):
    private_key = "0x53c833656351c686dc66d2454b48665554212f4fa71db4f07d59c3be87d894dd"

    def setUp(self) -> None:
        self.account = Account.from_key(self.private_key)
        _DIRNAME = os.path.dirname(__file__)

        path = os.path.join(_DIRNAME, '../zks-crypto-macos-x64.dylib')

        self.library = ZkSyncLibrary(path)

        w3 = Web3(HTTPProvider(
            endpoint_uri="https://rinkeby.infura.io/v3/bcf42e619a704151a1b0d95a35cb2e62"))
        self.zksync = ZkSync(account=self.account,
                             network=rinkeby,
                             web3=w3)

        ethereum_provider = EthereumProvider(w3, self.zksync)
        signer = ZkSyncSigner(self.account, self.library, rinkeby.chain_id)

        provider = ZkSyncProvider(provider=HttpJsonRPCProvider(network=rinkeby))

        ethereum_signer = EthereumSigner(account=self.account)
        self.wallet = Wallet(ethereum_provider=ethereum_provider, zk_signer=signer,
                             eth_signer=ethereum_signer, provider=provider)

    async def test_get_account_state(self):
        data = await self.wallet.zk_provider.get_state(self.account.address)
        assert data.address.lower() == self.account.address.lower()

    async def test_deposit(self):
        await self.wallet.ethereum_provider.deposit(Token.eth(), Decimal(0.001),
                                                    self.account.address)

    async def test_is_public_key_onset(self):
        account, nonce = await self.wallet.zk_provider.get_account_nonce(self.account.address)
        assert await self.wallet.ethereum_provider.is_onchain_auth_pubkey_hash_set(nonce)

    async def test_transfer(self):
        tr = await self.wallet.transfer("0x21dDF51966f2A66D03998B0956fe59da1b3a179F",
                                        amount=Decimal("0.0001"), token="ETH",
                                        fast_processing=False)
        assert tr

    async def test_forced_exit(self):
        tr = await self.wallet.forced_exit("0x21dDF51966f2A66D03998B0956fe59da1b3a179F", "USDC")

        assert tr

    async def test_withdraw(self):
        tr = await self.wallet.withdraw("0x21dDF51966f2A66D03998B0956fe59da1b3a179F",
                                        Decimal("0.001"), "USDT")

        assert tr

    async def test_get_tokes(self):
        tokens = await self.wallet.zk_provider.get_tokens()
        assert tokens.find_by_symbol("ETH")


class TestEthereumProvider(IsolatedAsyncioTestCase):
    private_key = "0x53c833656351c686dc66d2454b48665554212f4fa71db4f07d59c3be87d894dd"

    def setUp(self) -> None:
        self.account = Account.from_key(self.private_key)
        _DIRNAME = os.path.dirname(__file__)

        path = os.path.join(_DIRNAME, '../zks-crypto-macos-x64.dylib')

        self.library = ZkSyncLibrary(path)

        w3 = Web3(HTTPProvider(
            endpoint_uri="https://rinkeby.infura.io/v3/bcf42e619a704151a1b0d95a35cb2e62"))
        self.zksync = ZkSync(account=self.account,
                             network=rinkeby,
                             web3=w3)
        self.ethereum_provider = EthereumProvider(w3, self.zksync)

    async def test_approve_deposit(self):
        token = Token(address=Web3.toChecksumAddress('0xfe1b6abc39e46cec54d275efb4b29b33be176c2a'),
                      id=20, symbol='PHNX',
                      decimals=18)
        data = await self.ethereum_provider.approve_deposit(token, 10)
        print(data)

    async def test_full_exit(self):
        token = Token(address=Web3.toChecksumAddress('0xfe1b6abc39e46cec54d275efb4b29b33be176c2a'),
                      id=20, symbol='PHNX',
                      decimals=18)
        data = await self.ethereum_provider.full_exit(token, 6713)
        print(data)
