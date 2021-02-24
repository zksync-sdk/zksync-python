from decimal import Decimal
from unittest import IsolatedAsyncioTestCase

from eth_account import Account
from web3 import HTTPProvider, Web3

from zksync_sdk import ZkSyncLibrary
from zksync_sdk.ethereum_provider import EthereumProvider
from zksync_sdk.ethereum_signer import EthereumSignerWeb3
from zksync_sdk.network import rinkeby
from zksync_sdk.transport.http import HttpJsonRPCTransport
from zksync_sdk.types import ChangePubKeyTypes, Token
from zksync_sdk.wallet import Wallet
from zksync_sdk.zksync import ZkSync
from zksync_sdk.zksync_provider import ZkSyncProviderV01
from zksync_sdk.zksync_signer import ZkSyncSigner


class TestWallet(IsolatedAsyncioTestCase):
    private_key = "0xcfcf55abae35cfd18caeb3975688d3dcb4834dac21d9c03ca0b670a00028df4c"

    async def asyncSetUp(self) -> None:
        self.account = Account.from_key(self.private_key)
        self.library = ZkSyncLibrary()

        w3 = Web3(
            HTTPProvider(
                endpoint_uri="https://rinkeby.infura.io/v3/bcf42e619a704151a1b0d95a35cb2e62"
            )
        )
        provider = ZkSyncProviderV01(provider=HttpJsonRPCTransport(network=rinkeby))
        address = await provider.get_contract_address()
        self.zksync = ZkSync(account=self.account, web3=w3,
                             zksync_contract_address=address.main_contract)

        ethereum_provider = EthereumProvider(w3, self.zksync)
        signer = ZkSyncSigner.from_account(self.account, self.library, rinkeby.chain_id)

        ethereum_signer = EthereumSignerWeb3(account=self.account)
        self.wallet = Wallet(ethereum_provider=ethereum_provider, zk_signer=signer,
                             eth_signer=ethereum_signer, provider=provider)

    async def test_get_account_state(self):
        data = await self.wallet.zk_provider.get_state(self.account.address)
        assert data.address.lower() == self.account.address.lower()

    async def test_deposit(self):
        token = await self.wallet.resolve_token("USDT")
        await self.wallet.ethereum_provider.approve_deposit(token, Decimal(10))

        assert await self.wallet.ethereum_provider.deposit(token, Decimal(10),
                                                           self.account.address)

    async def test_change_pubkey(self):
        res = await self.wallet.set_signing_key("ETH", ChangePubKeyTypes.ecdsa)
        assert res

    async def test_is_public_key_onset(self):
        pubkey_hash = self.wallet.zk_signer.pubkey_hash()
        account, nonce = await self.wallet.zk_provider.get_account_nonce(self.account.address)
        await self.wallet.ethereum_provider.set_auth_pubkey_hash(pubkey_hash, nonce)
        assert await self.wallet.ethereum_provider.is_onchain_auth_pubkey_hash_set(nonce)

    async def test_transfer(self):
        tr = await self.wallet.transfer("0x21dDF51966f2A66D03998B0956fe59da1b3a179F",
                                        amount=Decimal("0.0001"), token="ETH")
        assert tr

    async def test_forced_exit(self):
        tr = await self.wallet.forced_exit("0x21dDF51966f2A66D03998B0956fe59da1b3a179F",
                                           "USDC")

        assert tr

    async def test_withdraw(self):
        tr = await self.wallet.withdraw("0x21dDF51966f2A66D03998B0956fe59da1b3a179F",
                                        Decimal("0.001"), "USDT")

        assert tr

    async def test_get_tokes(self):
        tokens = await self.wallet.zk_provider.get_tokens()
        assert tokens.find_by_symbol("ETH")

    async def test_is_signing_key_set(self):
        assert await self.wallet.is_signing_key_set()

    class TestEthereumProvider(IsolatedAsyncioTestCase):
        private_key = "0x53c833656351c686dc66d2454b48665554212f4fa71db4f07d59c3be87d894dd"

        async def asyncSetUp(self) -> None:
            self.account = Account.from_key(self.private_key)
            self.library = ZkSyncLibrary()

            w3 = Web3(HTTPProvider(
                endpoint_uri="https://rinkeby.infura.io/v3/bcf42e619a704151a1b0d95a35cb2e62"))
            provider = ZkSyncProviderV01(provider=HttpJsonRPCTransport(network=rinkeby))
            address = await provider.get_contract_address()
            self.zksync = ZkSync(account=self.account, web3=w3,
                                 zksync_contract_address=address.main_contract)
            self.ethereum_provider = EthereumProvider(w3, self.zksync)

        async def test_approve_deposit(self):
            token = Token(
                address=Web3.toChecksumAddress('0xfe1b6abc39e46cec54d275efb4b29b33be176c2a'),
                id=20, symbol='PHNX',
                decimals=18)
            assert await self.ethereum_provider.approve_deposit(token, Decimal(10))

        async def test_full_exit(self):
            token = Token(
                address=Web3.toChecksumAddress('0xfe1b6abc39e46cec54d275efb4b29b33be176c2a'),
                id=20, symbol='PHNX',
                decimals=18)
            assert await self.ethereum_provider.full_exit(token, 6713)

        async def test_is_deposit_approved(self):
            token = Token(
                address=Web3.toChecksumAddress('0xfe1b6abc39e46cec54d275efb4b29b33be176c2a'),
                id=20, symbol='PHNX',
                decimals=18)
            assert await self.ethereum_provider.is_deposit_approved(token, 10)

    class TestZkSyncProvider(IsolatedAsyncioTestCase):
        def setUp(self) -> None:
            self.provider = ZkSyncProviderV01(provider=HttpJsonRPCTransport(network=rinkeby))

        async def test_get_token_price(self):
            tokens = await self.provider.get_tokens()
            price = await self.provider.get_token_price(tokens.find_by_symbol("USDC"))
            self.assertAlmostEqual(float(price), 1.0, delta=0.2)
