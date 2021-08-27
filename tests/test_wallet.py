from decimal import Decimal
from fractions import Fraction
from unittest import IsolatedAsyncioTestCase
from zksync_sdk.zksync_provider.types import FeeTxType
from zksync_sdk.types.responses import Fee

from web3 import Account, HTTPProvider, Web3

from zksync_sdk import (EthereumProvider, EthereumSignerWeb3, HttpJsonRPCTransport, Wallet, ZkSync,
                        ZkSyncLibrary, ZkSyncProviderV01, ZkSyncSigner, )
from zksync_sdk.zksync_provider.batch_builder import BatchBuilder
from zksync_sdk.network import rinkeby
from zksync_sdk.types import ChangePubKeyEcdsa, Token, TransactionWithSignature,\
                             TransactionWithOptionalSignature, RatioType


class TestWallet(IsolatedAsyncioTestCase):
    # 0x995a8b7f96cb837533b79775b6209696d51f435c
    private_key = "0xa045b52470d306ff78e91b0d2d92f90f7504189125a46b69423dc673fd6b4f3e"
    private_keys = [
        # 0x800455ca06265d0cf742086663a527d7c08049fc
        "0x601b47729b2820e94bc10125edc8d534858827428b449175a275069dc00c303f",
        # 0x3aa03b5bcba43eebcb98432507474ffb3423ac94
        "0xa7adf8459b4c9a62f09e0e5390983c0145fa20e88c9e5bf837d8bf3dcd05bd9c",
    ]
    receiver_address = "0x21dDF51966f2A66D03998B0956fe59da1b3a179F"

    async def get_wallet(self, private_key: str) -> Wallet:
        account = Account.from_key(private_key)
        ethereum_signer = EthereumSignerWeb3(account=account)

        w3 = Web3(HTTPProvider(
            endpoint_uri="https://rinkeby.infura.io/v3/bcf42e619a704151a1b0d95a35cb2e62"))
        provider = ZkSyncProviderV01(provider=HttpJsonRPCTransport(network=rinkeby))
        address = await provider.get_contract_address()
        zksync = ZkSync(account=account, web3=w3, zksync_contract_address=address.main_contract)
        ethereum_provider = EthereumProvider(w3, zksync)
        signer = ZkSyncSigner.from_account(account, self.library, rinkeby.chain_id)

        return Wallet(ethereum_provider=ethereum_provider, zk_signer=signer,
                      eth_signer=ethereum_signer, provider=provider)

    async def asyncSetUp(self):
        self.library = ZkSyncLibrary()
        self.wallet = await self.get_wallet(self.private_key)
        self.wallets = [await self.get_wallet(key) for key in self.private_keys]

    async def test_get_account_state(self):
        data = await self.wallet.zk_provider.get_state(self.wallet.address())
        assert data.address.lower() == self.wallet.address().lower()

    async def test_deposit(self):
        token = await self.wallet.resolve_token("USDT")
        await self.wallet.ethereum_provider.approve_deposit(token, Decimal(1))

        res = await self.wallet.ethereum_provider.deposit(token, Decimal(1),
                                                          self.wallet.address())
        assert res

    async def test_change_pubkey(self):
        res = await self.wallet.set_signing_key("ETH", eth_auth_data=ChangePubKeyEcdsa())
        assert res

    async def test_is_public_key_onset(self):
        pubkey_hash = self.wallet.zk_signer.pubkey_hash()
        nonce = await self.wallet.zk_provider.get_account_nonce(self.wallet.address())
        await self.wallet.ethereum_provider.set_auth_pubkey_hash(pubkey_hash, nonce)
        assert await self.wallet.ethereum_provider.is_onchain_auth_pubkey_hash_set(nonce)

    async def test_transfer(self):
        tr = await self.wallet.transfer("0x21dDF51966f2A66D03998B0956fe59da1b3a179F",
                                        amount=Decimal("0.01"), token="USDC")
        assert tr

    async def test_swap(self):
        order1 = await self.wallets[0].get_order('USDT', 'ETH', Fraction(1500, 1), RatioType.token, Decimal('10.0'))
        order2 = await self.wallets[1].get_order('ETH', 'USDT', Fraction(1, 1200), RatioType.token, Decimal('0.007'))
        tr = await self.wallet.swap((order1, order2), 'ETH')
        assert tr

    async def test_batch(self):
        trs = []
        eth_token = await self.wallet.resolve_token("ETH")
        fee = (await self.wallet.zk_provider.get_transaction_fee(
            FeeTxType.transfer, "0x21dDF51966f2A66D03998B0956fe59da1b3a179F", "ETH"
        )).total_fee
        nonce = await self.wallet.zk_provider.get_account_nonce(self.wallet.address())

        for i in range(1):
            tr, sig = await self.wallet.build_transfer(self.receiver_address,
                                                       amount=1,
                                                       token=eth_token,
                                                       fee=fee,
                                                       nonce=nonce + i)
            trs.append(TransactionWithSignature(tr, sig))
        res = await self.wallet.send_txs_batch(trs)
        assert len(res) == 3

    async def test_build_batch_original(self):
        eth_token = await self.wallet.resolve_token("ETH")
        fee = (await self.wallet.zk_provider.get_transaction_fee(
            FeeTxType.transfer, self.receiver_address, "ETH"
        )).total_fee
        nonce = await self.wallet.zk_provider.get_account_nonce(self.wallet.address())

        msg = []
        trs = []
        # test_fee = fee * 4
        for i in range(2):
            tr, sig = await self.wallet.build_transfer(self.receiver_address,
                                                       amount=1,
                                                       token=eth_token,
                                                       fee=fee
                                                       #, nonce=nonce
                                                       )

            trs.append(tr)
            msg.append(tr.batch_message_part())
        final_msg = ""
        for m in msg:
            final_msg += m
        final_msg += f"Nonce: {nonce}"
        print(f"Final message:\n{final_msg}")
        signature = self.wallet.eth_signer.sign(final_msg.encode())
        trans1 = TransactionWithOptionalSignature(trs[0])
        trans2 = TransactionWithOptionalSignature(trs[1])
        # res = await self.wallet.zk_provider.submit_trx_batch2([trans_to], [sig])
        res = await self.wallet.zk_provider.submit_trx_batch_v2([trans1, trans2], signature)
        print(f"result : {res}")

    async def test_build_batch_transfer(self):
        nonce = await self.wallet.zk_provider.get_account_nonce(self.wallet.address())
        builder = BatchBuilder.from_wallet(self.wallet, nonce)
        # for i in range(3):
        for i in range(1):
            builder.add_transfer(self.receiver_address, "USDC", Decimal(1))
        build_result = await builder.build("USDT")
        trans = await self.wallet.zk_provider.submit_trx_batch3(build_result["transactions"],
                                                                build_result["signature"])
        # trans = await self.wallet.send_txs_batch(build_result["transactions"], [build_result["signature"]])
        print(f"result : {trans}")

    async def test_build_batch_change_pub_key(self):
        nonce = await self.wallet.zk_provider.get_account_nonce(self.wallet.address())
        builder = BatchBuilder.from_wallet(self.wallet, nonce)
        builder.add_change_pub_key("ETH", eth_auth_type=ChangePubKeyEcdsa())
        res = await builder.build("USDC")
        print(f"result : {res}")

    async def test_build_batch_withdraw(self):
        nonce = await self.wallet.zk_provider.get_account_nonce(self.wallet.address())
        builder = BatchBuilder.from_wallet(self.wallet, nonce)
        builder.add_withdraw(self.receiver_address,
                             "ETH",
                             Decimal(1),
                             Decimal("0.1")
                             )
        res = await builder.build("USDC")
        print(f"result : {res}")

    async def test_build_batch_mint_nft(self):
        nonce = await self.wallet.zk_provider.get_account_nonce(self.wallet.address())
        builder = BatchBuilder.from_wallet(self.wallet, nonce)
        builder.add_mint_nft("0x0000000000000000000000000000000000000000000000000000000000000123",
                             self.receiver_address,
                             "USDC"
                             # , Decimal(0.001) - FEE IS TOO LOW
                             )
        res = await builder.build("USDC")
        print(f"result : {res}")

    async def test_build_batch_withdraw_nft(self):
        # await self.wallet.mint_nft("0x0000000000000000000000000000000000000000000000000000000000000123",
        #                            self.receiver_address, "USDC")
        account_state = await self.wallet.get_account_state()
        nfts = account_state.verified.minted_nfts.values()
        if not nfts:
            return
        nfts_iterator = iter(nfts)
        first_value = next(nfts_iterator)

        nonce = await self.wallet.zk_provider.get_account_nonce(self.wallet.address())
        builder = BatchBuilder.from_wallet(self.wallet, nonce)
        builder.add_withdraw_nft(self.receiver_address,
                                 first_value,
                                 "USDC"
                                 # , Decimal("0.01") - FEE IS TOO LOW
                                 )
        res = await builder.build("USDC")
        print(f"result : {res}")

    # async def test_build_batch_swap(self):
    #     nonce = await self.wallet.zk_provider.get_account_nonce(self.wallet.address())
    #     builder = BatchBuilder.from_wallet(self.wallet, nonce)
    #
    #     order1 = await self.wallets[0].get_order('USDT', 'ETH', Fraction(1500, 1), RatioType.token, Decimal('10.0'))
    #     order1.ethSignature = None
    #     order2 = await self.wallets[1].get_order('ETH', 'USDT', Fraction(1, 1200), RatioType.token, Decimal('0.007'))
    #     order2.ethSignature = None
    #     builder.add_swap((order1, order2), "ETH")
    #     build_result = await builder.build("USDC")
    #     # trans = await self.wallet.send_txs_batch(build_result["transactions"], build_result["signature"])
    #     trans = await self.wallet.zk_provider.submit_trx_batch2(build_result["transactions"],
    #                                                             [build_result["signature"]])
    #     print(f"result : {trans}")

    async def test_forced_exit(self):
        tr = await self.wallet.forced_exit(self.receiver_address, "USDC")
        assert tr

    async def test_mint_nft(self):
        tr = await self.wallet.mint_nft("0x0000000000000000000000000000000000000000000000000000000000000123",
                                        self.receiver_address, "USDC")

        assert tr

    async def test_transfer_nft(self):
        account_state = await self.wallet.get_account_state()
        nfts = account_state.committed.nfts.values()
        nfts_iterator = iter(nfts)
        first_value = next(nfts_iterator)

        txs = await self.wallet.transfer_nft(
            "0x995a8b7f96cb837533b79775b6209696d51f435c",
            first_value,
            "USDC"
        )

        assert txs

    async def test_withdraw_nft(self):
        await self.wallet.mint_nft("0x0000000000000000000000000000000000000000000000000000000000000123",
                                   self.receiver_address, "USDC")
        account_state = await self.wallet.get_account_state()
        minted_nfts = account_state.committed.minted_nfts.values()
        minted_nfts_iterator = iter(minted_nfts)
        first_value = next(minted_nfts_iterator)

        tr = await self.wallet.withdraw_nft(self.receiver_address,
                                            first_value, "USDC")

        assert tr

    async def test_withdraw(self):
        tr = await self.wallet.withdraw(self.receiver_address,
                                        Decimal("0.000001"), "USDT")

        assert tr

    async def test_get_tokens(self):
        tokens = await self.wallet.zk_provider.get_tokens()
        assert tokens.find_by_symbol("ETH")

    async def test_is_signing_key_set(self):
        assert await self.wallet.is_signing_key_set()


class TestEthereumProvider(IsolatedAsyncioTestCase):
    private_key = "0xa045b52470d306ff78e91b0d2d92f90f7504189125a46b69423dc673fd6b4f3e"

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
            address=Web3.toChecksumAddress('0xeb8f08a975ab53e34d8a0330e0d34de942c95926'),
            id=20, symbol='USDC',
            decimals=18)
        assert await self.ethereum_provider.approve_deposit(token, Decimal(1))

    async def test_full_exit(self):
        token = Token(
            address=Web3.toChecksumAddress('0xD2084eA2AE4bBE1424E4fe3CDE25B713632fb988'),
            id=20, symbol='BAT',
            decimals=18)
        assert await self.ethereum_provider.full_exit(token, 6713)

    async def test_is_deposit_approved(self):
        token = Token(
            address=Web3.toChecksumAddress('0xD2084eA2AE4bBE1424E4fe3CDE25B713632fb988'),
            id=20, symbol='BAT',
            decimals=18)
        assert await self.ethereum_provider.is_deposit_approved(token, 1)


class TestZkSyncProvider(IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.provider = ZkSyncProviderV01(provider=HttpJsonRPCTransport(network=rinkeby))

    async def test_get_token_price(self):
        tokens = await self.provider.get_tokens()
        price = await self.provider.get_token_price(tokens.find_by_symbol("USDC"))
        self.assertAlmostEqual(float(price), 1.0, delta=0.2)
