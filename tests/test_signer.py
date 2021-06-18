from unittest import TestCase

from web3 import Account

from zksync_sdk import ZkSyncLibrary
from zksync_sdk.serializers import closest_packable_amount, closest_packable_transaction_fee
from zksync_sdk.types import ChainId, ForcedExit, Token, Transfer, Withdraw, MintNFT, WithdrawNFT
from zksync_sdk.zksync_signer import ZkSyncSigner

PRIVATE_KEY = "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"


class ZkSyncSignerTest(TestCase):
    def setUp(self):
        self.library = ZkSyncLibrary()

    def test_derive_pub_key(self):
        account = Account.from_key(PRIVATE_KEY)
        signer = ZkSyncSigner.from_account(account, self.library, ChainId.MAINNET)
        assert signer.public_key.hex() == "40771354dc314593e071eaf4d0f42ccb1fad6c7006c57464feeb7ab5872b7490"

    def test_transfer_bytes(self):
        tr = Transfer(from_address="0xedE35562d3555e61120a151B3c8e8e91d83a378a",
                      to_address="0x19aa2ed8712072e918632259780e587698ef58df",
                      token=Token.eth(),
                      amount=1000000000000, fee=1000000, nonce=12, valid_from=0,
                      valid_until=4294967295, account_id=44)
        res = "fa010000002cede35562d3555e61120a151b3c8e8e91d83a378a19aa2ed8712072e918632259780e587698ef58df000000004a817c80027d030000000c000000000000000000000000ffffffff"
        assert tr.encoded_message().hex() == res

    def test_withdraw_bytes(self):
        tr = Withdraw(from_address="0xedE35562d3555e61120a151B3c8e8e91d83a378a",
                      to_address="0x19aa2ed8712072e918632259780e587698ef58df",
                      token=Token.eth(),
                      amount=1000000000000, fee=1000000, nonce=12, valid_from=0,
                      valid_until=4294967295, account_id=44)

        res = "fc010000002cede35562d3555e61120a151b3c8e8e91d83a378a19aa2ed8712072e918632259780e587698ef58df000000000000000000000000000000e8d4a510007d030000000c000000000000000000000000ffffffff"
        assert tr.encoded_message().hex() == res

    def test_forced_exit_bytes(self):
        tr = ForcedExit(
            target="0x19aa2ed8712072e918632259780e587698ef58df",
            token=Token.eth(),
            fee=1000000, nonce=12, valid_from=0,
            valid_until=4294967295, initiator_account_id=44
        )
        res = "f7010000002c19aa2ed8712072e918632259780e587698ef58df000000007d030000000c000000000000000000000000ffffffff"
        assert tr.encoded_message().hex() == res

    def test_mint_nft_bytes(self):
        tr = MintNFT(
            creator_id=44,
            creator_address="0xedE35562d3555e61120a151B3c8e8e91d83a378a",
            content_hash="0x0000000000000000000000000000000000000000000000000000000000000123",
            recipient="0x19aa2ed8712072e918632259780e587698ef58df",
            fee=1000000,
            fee_token=Token.eth(),
            nonce=12
        )
        res = "f6010000002cede35562d3555e61120a151b3c8e8e91d83a378a000000000000000000000000000000000000000000000000000000000000012319aa2ed8712072e918632259780e587698ef58df000000007d030000000c"
        assert tr.encoded_message().hex() == res

    def test_withdraw_nft_bytes(self):
        tr = WithdrawNFT(
            account_id=44,
            from_address="0xedE35562d3555e61120a151B3c8e8e91d83a378a",
            to_address="0x19aa2ed8712072e918632259780e587698ef58df",
            fee_token=Token.eth(),
            fee=1000000,
            nonce=12,
            valid_from=0,
            valid_until=4294967295,
            token_id=100000
        )
        res = "f5010000002cede35562d3555e61120a151b3c8e8e91d83a378a19aa2ed8712072e918632259780e587698ef58df000186a0000000007d030000000c000000000000000000000000ffffffff"
        assert tr.encoded_message().hex() == res

    def test_pack(self):
        amounts = [0, 1, 2047, 2047000, 1000000000000000000000000000000000]
        for amount in amounts:
            assert closest_packable_transaction_fee(amount) == amount
            assert closest_packable_amount(amount) == amount

    def test_signature(self):
        account = Account.from_key(PRIVATE_KEY)
        signer = ZkSyncSigner.from_account(account, self.library, ChainId.MAINNET)
        tr = Transfer(from_address="0xedE35562d3555e61120a151B3c8e8e91d83a378a",
                      to_address="0x19aa2ed8712072e918632259780e587698ef58df",
                      token=Token.eth(),
                      amount=1000000000000,
                      fee=1000000,
                      nonce=12,
                      valid_from=0,
                      valid_until=4294967295, account_id=44)
        res = signer.sign_tx(tr)
        assert res.signature == 'b3211c7e15d31d64619e0c7f65fce8c6e45637b5cfc8711478c5a151e6568d875ec7f48e040225fe3cc7f1e7294625cad6d98b4595d007d36ef62122de16ae01'


def check_bytes(a, b):
    res = True
    for i, c in enumerate(a):
        if c != b[i]:
            print(f"Wrong char {i}, {c}, {b[i]}")
            res = False
    assert res
