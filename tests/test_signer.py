from unittest import TestCase

from eth_account import Account

from zksync_sdk import ZkSyncLibrary
from zksync_sdk.serializers import (closest_packable_amount, closest_packable_transaction_fee,
                                    )
from zksync_sdk.types import ChainId, ForcedExit, Token, Transfer, Withdraw
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
        res = "050000002cede35562d3555e61120a151b3c8e8e91d83a378a19aa2ed8712072e918632259780e587698ef58df00004a817c80027d030000000c000000000000000000000000ffffffff"
        assert tr.encoded_message().hex() == res

    def test_withdraw_bytes(self):
        tr = Withdraw(from_address="0xedE35562d3555e61120a151B3c8e8e91d83a378a",
                      to_address="0x19aa2ed8712072e918632259780e587698ef58df",
                      token=Token.eth(),
                      amount=1000000000000, fee=1000000, nonce=12, valid_from=0,
                      valid_until=4294967295, account_id=44)

        res = "030000002cede35562d3555e61120a151b3c8e8e91d83a378a19aa2ed8712072e918632259780e587698ef58df00000000000000000000000000e8d4a510007d030000000c000000000000000000000000ffffffff"
        assert tr.encoded_message().hex() == res

    def test_forced_exit_bytes(self):
        tr = ForcedExit(
            target="0x19aa2ed8712072e918632259780e587698ef58df",
            token=Token.eth(),
            fee=1000000, nonce=12, valid_from=0,
            valid_until=4294967295, initiator_account_id=44
        )
        res = "080000002c19aa2ed8712072e918632259780e587698ef58df00007d030000000c000000000000000000000000ffffffff"
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
        assert res.signature == '849281ea1b3a97b3fe30fbd25184db3e7860db96e3be9d53cf643bd5cf7805a30dbf685c1e63fd75968a61bd83d3a1fb3a0b1c68c71fe87d96f1c1cb7de45b05'


def check_bytes(a, b):
    res = True
    for i, c in enumerate(a):
        if c != b[i]:
            print(f"Wrong char {i}, {c}, {b[i]}")
            res = False
    assert res
