import os
from unittest import TestCase

from eth_account import Account

from zksync_sdk import ZkSyncLibrary
from zksync_sdk.serialize_utils import (closest_packable_amount, closest_packable_transaction_fee,
                                        )
from zksync_sdk.signer import ZkSyncSigner
from zksync_sdk.types import ChainId, ForcedExit, Token, Transfer, Withdraw

PRIVATE_KEY = "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"


class ZkSyncSignerTest(TestCase):
    def setUp(self):
        _DIRNAME = os.path.dirname(__file__)

        path = os.path.join(_DIRNAME, '../zks-crypto-macos-x64.dylib')

        self.library = ZkSyncLibrary(path)

    def test_derive_pub_key(self):
        account = Account.from_key(PRIVATE_KEY)
        signer = ZkSyncSigner(account, self.library, ChainId.MAINNET)
        assert signer.public_key.hex() == "17f3708f5e2b2c39c640def0cf0010fd9dd9219650e389114ea9da47f5874184"

    def test_transfer_bytes(self):
        tr = Transfer(from_address="0xedE35562d3555e61120a151B3c8e8e91d83a378a",
                      to_address="0x19aa2ed8712072e918632259780e587698ef58df",
                      token=Token.eth(),
                      amount=1000000000000, fee=1000000, nonce=12, valid_from=0,
                      valid_until=4294967295, account_id=44)
        res = "050000002cede35562d3555e61120a151b3c8e8e91d83a378a19aa2ed8712072e918632259780e587698ef58df00004a817c80027d030000000c000000000000000000000000ffffffff"
        assert tr.encoded_message().hex() == res

    def test_withdraw_bytes(self):
        tr = Withdraw(from_address=bytes.fromhex("edE35562d3555e61120a151B3c8e8e91d83a378a"),
                      eth_address=bytes.fromhex("19aa2ed8712072e918632259780e587698ef58df"),
                      token_id=0,
                      amount=1000000000000, fee=1000000, nonce=12, valid_from=0,
                      valid_until=4294967295, account_id=44)

        res = "030000002cede35562d3555e61120a151b3c8e8e91d83a378a19aa2ed8712072e918632259780e587698ef58df00000000000000000000000000e8d4a510007d030000000c000000000000000000000000ffffffff"
        assert tr.encoded_message().hex() == res

    def test_forced_exit_bytes(self):
        tr = ForcedExit(
            target=bytes.fromhex("19aa2ed8712072e918632259780e587698ef58df"),
            token_id=0,
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
        signer = ZkSyncSigner(account, self.library, ChainId.MAINNET)
        tr = Transfer(from_address="0xedE35562d3555e61120a151B3c8e8e91d83a378a",
                      to_address="0x19aa2ed8712072e918632259780e587698ef58df",
                      token=Token.eth(),
                      amount=1000000000000 * 10 ** 18, fee=1000000 * 10 ** 18, nonce=12,
                      valid_from=0,
                      valid_until=4294967295, account_id=44)
        print(f"res {tr.human_readable_message().encode().hex()}")
        res = signer.sign_tx(tr)
        print(res.signature.encode().hex())


def check_bytes(a, b):
    res = True
    for i, c in enumerate(a):
        if c != b[i]:
            print(f"Wrong char {i}, {c}, {b[i]}")
            res = False
    assert res
