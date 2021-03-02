import os
from unittest import TestCase

from zksync_sdk import ZkSyncLibrary


class TestZkSyncLibrary(TestCase):
    def setUp(self):
        self.library = ZkSyncLibrary()

    def test_public_key_hash_from_seed(self):
        seed = b"1" * 32
        key = self.library.private_key_from_seed(seed)
        assert key != seed
        pub_key = self.library.get_public_key(key)
        assert pub_key != key
        pub_key_hash = self.library.get_pubkey_hash(pub_key)
        assert pub_key != pub_key_hash

    def test_sign(self):
        seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        message = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
        key = self.library.private_key_from_seed(seed)
        signature = self.library.sign(key, message)
        pub_key = self.library.get_public_key(key)

        assert key.hex() == "0552a69519d1f3043611126c13489ff4a2a867a1c667b1d9d9031cd27fdcff5a"
        assert signature.hex() == "5462c3083d92b832d540c9068eed0a0450520f6dd2e4ab169de1a46585b394a4292896a2ebca3c0378378963a6bc1710b64c573598e73de3a33d6cec2f5d7403"
        assert pub_key.hex() == "17f3708f5e2b2c39c640def0cf0010fd9dd9219650e389114ea9da47f5874184"
        assert signature != message
