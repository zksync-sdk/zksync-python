import os
from unittest import TestCase

from zksync import ZkSyncLibrary


class TestZkSyncLibrary(TestCase):
    def setUp(self):
        _DIRNAME = os.path.dirname(__file__)

        path = os.path.join(_DIRNAME, '../zks-crypto-macos-x64.dylib')

        self.library = ZkSyncLibrary(path)

    def test_public_key_hash_from_seed(self):
        seed = b"1" * 32
        key = self.library.private_key_from_seed(seed)
        assert key != seed
        pub_key = self.library.get_public_key(key)
        assert pub_key != key
        pub_key_hash = self.library.get_pubkey_hash(pub_key)
        assert pub_key != pub_key_hash

    def test_sign(self):
        seed = b"2" * 32
        message = b"message"
        key = self.library.private_key_from_seed(seed)
        signature = self.library.sign(key, b"message")
        assert signature != key
        assert signature != message
