import ctypes
from ctypes import (Structure, c_ubyte, cdll)

PRIVATE_KEY_LEN = 32
PUBLIC_KEY_LEN = 32
PUBKEY_HASH_LEN = 20
PACKED_SIGNATURE_LEN = 64


class ZksPrivateKey(Structure):
    _fields_ = [
        ("data", c_ubyte * PRIVATE_KEY_LEN),
    ]


class ZksPackedPublicKey(Structure):
    _fields_ = [
        ("data", c_ubyte * PUBLIC_KEY_LEN),
    ]


class ZksPubkeyHash(Structure):
    _fields_ = [
        ("data", c_ubyte * PUBKEY_HASH_LEN),
    ]


class ZksSignature(Structure):
    _fields_ = [
        ("data", c_ubyte * PACKED_SIGNATURE_LEN),
    ]


class ZkSyncLibrary:

    def __init__(self, library_path: str):
        self.lib = cdll.LoadLibrary(library_path)

    def private_key_from_seed(self, seed: bytes):
        assert len(seed) == 32
        private_key = ctypes.pointer(ZksPrivateKey())
        self.lib.zks_crypto_private_key_from_seed(seed, 32, private_key)
        return bytes(private_key.contents.data)

    def get_public_key(self, private_key: bytes):
        assert len(private_key) == PRIVATE_KEY_LEN

        public_key = ctypes.pointer(ZksPackedPublicKey())
        pk = ctypes.pointer(ZksPrivateKey(data=(c_ubyte * PRIVATE_KEY_LEN)(*private_key)))
        self.lib.zks_crypto_private_key_to_public_key(pk, public_key)
        return bytes(public_key.contents.data)

    def get_pubkey_hash(self, public_key: bytes):
        assert len(public_key) == PUBLIC_KEY_LEN
        public_key_hash = ctypes.pointer(ZksPubkeyHash())
        public_key = ctypes.pointer(
            ZksPackedPublicKey(data=(c_ubyte * PUBLIC_KEY_LEN)(*public_key)))
        self.lib.zks_crypto_public_key_to_pubkey_hash(public_key, public_key_hash)
        return bytes(public_key_hash.contents.data)

    def sign(self, private_key: bytes, message: bytes):
        assert len(private_key) == PRIVATE_KEY_LEN
        signature = ctypes.pointer(ZksSignature())
        private_key = ctypes.pointer(
            ZksPrivateKey(data=(c_ubyte * PRIVATE_KEY_LEN)(*private_key)))
        self.lib.zks_crypto_sign_musig(private_key, message, len(message), signature)
        return bytes(signature.contents.data)
