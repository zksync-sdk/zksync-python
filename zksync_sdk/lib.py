import ctypes
from ctypes import (Structure, c_ubyte, cdll)
import os
from typing import Optional

PRIVATE_KEY_LEN = 32
PUBLIC_KEY_LEN = 32
PUBKEY_HASH_LEN = 20
PACKED_SIGNATURE_LEN = 64
ORDER_LEN = 89
ORDERS_HASH_LEN = 31


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


class ZksOrdersHash(Structure):
    _fields_ = [
        ("data", c_ubyte * ORDERS_HASH_LEN),
    ]


class ZksOrders(Structure):
    _fields_ = [
        ("data", c_ubyte * (ORDER_LEN * 2)),
    ]


class ZkSyncLibrary:

    def __init__(self, library_path: Optional[str] = None):
        if library_path is None:
            library_path = os.environ["ZK_SYNC_LIBRARY_PATH"]
        self.lib = cdll.LoadLibrary(library_path)

    def private_key_from_seed(self, seed: bytes):
        private_key = ctypes.pointer(ZksPrivateKey())
        self.lib.zks_crypto_private_key_from_seed(seed, len(seed), private_key)
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
        public_key_ptr = ctypes.pointer(
            ZksPackedPublicKey(data=(c_ubyte * PUBLIC_KEY_LEN)(*public_key)))
        self.lib.zks_crypto_public_key_to_pubkey_hash(public_key_ptr, public_key_hash)
        return bytes(public_key_hash.contents.data)

    def sign(self, private_key: bytes, message: bytes):
        assert len(private_key) == PRIVATE_KEY_LEN
        signature = ctypes.pointer(ZksSignature())
        private_key_ptr = ctypes.pointer(
            ZksPrivateKey(data=(c_ubyte * PRIVATE_KEY_LEN)(*private_key)))
        self.lib.zks_crypto_sign_musig(private_key_ptr, message, len(message), signature)
        return bytes(signature.contents.data)

    def hash_orders(self, orders: bytes):
        assert len(orders) == ORDER_LEN * 2
        orders_hash = ctypes.pointer(ZksOrdersHash())
        orders_bytes = ctypes.pointer(
            ZksOrders(data=(c_ubyte * (ORDER_LEN * 2))(*orders)))
        self.lib.rescue_hash_orders(orders_bytes, len(orders), orders_hash)
        return bytes(orders_hash.contents.data)

    def is_valid_signature(self, message: bytes, public_key: bytes, zk_sync_signature: bytes) -> bool:
        assert len(public_key) == PUBLIC_KEY_LEN
        assert len(zk_sync_signature) == PACKED_SIGNATURE_LEN
        public_key_ptr = ctypes.pointer(
            ZksPackedPublicKey(data=(c_ubyte * PUBLIC_KEY_LEN)(*public_key)))
        signature_ptr = ctypes.pointer(
            ZksSignature(data=(c_ubyte * PACKED_SIGNATURE_LEN)(*zk_sync_signature)))
        ret = self.lib.zks_crypto_verify_musig(message, len(message), public_key_ptr, signature_ptr)
        return ret == 0
