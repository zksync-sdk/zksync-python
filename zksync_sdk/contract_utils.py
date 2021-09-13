import importlib.resources as pkg_resources
import json

from . import contract_abi

zksync_abi_cache = None
ierc20_abi_cache = None

__all__ = ['zksync_abi', 'erc20_abi']


def zksync_abi():
    global zksync_abi_cache

    if zksync_abi_cache is None:
        abi_text = pkg_resources.read_text(contract_abi, 'ZkSync.json')
        zksync_abi_cache = json.loads(abi_text)['abi']

    return zksync_abi_cache


def erc20_abi():
    global ierc20_abi_cache

    if ierc20_abi_cache is None:
        abi_text = pkg_resources.read_text(contract_abi, 'IERC20.json')
        ierc20_abi_cache = json.loads(abi_text)['abi']

    return ierc20_abi_cache
