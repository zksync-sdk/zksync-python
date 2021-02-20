import json

try:
    import importlib.resources as pkg_resources
except ImportError:
    # Try backported to PY<37 `importlib_resources`.
    import importlib_resources as pkg_resources
from . import contract_abi

zksync_abi = None
ierc20_abi = None


def zk_sync_abi():
    global zksync_abi

    if zksync_abi is None:
        abi_text = pkg_resources.read_text(contract_abi, 'ZkSync.json')
        zksync_abi = json.loads(abi_text)['abi']

    return zksync_abi


def erc20_abi():
    global ierc20_abi

    if ierc20_abi is None:
        abi_text = pkg_resources.read_text(contract_abi, 'IERC20.json')
        ierc20_abi = json.loads(abi_text)['abi']

    return ierc20_abi
