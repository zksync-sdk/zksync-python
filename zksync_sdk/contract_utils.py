import json

try:
    import importlib.resources as pkg_resources
except ImportError:
    # Try backported to PY<37 `importlib_resources`.
    import importlib_resources as pkg_resources
from . import contract_abi

abi = None


def zk_sync_abi():
    global abi

    if abi is None:
        abi_text = pkg_resources.read_text(contract_abi, 'ZkSync.json')
        abi = json.loads(abi_text)['abi']

    return abi
