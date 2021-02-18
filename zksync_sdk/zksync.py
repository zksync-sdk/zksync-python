from eth_account.signers.base import BaseAccount
from web3 import Web3

from zksync_sdk.contract_utils import zk_sync_abi
from zksync_sdk.network import Network


class ZkSync:
    def __init__(self, web3: Web3, network: Network, account: BaseAccount):
        self.web3 = web3
        self.contract_address = network.zksync_contract_address
        self.account = account

        self.contract = self.web3.eth.contract(self.contract_address, abi=zk_sync_abi())

    def deposit_eth(self, address: str, amount: int):
        return self._call_method("depositETH", address, amount=amount)

    def deposit_erc20(self, token_address: str, address: str, amount: int):
        return self._call_method("depositERC20", token_address, amount, address)

    def full_exit(self, token_address: str, account_id: int):
        return self._call_method("fullExit", account_id, token_address)

    def set_auth_pub_key_hash(self, pub_key_hash: bytes, nonce: int):
        return self._call_method("setAuthPubkeyHash", pub_key_hash, nonce)

    def auth_facts(self, sender_address: str, nonce: int):
        return self.contract.caller.authFacts(sender_address, nonce)

    def _call_method(self, method_name, *args, amount=None, **kwargs):
        params = {}
        if amount is not None:
            params['value'] = amount
        params['from'] = self.account.address
        transaction = getattr(self.contract.functions, method_name)(
            *args,
            **kwargs
        ).buildTransaction()

        transaction.update({'nonce': self.web3.eth.getTransactionCount(self.account.address)})
        transaction.update(params)
        signed_tx = self.account.sign_transaction(transaction)
        txn_hash = self.web3.eth.sendRawTransaction(signed_tx.rawTransaction)
        txn_receipt = self.web3.eth.waitForTransactionReceipt(txn_hash)
        return txn_receipt
