from eth_account.signers.base import BaseAccount
from web3 import Web3

from zksync_sdk.contract_utils import erc20_abi, zksync_abi

MAX_ERC20_APPROVE_AMOUNT = 115792089237316195423570985008687907853269984665640564039457584007913129639935  # 2^256 - 1
ERC20_APPROVE_THRESHOLD = 57896044618658097711785492504343953926634992332820282019728792003956564819968  # 2^255


class Contract:
    def __init__(self, contract_address: str, web3: Web3, account: BaseAccount, abi):
        self.contract_address = contract_address
        self.web3 = web3
        self.contract = self.web3.eth.contract(self.contract_address, abi=abi)  # type: ignore[call-overload]
        self.account = account

    def _call_method(self, method_name, *args, amount=None, **kwargs):
        params = {}
        if amount is not None:
            params['value'] = amount
        params['from'] = self.account.address
        transaction = getattr(self.contract.functions, method_name)(
            *args,
            **kwargs
        ).build_transaction(params)

        transaction.update({'nonce': self.web3.eth.get_transaction_count(self.account.address)})
        signed_tx = self.account.sign_transaction(transaction)
        txn_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
        txn_receipt = self.web3.eth.wait_for_transaction_receipt(txn_hash)
        return txn_receipt


class ZkSync(Contract):
    def __init__(self, web3: Web3, zksync_contract_address: str, account: BaseAccount):
        super().__init__(zksync_contract_address, web3, account, zksync_abi())

    def deposit_eth(self, address: str, amount: int):
        return self._call_method("depositETH", address, amount=amount)

    def deposit_erc20(self, token_address: str, address: str, amount: int):
        return self._call_method("depositERC20", token_address, amount, address)

    def full_exit(self, account_id: int, token_address: str, ):
        return self._call_method("requestFullExit", account_id, token_address)

    def full_exit_nft(self, account_id: int, token_id: int):
        return self._call_method("requestFullExitNFT", account_id, token_id)

    def set_auth_pub_key_hash(self, pub_key_hash: bytes, nonce: int):
        return self._call_method("setAuthPubkeyHash", pub_key_hash, nonce)

    def auth_facts(self, sender_address: str, nonce: int) -> bytes:
        return self.contract.caller.authFacts(sender_address, nonce)


class ERC20Contract(Contract):
    def __init__(self, web3: Web3, zksync_address: str, contract_address: str,
                 account: BaseAccount):
        self.zksync_address = zksync_address
        super().__init__(contract_address, web3, account, erc20_abi())

    def approve_deposit(self, max_erc20_approve_amount=MAX_ERC20_APPROVE_AMOUNT):
        return self._call_method('approve', self.zksync_address, max_erc20_approve_amount)

    def is_deposit_approved(self, erc20_approve_threshold=ERC20_APPROVE_THRESHOLD):
        allowance = self.contract.functions.allowance(self.account.address,
                                                      self.zksync_address).call()

        return allowance >= erc20_approve_threshold
