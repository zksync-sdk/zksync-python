from concurrent.futures import Future, ThreadPoolExecutor
from enum import Enum, auto
from zksync_sdk.types import TransactionDetails
import time
import asyncio


class TransactionStatus(Enum):
    FAILED = auto()
    EXECUTED = auto()
    COMMITTED = auto()
    VERIFIED = auto()


class Transaction:
    thread_pool: ThreadPoolExecutor = None

    @classmethod
    def build_transaction(cls, provider, transaction_id: str):
        transaction = cls(provider, transaction_id)
        return transaction

    def __init__(self, provider, transaction_id: str):
        self.provider = provider
        self.transaction_id = transaction_id

    async def await_committed(self, attempts: int = 10, attempts_timeout: int = 100):
        status = TransactionStatus.FAILED
        while True:
            if attempts <= 0:
                return status
            transaction_details = await self.provider.get_tx_receipt(self.transaction_id)
            attempts -= 1
            if "failReason" in transaction_details and transaction_details["failReason"] is not None:
                print(f"Debug Error: {transaction_details['failReason']}")
                return TransactionStatus.FAILED

            if "executed" in transaction_details and transaction_details["executed"]:
                status = TransactionStatus.EXECUTED

            if "block" in transaction_details:
                block = transaction_details["block"]
                if block is not None and "committed" in block and block["committed"]:
                    return TransactionStatus.COMMITTED
            time.sleep(attempts_timeout / 1000)

    async def await_verified(self, attempts: int = 10, attempts_timeout: int = 100):
        intermediate_status = TransactionStatus.FAILED
        while True:
            if attempts <= 0:
                return intermediate_status

            transaction_details = await self.provider.get_tx_receipt(self.transaction_id)
            attempts -= 1
            if "failReason" in transaction_details and transaction_details["failReason"] is not None:
                print(f"Debug Error: {transaction_details['failReason']}")
                return TransactionStatus.FAILED

            if "executed" in transaction_details and transaction_details["executed"]:
                intermediate_status = TransactionStatus.EXECUTED

            if "block" in transaction_details:
                block = transaction_details["block"]
                if block is not None and "committed" in block and block["committed"]:
                    intermediate_status = TransactionStatus.COMMITTED

            if "block" in transaction_details:
                block = transaction_details["block"]
                if block is not None and \
                        "verified" in block and\
                        block["verified"]:
                    return TransactionStatus.VERIFIED
            time.sleep(attempts_timeout / 1000)
