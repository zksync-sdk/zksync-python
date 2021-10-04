import asyncio
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional


class TransactionStatus(Enum):
    FAILED = auto()
    COMMITTED = auto()
    VERIFIED = auto()


@dataclass
class TransactionResult:
    status: TransactionStatus
    error_message: str


class Transaction:

    @classmethod
    def build_transaction(cls, provider, transaction_id: str):
        transaction = cls(provider, transaction_id)
        return transaction

    def __init__(self, provider, transaction_hash: str):
        self.provider = provider
        self.transaction_hash = transaction_hash

    async def await_committed(self, attempts: int = 10, attempts_timeout: int = 100) -> TransactionResult:
        status = TransactionResult(TransactionStatus.FAILED,
                                   f"Transaction has not been executed with amount of attempts {attempts}"
                                   f"and timeout {attempts_timeout}")
        while True:
            if attempts <= 0:
                return status
            transaction_details = await self.provider.get_tx_receipt(self.transaction_hash)
            attempts -= 1
            if "failReason" in transaction_details and transaction_details["failReason"] is not None:
                return TransactionResult(TransactionStatus.FAILED, transaction_details['failReason'])

            if "block" in transaction_details:
                block = transaction_details["block"]
                if block is not None and "committed" in block and block["committed"]:
                    return TransactionResult(TransactionStatus.COMMITTED, "")
            await asyncio.sleep(attempts_timeout / 1000)

    async def await_verified(self, attempts: int = 10, attempts_timeout: int = 100):
        intermediate_status = TransactionResult(
            TransactionStatus.FAILED,
            f"Transaction has not been executed with amount of attempts {attempts}"
            f"and timeout {attempts_timeout}")
        while True:
            if attempts <= 0:
                return intermediate_status

            transaction_details = await self.provider.get_tx_receipt(self.transaction_hash)
            attempts -= 1
            if "failReason" in transaction_details and transaction_details["failReason"] is not None:
                return TransactionResult(TransactionStatus.FAILED, transaction_details['failReason'])

            if "block" in transaction_details:
                block = transaction_details["block"]
                if block is not None and "committed" in block and block["committed"]:
                    intermediate_status = TransactionResult(TransactionStatus.COMMITTED, "")

            if "block" in transaction_details:
                block = transaction_details["block"]
                if block is not None and \
                        "verified" in block and \
                        block["verified"]:
                    return TransactionResult(TransactionStatus.VERIFIED, "")
            await asyncio.sleep(attempts_timeout / 1000)
