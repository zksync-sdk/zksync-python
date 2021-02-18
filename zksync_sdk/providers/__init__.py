from abc import ABC, abstractmethod
from typing import List, Optional


class JsonRPCProvider(ABC):
    @abstractmethod
    async def request(self, method: str, params: Optional[List]):
        pass

    def create_request(self, method: str, params=None):
        return {
            "id":      1,
            "jsonrpc": '2.0',
            "method":  method,
            "params":  params
        }
