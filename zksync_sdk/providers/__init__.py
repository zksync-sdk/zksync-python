from abc import ABC, abstractmethod
from typing import Any, List, Optional


class ProviderError(Exception):
    def __init__(self, basic_response, *args):
        self.basic_response = basic_response
        super().__init__(*args)


class ResponseError(Exception):
    def __init__(self, id, text, *args):
        self.id = id
        self.text = text
        super().__init__(*args)


class JsonRPCProvider(ABC):
    @abstractmethod
    async def request(self, method: str, params: Optional[List]) -> Any:
        pass

    def create_request(self, method: str, params=None):
        return {
            "id":      1,
            "jsonrpc": '2.0',
            "method":  method,
            "params":  params
        }
