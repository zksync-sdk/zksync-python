from http.client import OK
from typing import List

import httpx

from . import JsonRPCProvider
from ..network import Network


class HttpJsonRPCProvider(JsonRPCProvider):
    def __init__(self, network: Network):
        self.network = network

    async def request(self, method: str, params: List):
        print(params)
        async with httpx.AsyncClient() as client:
            response = await client.post(self.network.zksync_url,
                                         json=self.create_request(method, params))
            if response.status_code == OK:
                result = response.json()
                if "error" in result:
                    raise Exception(result["error"])
                else:
                    return result['result']
            else:
                raise Exception
