from http.client import OK
from typing import List, Optional

import httpx

from . import JsonRPCTransport, ProviderError, ResponseError
from ..network import Network


class HttpJsonRPCTransport(JsonRPCTransport):
    def __init__(self, network: Network):
        self.network = network

    async def request(self, method: str, params: Optional[List]):
        async with httpx.AsyncClient() as client:
            response = await client.post(self.network.zksync_url, json=self.create_request(method, params))
            if response.status_code == OK:
                result = response.json()
                if "error" in result:
                    data = result["error"]
                    raise ResponseError(data['code'], data['message'])
                else:
                    return result['result']
            else:
                raise ProviderError(response, "Unexpected status code")
