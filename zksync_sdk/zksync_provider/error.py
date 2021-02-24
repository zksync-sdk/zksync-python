class ZkSyncProviderError(Exception):
    pass


class AccountDoesNotExist(ZkSyncProviderError):
    def __init__(self, address, *args):
        self.address = address
        super().__init__(*args)
