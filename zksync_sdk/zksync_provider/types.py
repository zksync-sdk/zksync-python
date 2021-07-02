from enum import Enum

__all__ = ['FeeTxType']


class FeeTxType(Enum):
    withdraw = "Withdraw"
    transfer = "Transfer"
    swap = "Swap"
    fast_withdraw = "FastWithdraw"
    change_pub_key_onchain = {"ChangePubKey": "Onchain"}
    change_pub_key_ecdsa = {"ChangePubKey": "ECDSA"}
    change_pub_key_create2 = {"ChangePubKey": "CREATE2"}
    mint_nft = "MintNFT"
    withdraw_nft = "WithdrawNFT"
