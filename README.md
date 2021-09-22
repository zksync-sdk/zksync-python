# zkSync Python SDK

[![Live on Mainnet](https://img.shields.io/badge/wallet-Live%20on%20Mainnet-blue)](https://wallet.zksync.io)
[![Live on Rinkeby](https://img.shields.io/badge/wallet-Live%20on%20Rinkeby-blue)](https://rinkeby.zksync.io)
[![Live on Ropsten](https://img.shields.io/badge/wallet-Live%20on%20Ropsten-blue)](https://ropsten.zksync.io)
[![Join the technical discussion chat at https://gitter.im/matter-labs/zksync](https://badges.gitter.im/matter-labs/zksync.svg)](https://gitter.im/matter-labs/zksync?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

This repository provides a Python SDK for zkSync developers, which can be used either on PC or Android.

## What is zkSync

zkSync is a scaling and privacy engine for Ethereum. Its current functionality scope includes low gas transfers of ETH
and ERC20 tokens in the Ethereum network.  
zkSync is built on ZK Rollup architecture. ZK Rollup is an L2 scaling solution in which all funds are held by a smart
contract on the mainchain, while computation and storage are performed off-chain. For every Rollup block, a state
transition zero-knowledge proof (SNARK) is generated and verified by the mainchain contract. This SNARK includes the
proof of the validity of every single transaction in the Rollup block.
Additionally, the public data update for every block is published over the mainchain network in the cheap calldata.
This architecture provides the following guarantees:

- The Rollup validator(s) can never corrupt the state or steal funds (unlike Sidechains).  
- Users can always retrieve the funds from the Rollup even if validator(s) stop cooperating because the data is available (unlike Plasma).
- Thanks to validity proofs, neither users nor a single other trusted party needs to be online to monitor Rollup blocks in order to prevent fraud.
In other words, ZK Rollup strictly inherits the security guarantees of the underlying L1.

To learn how to use zkSync, please refer to the [zkSync SDK documentation](https://zksync.io/api/sdk/python/tutorial.html).
## Supporting version
Python 3.8+ 

## License

zkSync Python SDK is distributed under the terms of the MIT license.
See  [LICENSE](LICENSE) for details.


### Batch builder ###
Here is added ability to collect the different transaction is batch and singing it only once. For this has been added
`BatchBuilder` class. It allows to collect the different transactions type and then build them once. For executing there must be used 
new method `submit_batch_builder_trx_batch` with constructed result of batches. Here is the list of supported transactions types:
* ChangePubKey
* Withdraw
* MintNFT
* WithdrawNFT
* Transfer
* ForceExit
* Swap

For creating BatchBuilder object there is necessary to provide `Wallet` object and its current Nonce.
Also `BatchBuilder` could accept already signed transactions list, for instance,
made by build_ method of this wallet object.
