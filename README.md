<p align="center">
  <h1 align="center">starknet-bootstrap</h1>
</p>

**Bootstrap a new Starknet network by declaring and deploying commonly used classes and contracts.**

## Prerequisites

To run this tool, the new L2 network must fulfill the following requirements:

- The L2 ETH token must be available at the `0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7` address.
- The L2 network must have the OZ Cairo 0 account class `0x05c478ee27f2112411f86f207605b2e2c58cdb647bac0df27f660ef2252359c6` declared.

You'd need to have these available:

- an L1 JSON-RPC endpoint URL;
- an L2 JSON-RPC (v0.4.x) endponit URL;
- the `StarknetEthBridge` (proxy) contract address on L1;
- private key to an L1 address that has at least `0.01 + fees` ETH balance;
- any L2 private key that you choose.

## Bootstrapping process

The bootstrapping process looks like this:

1. The L1 account sends `0.01` ETH to an L2 to-be-deployed bootstrapper account (OZ Cairo 0);
2. The L2 bootstrapper account is deployed using a `DEPLOY_ACCOUNT` transaction;
3. The bootstrapper declares the UDC class;
4. The bootstrapper declares a special account class whose sole purpose is to deploy the UDC contract using the `deploy` syscall;
5. The bootstrapper sends `0.001` ETH to the to-be-deployed special account;
6. The special account is deployed using a `DEPLOY_ACCOUNT` transaction;
7. The special account deploys the UDC;
8. The bootstrapper account declares all the classes needed, and deploys all the contracts needed using the UDC deployed.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](./LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
