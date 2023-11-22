use ethers::contract::abigen;

pub use starknet_eth_bridge::StarknetEthBridge;

abigen!(
    StarknetEthBridge,
    "./src/contracts/abis/StarknetEthBridge.json"
);
