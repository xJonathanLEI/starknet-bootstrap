use std::{ffi::OsStr, sync::Arc, time::Duration};

use anyhow::Result;
use clap::{builder::TypedValueParser, Parser};
use ethers::{
    core::k256::ecdsa::SigningKey as L1Key,
    middleware::SignerMiddleware,
    providers::{Middleware, Provider as L1Provider},
    signers::{LocalWallet as L1LocalWallet, Signer},
    types::{Address as L1Address, U256},
};
use starknet::{
    accounts::{AccountFactory, OpenZeppelinAccountFactory},
    core::types::{BlockId, BlockTag, ExecutionResult, FieldElement, FunctionCall, StarknetError},
    macros::{felt, selector},
    providers::{
        jsonrpc::HttpTransport, JsonRpcClient, MaybeUnknownErrorCode, Provider, ProviderError,
        StarknetErrorWithMessage,
    },
    signers::{LocalWallet as L2LocalWallet, SigningKey as L2Key},
};
use url::Url;

use crate::contracts::StarknetEthBridge;

mod contracts;

const L2_ETH_ADDRESS: FieldElement =
    felt!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7");
const L2_OZ_CLASS_HASH: FieldElement =
    felt!("0x05c478ee27f2112411f86f207605b2e2c58cdb647bac0df27f660ef2252359c6");

const POLL_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug, Parser)]
#[clap(author, version, about)]
struct Cli {
    #[clap(long, help = "Layer 1 JSON-RPC URL")]
    l1_rpc: Url,
    #[clap(long, help = "Layer 2 JSON-RPC (v0.4.x) URL")]
    l2_rpc: Url,
    #[clap(long, help = "Layer 1 address for the StarknetEthBridge proxy")]
    eth_bridge_address: L1Address,
    #[clap(
        long,
        value_parser = L1KeyParser,
        help = "Layer 1 private key"
    )]
    l1_key: L1Key,
    #[clap(
        long,
        value_parser = L2KeyParser,
        help = "Layer 2 private key"
    )]
    l2_key: L2Key,
}

#[derive(Clone)]
pub struct L1KeyParser;

#[derive(Clone)]
pub struct L2KeyParser;

impl TypedValueParser for L1KeyParser {
    type Value = L1Key;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        _arg: Option<&clap::Arg>,
        value: &OsStr,
    ) -> std::result::Result<Self::Value, clap::Error> {
        match hex::decode(value.to_string_lossy().trim_start_matches("0x")) {
            Ok(bytes) => L1Key::from_slice(&bytes)
                .map_err(|err| cmd.clone().error(clap::error::ErrorKind::InvalidValue, err)),
            Err(err) => Err(cmd.clone().error(clap::error::ErrorKind::InvalidValue, err)),
        }
    }
}

impl TypedValueParser for L2KeyParser {
    type Value = L2Key;

    fn parse_ref(
        &self,
        cmd: &clap::Command,
        _arg: Option<&clap::Arg>,
        value: &OsStr,
    ) -> std::result::Result<Self::Value, clap::Error> {
        FieldElement::from_hex_be(&value.to_string_lossy())
            .map(L2Key::from_secret_scalar)
            .map_err(|err| cmd.clone().error(clap::error::ErrorKind::InvalidValue, err))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    run().await
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    let l2_provider = Arc::new(JsonRpcClient::new(HttpTransport::new(cli.l2_rpc)));
    let l2_chain_id = l2_provider.chain_id().await?;

    let mut oz_cairo_0_factory = OpenZeppelinAccountFactory::new(
        L2_OZ_CLASS_HASH,
        l2_chain_id,
        L2LocalWallet::from_signing_key(cli.l2_key),
        l2_provider.clone(),
    )
    .await?;
    oz_cairo_0_factory.set_block_id(BlockId::Tag(BlockTag::Pending));

    // Locally calculates bootstrapper address
    let bootstrapper_deployment = oz_cairo_0_factory.deploy(FieldElement::ZERO);
    let bootstrapper_address = bootstrapper_deployment.address();
    println!("L2 bootstrapper address: {:#064x}", bootstrapper_address);

    if is_address_deployed(&l2_provider, bootstrapper_address).await? {
        println!("L2 bootstrapper has already been deployed");
    } else {
        // Checks if the address needs to be funded first
        let bootstrapper_eth_balance = get_l2_balance(&l2_provider, bootstrapper_address).await?;
        println!(
            "L2 bootstrapper address balance: {} ETH",
            bootstrapper_eth_balance.to_big_decimal(18)
        );

        if bootstrapper_eth_balance == FieldElement::ZERO {
            let l1_provider = Arc::new(L1Provider::new(ethers::providers::Http::new(cli.l1_rpc)));
            let l1_chain_id = l1_provider.get_chainid().await?.as_u64();

            let l1_signer: L1LocalWallet = cli.l1_key.into();
            let l1_signer = Arc::new(SignerMiddleware::new(
                l1_provider,
                l1_signer.with_chain_id(l1_chain_id),
            ));

            let eth_bridge = StarknetEthBridge::new(cli.eth_bridge_address, l1_signer);

            // 0.01 ETH
            let deposit_amount = U256::from_dec_str("10000000000000000").unwrap();

            // The bridge takes any fee amount
            let fee_amount = U256::from_dec_str("1").unwrap();

            let deposit_call = eth_bridge
                .deposit_with_amount(
                    deposit_amount,
                    U256::from_str_radix(&format!("{:064x}", bootstrapper_address), 16).unwrap(),
                )
                .value(deposit_amount + fee_amount);

            println!("Depositing 0.01 ETH through StarkGate...");

            let deposit_tx = deposit_call.send().await?;
            println!(
                "StarkGate deposit transaction: 0x{}. Waiting for confirmation...",
                hex::encode(*deposit_tx)
            );

            deposit_tx.await?;
            println!("StarkGate deposit transaction confirmed. Waiting for L2 balance to become available...");

            // Waits until L2 balance is available
            loop {
                let bootstrapper_eth_balance =
                    get_l2_balance(&l2_provider, bootstrapper_address).await?;
                println!(
                    "L2 bootstrapper address balance: {} ETH",
                    bootstrapper_eth_balance.to_big_decimal(18)
                );

                if bootstrapper_eth_balance > FieldElement::ZERO {
                    println!("L1->L2 ETH bridging completed");
                    break;
                }

                tokio::time::sleep(POLL_INTERVAL).await;
            }
        }

        // Deploys bootstrapper address
        let bootstrapper_deployment_tx = bootstrapper_deployment.send().await?;
        println!(
            "L2 bootstrapper account deployment transaction: {:#064x}",
            bootstrapper_deployment_tx.transaction_hash
        );
        watch_l2_tx(&l2_provider, bootstrapper_deployment_tx.transaction_hash).await?;

        println!(
            "L2 bootstrapper account is now available at: {:#064x}",
            bootstrapper_address
        );
    }

    Ok(())
}

async fn is_address_deployed<P>(provider: P, address: FieldElement) -> Result<bool>
where
    P: Provider,
{
    match provider
        .get_class_hash_at(BlockId::Tag(BlockTag::Pending), address)
        .await
    {
        Ok(_) => Ok(true),
        Err(ProviderError::StarknetError(StarknetErrorWithMessage {
            code: MaybeUnknownErrorCode::Known(StarknetError::ContractNotFound),
            ..
        })) => Ok(false),
        Err(err) => Err(err.into()),
    }
}

async fn get_l2_balance<P>(provider: P, address: FieldElement) -> Result<FieldElement>
where
    P: Provider,
{
    Ok(provider
        .call(
            FunctionCall {
                contract_address: L2_ETH_ADDRESS,
                entry_point_selector: selector!("balanceOf"),
                calldata: vec![address],
            },
            BlockId::Tag(BlockTag::Pending),
        )
        .await?[0])
}

pub async fn watch_l2_tx<P>(provider: P, transaction_hash: FieldElement) -> Result<()>
where
    P: Provider,
{
    loop {
        match provider.get_transaction_receipt(transaction_hash).await {
            Ok(receipt) => match receipt.execution_result() {
                ExecutionResult::Succeeded => {
                    eprintln!("Transaction {:#064x} confirmed", transaction_hash);

                    return Ok(());
                }
                ExecutionResult::Reverted { reason } => {
                    return Err(anyhow::anyhow!("transaction reverted: {}", reason));
                }
            },
            Err(ProviderError::StarknetError(StarknetErrorWithMessage {
                code: MaybeUnknownErrorCode::Known(StarknetError::TransactionHashNotFound),
                ..
            })) => {
                eprintln!("Transaction not confirmed yet...");
            }
            // Some nodes are still serving error code `25` for tx hash not found. This is
            // technically a bug on the node's side, but we maximize compatibility here by also
            // accepting it.
            Err(ProviderError::StarknetError(StarknetErrorWithMessage {
                code: MaybeUnknownErrorCode::Known(StarknetError::InvalidTransactionHash),
                ..
            })) => {
                eprintln!(
                    "Transaction {:#064x} not confirmed yet...",
                    transaction_hash
                );
            }
            Err(err) => return Err(err.into()),
        }

        tokio::time::sleep(POLL_INTERVAL).await;
    }
}
