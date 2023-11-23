use std::{convert::Infallible, ffi::OsStr, sync::Arc, time::Duration};

use anyhow::Result;
use async_trait::async_trait;
use clap::{builder::TypedValueParser, Parser};
use ethers::{
    core::k256::ecdsa::SigningKey as L1Key,
    middleware::SignerMiddleware,
    providers::{Middleware, Provider as L1Provider},
    signers::{LocalWallet as L1LocalWallet, Signer},
    types::{Address as L1Address, U256},
};
use starknet::{
    accounts::{
        Account, AccountFactory, Call, ConnectedAccount, ExecutionEncoding,
        OpenZeppelinAccountFactory, RawAccountDeployment, SingleOwnerAccount,
    },
    contract::ContractFactory,
    core::types::{
        contract::{legacy::LegacyContractClass, CompiledClass, SierraClass},
        BlockId, BlockTag, BroadcastedInvokeTransaction, BroadcastedTransaction, ExecutionResult,
        FieldElement, FunctionCall, StarknetError,
    },
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

const CLASSES: &[ClassToProcess] = &[
    // This contract is expected by the Argent X extension
    ClassToProcess {
        name: "Multicall",
        class_json: include_str!("./classes/Multicall.json"),
        deployments: &[ClassDeployment {
            salt: FieldElement::ZERO,
            calldata: &[],
        }],
    },
    // Argent X account class as of extension version 5.10.4
    ClassToProcess {
        name: "Argent",
        class_json: include_str!("./classes/Argent.json"),
        deployments: &[],
    },
    ClassToProcess {
        name: "BraavosProxy",
        class_json: include_str!("./classes/BraavosProxy.json"),
        deployments: &[],
    },
    ClassToProcess {
        name: "BraavosAccount",
        class_json: include_str!("./classes/BraavosAccount.json"),
        deployments: &[],
    },
    ClassToProcess {
        name: "BraavosMulticall",
        class_json: include_str!("./classes/BraavosMulticall.json"),
        deployments: &[ClassDeployment {
            salt: FieldElement::ZERO,
            calldata: &[],
        }],
    },
    // Some unknown contract used by Braavos. Braavos doesn't work without it.
    ClassToProcess {
        name: "BraavosUnknown",
        class_json: include_str!("./classes/BraavosUnknown.json"),
        deployments: &[],
    },
    ClassToProcess {
        name: "OZ-Account-v0.8.0-beta1",
        class_json: include_str!("./classes/OZ-Account-v0.8.0-beta1.json"),
        deployments: &[],
    },
    ClassToProcess {
        name: "OZ-ERC20-v0.8.0-beta1",
        class_json: include_str!("./classes/OZ-ERC20-v0.8.0-beta1.json"),
        deployments: &[],
    },
];

const L2_ETH_ADDRESS: FieldElement =
    felt!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7");
const L2_OZ_CLASS_HASH: FieldElement =
    felt!("0x05c478ee27f2112411f86f207605b2e2c58cdb647bac0df27f660ef2252359c6");

const POLL_INTERVAL: Duration = Duration::from_secs(5);

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

struct ClassToProcess {
    name: &'static str,
    class_json: &'static str,
    deployments: &'static [ClassDeployment],
}

struct ClassDeployment {
    salt: FieldElement,
    calldata: &'static [FieldElement],
}

#[derive(Clone)]
struct L1KeyParser;

#[derive(Clone)]
struct L2KeyParser;

#[derive(Clone)]
struct UdcDeployerFactory<P> {
    class_hash: FieldElement,
    chain_id: FieldElement,
    provider: P,
}

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

#[async_trait]
impl<P> AccountFactory for UdcDeployerFactory<P>
where
    P: Provider + Sync + Send,
{
    type Provider = P;
    type SignError = Infallible;

    fn class_hash(&self) -> FieldElement {
        self.class_hash
    }

    fn calldata(&self) -> Vec<FieldElement> {
        vec![]
    }

    fn chain_id(&self) -> FieldElement {
        self.chain_id
    }

    fn provider(&self) -> &Self::Provider {
        &self.provider
    }

    fn block_id(&self) -> BlockId {
        BlockId::Tag(BlockTag::Pending)
    }

    async fn sign_deployment(
        &self,
        _deployment: &RawAccountDeployment,
    ) -> Result<Vec<FieldElement>, Self::SignError> {
        Ok(vec![])
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    run().await
}

// Yes it's spaghetti code, but it's only gonna be used like once anyways.
async fn run() -> Result<()> {
    let cli = Cli::parse();

    let l2_provider = Arc::new(JsonRpcClient::new(HttpTransport::new(cli.l2_rpc)));
    let l2_chain_id = l2_provider.chain_id().await?;

    let bootstrapper_signer = Arc::new(L2LocalWallet::from_signing_key(cli.l2_key));

    let mut oz_cairo_0_factory = OpenZeppelinAccountFactory::new(
        L2_OZ_CLASS_HASH,
        l2_chain_id,
        bootstrapper_signer.clone(),
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

    let mut bootstrapper = SingleOwnerAccount::new(
        l2_provider.clone(),
        bootstrapper_signer.clone(),
        bootstrapper_address,
        l2_chain_id,
        ExecutionEncoding::Legacy,
    );
    bootstrapper.set_block_id(BlockId::Tag(BlockTag::Pending));

    let udc_class: Arc<LegacyContractClass> = Arc::new(
        serde_json::from_str(include_str!("./classes/UniversalDeployer.json"))
            .expect("to be valid contract class"),
    );
    let udc_class_hash =
        declare_legacy_class(&l2_provider, &bootstrapper, udc_class, "UniversalDeployer").await?;

    let udc_address = starknet::core::utils::get_contract_address(
        FieldElement::ZERO,
        udc_class_hash,
        &[],
        FieldElement::ZERO,
    );

    if is_address_deployed(&l2_provider, udc_address).await? {
        println!(
            "UniversalDeployer contract already available at: {:#064x}",
            udc_address
        );
    } else {
        println!("UniversalDeployer contract not deployed yet");

        // We can't deploy the UDC without having the UDC first. Here we use a special "account"
        // contract that's used for UDC deployment.
        //
        // For simplicity, it's implemented in Cairo 0 to avoid dealing with Sierra compilation.
        let udc_deployer_class: Arc<LegacyContractClass> = Arc::new(
            serde_json::from_str(include_str!("./classes/UdcDeployer.json"))
                .expect("to be valid contract class"),
        );
        let udc_deployer_class_hash = declare_legacy_class(
            &l2_provider,
            &bootstrapper,
            udc_deployer_class,
            "UdcDeployer",
        )
        .await?;

        let udc_deployer_address = starknet::core::utils::get_contract_address(
            FieldElement::ZERO,
            udc_deployer_class_hash,
            &[],
            FieldElement::ZERO,
        );

        if is_address_deployed(&l2_provider, udc_deployer_address).await? {
            println!(
                "UdcDeployer is already available at: {:#064x}",
                udc_deployer_address
            );
        } else {
            // Makes sure the new account has some funds in it
            let udc_deployer_balance = get_l2_balance(&l2_provider, udc_deployer_address).await?;
            println!(
                "UDC deployer address balance: {} ETH",
                udc_deployer_balance.to_big_decimal(18)
            );

            if udc_deployer_balance == FieldElement::ZERO {
                println!("Sending 0.001 ETH to UDC deployer address...");

                let eth_transfer_tx = bootstrapper
                    .execute(vec![Call {
                        to: L2_ETH_ADDRESS,
                        selector: selector!("transfer"),
                        calldata: vec![
                            udc_deployer_address,
                            felt!("1000000000000000"),
                            FieldElement::ZERO,
                        ],
                    }])
                    .send()
                    .await?;
                println!(
                    "ETH transfer transaction: {:#064x}",
                    eth_transfer_tx.transaction_hash
                );
                watch_l2_tx(&l2_provider, eth_transfer_tx.transaction_hash).await?;
            }

            println!("Deploying UDC deployer...");
            let udc_deployer_factory = UdcDeployerFactory {
                class_hash: udc_deployer_class_hash,
                chain_id: l2_chain_id,
                provider: l2_provider.clone(),
            };
            let deployment_tx = udc_deployer_factory
                .deploy(FieldElement::ZERO)
                .send()
                .await?;
            println!(
                "UDC deployer deployment transaction: {:#064x}",
                deployment_tx.transaction_hash
            );
            watch_l2_tx(&l2_provider, deployment_tx.transaction_hash).await?;
        }

        println!("Deploying UniversalDeployer...");

        let udc_deployment_nonce = l2_provider
            .get_nonce(BlockId::Tag(BlockTag::Pending), udc_deployer_address)
            .await?;

        let udc_deployment_fees = l2_provider
            .estimate_fee_single(
                BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction {
                    sender_address: udc_deployer_address,
                    calldata: vec![udc_class_hash],
                    max_fee: FieldElement::ZERO,
                    signature: vec![],
                    nonce: udc_deployment_nonce,
                    is_query: true,
                }),
                BlockId::Tag(BlockTag::Pending),
            )
            .await?;

        let udc_deployment_tx = l2_provider
            .add_invoke_transaction(BroadcastedInvokeTransaction {
                sender_address: udc_deployer_address,
                calldata: vec![udc_class_hash],
                max_fee: (udc_deployment_fees.overall_fee * 2).into(),
                signature: vec![],
                nonce: udc_deployment_nonce,
                is_query: false,
            })
            .await?;
        println!(
            "UniversalDeployer deployment transaction: {:#064x}",
            udc_deployment_tx.transaction_hash
        );
        watch_l2_tx(&l2_provider, udc_deployment_tx.transaction_hash).await?;

        // Sanity check on whether UDC is actually deployed
        if is_address_deployed(&l2_provider, udc_address).await? {
            println!(
                "UniversalDeployer is now available at: {:#064x}",
                udc_address
            );
        } else {
            anyhow::bail!("UDC still not available after deployment");
        }
    }

    for (ind_class, class) in CLASSES.iter().enumerate() {
        println!(
            "[{}/{}] Processing class {}...",
            ind_class + 1,
            CLASSES.len(),
            class.name
        );

        let class_hash = if let Ok(parsed_class) =
            serde_json::from_str::<LegacyContractClass>(class.class_json)
        {
            let class_hash = parsed_class.class_hash()?;
            println!("Class hash of {}: {:#064x}", class.name, class_hash);

            // Declares if not already declared
            declare_legacy_class(
                &l2_provider,
                &bootstrapper,
                Arc::new(parsed_class),
                class.name,
            )
            .await?
        } else if let Ok(parsed_class) = serde_json::from_str::<SierraClass>(class.class_json) {
            let class_hash = parsed_class.class_hash()?;
            println!("Class hash of {}: {:#064x}", class.name, class_hash);

            declare_sierra_class(
                &l2_provider,
                &bootstrapper,
                Arc::new(parsed_class),
                class.name,
            )
            .await?
        } else {
            anyhow::bail!("Failed to parse class {}", class.name);
        };

        let contract_factory =
            ContractFactory::new_with_udc(class_hash, &bootstrapper, udc_address);

        for (ind_deployment, deployment) in class.deployments.iter().enumerate() {
            let deployment =
                contract_factory.deploy(deployment.calldata.to_vec(), deployment.salt, false);

            let deployment_address = deployment.deployed_address();
            println!(
                "Deployment {}/{} of class {} should be at: {:#064x}",
                ind_deployment + 1,
                class.deployments.len(),
                class.name,
                deployment_address
            );

            if is_address_deployed(&l2_provider, deployment_address).await? {
                println!(
                    "Deployment at {:#064x} is already available",
                    deployment_address
                );
            } else {
                println!("Contract not deployed. Deploying...");

                let deployment_tx = deployment.send().await?;
                println!(
                    "Contract deployment transaction: {:#064x}",
                    deployment_tx.transaction_hash
                );
                watch_l2_tx(&l2_provider, deployment_tx.transaction_hash).await?;
            }
        }
    }

    println!("Network bootstrapping has completed");

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

async fn is_class_declared<P>(provider: P, class_hash: FieldElement) -> Result<bool>
where
    P: Provider,
{
    match provider
        .get_class(BlockId::Tag(BlockTag::Pending), class_hash)
        .await
    {
        Ok(_) => Ok(true),
        Err(ProviderError::StarknetError(StarknetErrorWithMessage {
            code: MaybeUnknownErrorCode::Known(StarknetError::ClassHashNotFound),
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

async fn declare_legacy_class<P, A>(
    provider: P,
    account: A,
    class: Arc<LegacyContractClass>,
    class_name: &'static str,
) -> Result<FieldElement>
where
    P: Provider + Sync,
    A: ConnectedAccount + Sync,
    A::SignError: 'static,
{
    let class_hash = class.class_hash()?;

    if is_class_declared(&provider, class_hash).await? {
        println!(
            "Legacy class {} already declared: {:#064x}",
            class_name, class_hash
        );
    } else {
        println!(
            "Legacy class {} not declared yet. Declaring it from bootstrapper...",
            class_name
        );

        let declaration_tx = account
            .declare_legacy(class)
            // Workaround for some weird issue with fee estimates
            .fee_estimate_multiplier(100.0)
            .send()
            .await?;
        println!(
            "Legacy class {} declaration transaction: {:#064x}",
            class_name, declaration_tx.transaction_hash
        );
        watch_l2_tx(provider, declaration_tx.transaction_hash).await?;

        println!(
            "Legacy class {} now declared: {:#064x}",
            class_name, class_hash
        );
    }

    Ok(class_hash)
}

async fn declare_sierra_class<P, A>(
    provider: P,
    account: A,
    class: Arc<SierraClass>,
    class_name: &'static str,
) -> Result<FieldElement>
where
    P: Provider + Sync,
    A: ConnectedAccount + Sync,
    A::SignError: 'static,
{
    let class_hash = class.class_hash()?;

    if is_class_declared(&provider, class_hash).await? {
        println!(
            "Sierra class {} already declared: {:#064x}",
            class_name, class_hash
        );
    } else {
        println!(
            "Sierra class {} not declared yet. Declaring it from bootstrapper...",
            class_name
        );

        println!("Compiling Sierra class with compiler v2.3.0...");

        let sierra_class_json = serde_json::to_string(class.as_ref())?;

        let contract_class: cairo_lang_starknet::contract_class::ContractClass =
            serde_json::from_str(&sierra_class_json)?;

        // TODO: implement the `validate_compatible_sierra_version` call

        let casm_contract =
            cairo_lang_starknet::casm_contract_class::CasmContractClass::from_contract_class(
                contract_class,
                false,
            )?;

        // TODO: directly convert type without going through JSON
        let casm_class =
            serde_json::from_str::<CompiledClass>(&serde_json::to_string(&casm_contract)?)?;

        let casm_class_hash = casm_class.class_hash()?;

        let declaration_tx = account
            .declare(
                Arc::new(class.as_ref().to_owned().flatten()?),
                casm_class_hash,
            )
            // Workaround for some weird issue with fee estimates
            .fee_estimate_multiplier(100.0)
            .send()
            .await?;
        println!(
            "Sierra class {} declaration transaction: {:#064x}",
            class_name, declaration_tx.transaction_hash
        );
        watch_l2_tx(provider, declaration_tx.transaction_hash).await?;

        println!(
            "Sierra class {} now declared: {:#064x}",
            class_name, class_hash
        );
    }

    Ok(class_hash)
}

async fn watch_l2_tx<P>(provider: P, transaction_hash: FieldElement) -> Result<()>
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
