use std::time::Duration;

use crate::{
    arch::Arch,
    args::{init_params::InitParamsArgs, wallet::WalletArgs},
    configs::{
        self,
        global::{EXTRA_DECIMALS, NOTICE_PERIOD},
    },
    deployment::{Deployment, get_deployment_adapter},
    utils::{format_rate, format_usdc},
};

use anyhow::{Context, Result, anyhow};
use ciborium::{Value, cbor};
use clap::Args;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tracing::info;

// Retry Configuration
const IP_CHECK_RETRIES: u32 = 20;
const IP_CHECK_INTERVAL: u64 = 15;
const ATTESTATION_RETRIES: u32 = 20;
const ATTESTATION_INTERVAL: u64 = 15;
const TCP_CHECK_RETRIES: u32 = 20;
const TCP_CHECK_INTERVAL: u64 = 15;

/// Deploy a new job
#[derive(Args, Debug)]
pub struct DeployArgs {
    /// Preset for parameters (e.g. blue)
    #[arg(long)]
    preset: Option<String>,

    /// CVM architecture
    #[arg(long)]
    arch: Option<Arch>,

    /// Operator address
    #[arg(long)]
    operator: Option<String>,

    /// AMI ID to deploy as a CVM
    #[arg(long)]
    image: Option<String>,

    /// Region for deployment
    #[arg(long, default_value = "ap-south-1")]
    region: String,

    /// Instance type (e.g. "r6g.large")
    #[arg(long)]
    instance_type: Option<String>,

    /// Average bandwidth cap in KBps
    #[arg(long, default_value = "10")]
    bandwidth: u32,

    /// Job duration in minutes
    #[arg(long)]
    duration_in_minutes: u64,

    /// Job name
    #[arg(long, default_value = "")]
    name: String,

    /// Initialization parameters
    #[command(flatten)]
    init_params: InitParamsArgs,

    /// Deployment
    #[arg(long, help_heading = "Deployment options", default_value = "arb")]
    deployment: Deployment,

    /// RPC URL
    #[arg(long, help_heading = "RPC options")]
    rpc: Option<String>,

    #[command(flatten)]
    wallet: WalletArgs,
}

#[derive(Serialize, Deserialize)]
struct Operator {
    allowed_regions: Vec<String>,
    min_rates: Vec<RateCard>,
}

#[derive(Serialize, Deserialize)]
struct RateCard {
    region: String,
    rate_cards: Vec<InstanceRate>,
}

#[derive(Serialize, Deserialize, Clone)]
struct InstanceRate {
    instance: String,
    min_rate: u64,
    cpu: u32,
    memory: u32,
    arch: String,
}

impl DeployArgs {
    pub async fn run(self) -> Result<()> {
        let args = self;
        tracing::info!("Starting deployment...");

        let operator = parse_operator(&args.deployment, args.operator);

        let mut deployment_adapter = get_deployment_adapter(
            args.deployment,
            args.rpc,
            Some(&args.wallet.load_required()?),
        )
        .context("Failed to create deployment adapter")?;

        // Get CP URL using the configured provider
        let cp_url = deployment_adapter
            .get_operator_cp(&operator)
            .await
            .context("Failed to get CP URL")?
            .trim_end_matches('/')
            .to_owned();
        info!("CP URL for operator: {}", cp_url);

        // Fetch operator specs from CP URL
        let spec_url = format!("{}/spec", cp_url);
        let operator_spec = fetch_operator_spec(&spec_url)
            .await
            .context("Failed to fetch operator spec")?;

        // Validate region is supported
        if !operator_spec
            .allowed_regions
            .iter()
            .any(|r| r == &args.region)
        {
            return Err(anyhow!(
                "Region '{}' not supported by operator",
                args.region
            ));
        }

        let instance_type = args.instance_type.map(Result::Ok).unwrap_or_else(|| {
        let arch = args.arch.as_ref().ok_or(anyhow!("Either instance-type or arch is required."))?;
        match args.preset.as_deref() {
            None => match arch {
                Arch::AMD64 => Ok("c6a.large".into()),
                Arch::ARM64 => Ok("c8g.medium".into()),
            },
            _ => Err(anyhow!("Given preset and arch do not have a default instance type, instance-type is required")),
        }
    })?;

        // Fetch operator min rates with early validation
        let selected_instance =
            find_minimum_rate_instance(&operator_spec, &args.region, &instance_type)
                .context("Configuration not supported by operator")?;

        // Calculate costs
        let duration_seconds = (args.duration_in_minutes) * 60 + NOTICE_PERIOD;
        info!("Adding {NOTICE_PERIOD} seconds to the duration to pay for the notice period.");
        let (total_cost, total_rate) = calculate_total_cost(
            &selected_instance,
            duration_seconds,
            args.bandwidth,
            &args.region,
            &cp_url,
            EXTRA_DECIMALS,
        )
        .await
        .context("Failed to calculate total cost")?;

        info!("Total cost: {:.6} USDC", format_usdc(total_cost));
        info!("Total rate: {:.6} USDC/hour", format_rate(total_rate));

        let image = args.image.map(Result::Ok).unwrap_or_else(|| {
            let (preset, arch) = args.preset.as_ref().zip(args.arch.as_ref()).ok_or(anyhow!(
                "Either image or a valid preset and arch is required."
            ))?;
            match preset.as_str() {
                "blue" => match arch {
                    // TODO: Replace with the correct ami ids
                    Arch::AMD64 => Ok(
                        "https://artifacts.marlin.org/oyster/eifs/base-blue_v3.0.0_linux_amd64.eif"
                            .into(),
                    ),
                    Arch::ARM64 => Ok(
                        "https://artifacts.marlin.org/oyster/eifs/base-blue_v3.0.0_linux_arm64.eif"
                            .into(),
                    ),
                },
                _ => Err(anyhow!(
                    "Given preset and arch do not have a default image, image is required"
                )),
            }
        })?;

        // Create metadata
        let metadata = create_metadata(
            &selected_instance.instance,
            &args.region,
            &image,
            &args.name,
            &args
                .init_params
                .load(args.preset, args.arch)
                .context("Failed to load init params")?
                .unwrap_or("".into()),
        )
        .context("Failed to encode metadata")?;

        // Create job
        let job_id = deployment_adapter
            .job_create(metadata, &operator, total_rate, total_cost)
            .await
            .context("Failed to send create transaction")?;
        info!("Job created with ID: {}", job_id);

        info!("Waiting for 20 seconds for enclave to start...");
        tokio::time::sleep(Duration::from_secs(20)).await;

        let ip_address = wait_for_ip_address(&cp_url, job_id, &args.region).await?;
        info!("IP address obtained: {}", ip_address);

        if !check_reachability(&ip_address).await {
            return Err(anyhow!("Reachability check failed after maximum retries"));
        }

        info!("Enclave is ready! IP address: {}", ip_address);

        Ok(())
    }
}

fn parse_operator(deployment: &Deployment, operator: Option<String>) -> String {
    match deployment {
        Deployment::Arb => operator.unwrap_or(configs::arb::DEFAULT_OPERATOR_ADDRESS.to_string()),
    }
}

async fn fetch_operator_spec(url: &str) -> Result<Operator> {
    let client = Client::new();
    let response = client.get(url).send().await?;
    let operator: Operator = response.json().await?;
    Ok(operator)
}

fn find_minimum_rate_instance(
    operator: &Operator,
    region: &str,
    instance: &str,
) -> Result<InstanceRate> {
    operator
        .min_rates
        .iter()
        .find(|rate_card| rate_card.region == region)
        .ok_or_else(|| anyhow!("No rate card found for region: {}", region))?
        .rate_cards
        .iter()
        .filter(|rate| rate.instance == instance)
        .min_by(|a, b| {
            let a_rate = a.min_rate;
            let b_rate = b.min_rate;
            a_rate.cmp(&b_rate)
        })
        .cloned()
        .ok_or_else(|| {
            anyhow!(
                "No matching instance rate found for region: {}, instance: {}",
                region,
                instance
            )
        })
}

async fn calculate_total_cost(
    instance_rate: &InstanceRate,
    duration: u64,
    bandwidth: u32,
    region: &str,
    cp_url: &str,
    extra_decimals: u32,
) -> Result<(u64, u64)> {
    let compute_rate = instance_rate.min_rate;
    let compute_cost = duration
        .checked_mul(compute_rate)
        .context("Failed to multiply duration and instance rate")?;

    let bandwidth_rate_region = get_bandwidth_rate_for_region(region, cp_url).await?;
    let bandwidth_rate = calculate_bandwidth_rate(bandwidth.into(), bandwidth_rate_region)
        .context("Failed to calculate bandwidth cost")?;
    let bandwidth_cost = duration
        .checked_mul(bandwidth_rate)
        .context("Failed to multiply duration and bandwidth rate")?;

    let total_cost = (compute_cost)
        .checked_add(bandwidth_cost)
        .context("Failed to add instance and bandwidth costs")?
        .checked_add(10u64.pow(extra_decimals) - 1)
        .context("Failed to add 10 pow extra - 1")?
        .checked_div(10u64.pow(extra_decimals))
        .context("Failed to divide total cost by 1e12")?;
    let total_rate = compute_rate
        .checked_add(bandwidth_rate)
        .context("Failed to add instance and bandwidth rates")?;

    Ok((total_cost, total_rate))
}

async fn get_bandwidth_rate_for_region(region_code: &str, cp_url: &str) -> Result<u64> {
    let client = reqwest::Client::new();
    let response = client.get(format!("{}/bandwidth", cp_url)).send().await?;
    let bandwidth_data: serde_json::Value = response.json().await?;

    // Extract rates array from response
    if let Some(rates) = bandwidth_data.get("rates").and_then(|r| r.as_array()) {
        // Find matching region and parse its rate
        for rate in rates {
            if let (Some(code), Some(rate)) = (
                rate.get("region_code").and_then(|c| c.as_str()),
                rate.get("rate").and_then(|r| r.as_u64()),
            ) && code == region_code
            {
                return Ok(rate);
            }
        }
    }

    Err(anyhow::anyhow!("Region not found or parsing failed"))
}

fn calculate_bandwidth_rate(
    bandwidth: u64, // KBps
    bandwidth_rate_for_region_scaled: u64,
) -> Result<u64> {
    let unit_conversion_divisor = 1_000_000;

    Ok(bandwidth
        .checked_mul(bandwidth_rate_for_region_scaled)
        .context("Failed to multiply bandwidth and bandwidth rate")?
        .div_ceil(unit_conversion_divisor))
}

fn create_metadata(
    instance: &str,
    region: &str,
    image: &str,
    name: &str,
    init_params: &[u8],
) -> Result<Vec<u8>> {
    let cbor = cbor!({
        "instance" => instance,
        "region" => region,
        "image" => image,
        "name" => name,
        "init_params" => Value::Bytes(init_params.to_vec()),
    })
    .context("Should never happen, failed to create cbor metadata")?;
    let mut serialized = Vec::new();
    ciborium::into_writer(&cbor, &mut serialized)
        .context("Should never happen, failed to serialize metadata")?;
    Ok(serialized)
}

async fn wait_for_ip_address(url: &str, job_id: u64, region: &str) -> Result<String> {
    let client = reqwest::Client::new();
    let mut last_response = String::new();

    // Construct the IP endpoint URL with query parameters
    let ip_url = format!("{}/ip?id={}&region={}", url, job_id, region);

    for attempt in 1..=IP_CHECK_RETRIES {
        info!(
            "Checking for IP address (attempt {}/{})",
            attempt, IP_CHECK_RETRIES
        );

        let resp = client.get(&ip_url).send().await;
        let Ok(response) = resp else {
            tracing::error!("Failed to connect to IP endpoint: {}", resp.unwrap_err());
            tokio::time::sleep(Duration::from_secs(IP_CHECK_INTERVAL)).await;
            continue;
        };

        // Get the status code
        let status = response.status();

        // Get text response first to log in case of error
        let text = response.text().await;
        let Ok(text_body) = text else {
            tracing::error!("Failed to read response body: {}", text.unwrap_err());
            tokio::time::sleep(Duration::from_secs(IP_CHECK_INTERVAL)).await;
            continue;
        };

        // Parse the JSON
        let json_result = serde_json::from_str::<serde_json::Value>(&text_body);
        let Ok(json) = json_result else {
            let err = json_result.unwrap_err();
            tracing::error!(
                "Failed to parse IP endpoint response (status: {}): {}. Raw response: {}",
                status,
                err,
                text_body
            );
            tokio::time::sleep(Duration::from_secs(IP_CHECK_INTERVAL)).await;
            continue;
        };

        last_response = json.to_string();

        info!("Response from IP endpoint: {}", last_response);

        // Check for IP in response
        if let Some(ip) = json.get("ip").and_then(|ip| ip.as_str())
            && !ip.is_empty()
        {
            return Ok(ip.to_string());
        }

        info!("IP not found yet, waiting {} seconds...", IP_CHECK_INTERVAL);
        tokio::time::sleep(Duration::from_secs(IP_CHECK_INTERVAL)).await;
    }

    Err(anyhow!(
        "IP address not found after {} attempts. Last response: {}",
        IP_CHECK_RETRIES,
        last_response
    ))
}

async fn ping_ip(ip: &str) -> bool {
    let address = format!("{}:1300", ip);
    for attempt in 1..=TCP_CHECK_RETRIES {
        info!(
            "Attempting TCP connection to {} (attempt {}/{})",
            address, attempt, TCP_CHECK_RETRIES
        );
        match tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(&address)).await {
            Ok(Ok(_)) => {
                return true;
            }
            Ok(Err(e)) => info!("TCP connection failed: {}", e),
            Err(_) => info!("TCP connection timed out"),
        }
        tokio::time::sleep(Duration::from_secs(TCP_CHECK_INTERVAL)).await;
    }
    info!("All TCP connection attempts failed");
    false
}

async fn check_reachability(ip: &str) -> bool {
    // First check basic connectivity
    if !ping_ip(ip).await {
        tracing::error!("Failed to establish TCP connection to the instance");
        return false;
    }

    let client = reqwest::Client::new();
    let attestation_url = format!("http://{}:1300/attestation/raw", ip);

    for attempt in 1..=ATTESTATION_RETRIES {
        info!(
            "Checking reachability (attempt {}/{})",
            attempt, ATTESTATION_RETRIES
        );

        match client.get(&attestation_url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    match response.bytes().await {
                        Ok(bytes) if !bytes.is_empty() => {
                            info!("Reachability check successful");
                            return true;
                        }
                        Ok(_) => info!("Empty attestation response"),
                        Err(e) => info!("Error reading attestation response: {}", e),
                    }
                }
            }
            Err(e) => info!("Failed to connect to attestation endpoint: {}", e),
        }

        info!(
            "Waiting {} seconds before next reachability check...",
            ATTESTATION_INTERVAL
        );
        tokio::time::sleep(Duration::from_secs(ATTESTATION_INTERVAL)).await;
    }

    false
}
