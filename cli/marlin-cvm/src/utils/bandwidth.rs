use anyhow::{Context, Result};

pub struct BandwidthUnit {
    pub id: &'static str,
    pub value: u64,
}

pub const OYSTER_BANDWIDTH_UNITS_LIST: [BandwidthUnit; 3] = [
    BandwidthUnit {
        id: "KBps",
        value: 1_000_000,
    },
    BandwidthUnit {
        id: "MBps",
        value: 1_000,
    },
    BandwidthUnit {
        id: "GBps",
        value: 1,
    },
];

pub async fn get_bandwidth_rate_for_region(region_code: &str, cp_url: &str) -> Result<u64> {
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

pub fn calculate_bandwidth_cost(
    bandwidth: &str,
    bandwidth_unit: &str,
    bandwidth_rate_for_region_scaled: u64,
    duration: u64,
) -> Result<u64> {
    let unit_conversion_divisor = OYSTER_BANDWIDTH_UNITS_LIST
        .iter()
        .find(|unit| unit.id == bandwidth_unit)
        .map(|unit| unit.value)
        .context("Failed to find bandwidth unit")?;

    let bandwidth_u64 = bandwidth
        .parse::<u64>()
        .context("Failed to parse bandwidth as u64")?;

    (bandwidth_u64)
        .checked_mul(bandwidth_rate_for_region_scaled)
        .context("Failed to multiply bandwidth and bandwidth rate")?
        .checked_mul(u64::from(duration))
        .context("Failed to multiply duration and bandwidth rate")?
        .checked_div(unit_conversion_divisor)
        .context("Failed to divide by unit conversion divisor")
}
