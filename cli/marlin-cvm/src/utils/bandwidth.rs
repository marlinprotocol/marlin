use anyhow::{Context, Result};

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

pub fn calculate_bandwidth_rate(
    bandwidth: u64, // KBps
    bandwidth_rate_for_region_scaled: u64,
) -> Result<u64> {
    let unit_conversion_divisor = 1000_000;

    (bandwidth)
        .checked_mul(bandwidth_rate_for_region_scaled)
        .context("Failed to multiply bandwidth and bandwidth rate")?
        .checked_add(unit_conversion_divisor - 1)
        .context("Failed to add unit conversion divisor minus one")?
        .checked_div(unit_conversion_divisor)
        .context("Failed to divide by unit conversion divisor")
}
