pub mod bandwidth;

/// Formats a U256 value as USDC with 6 decimal places
pub fn format_usdc(value: u64, extra_decimals: u32) -> f64 {
    value as f64 / 10f64.powi(12 - extra_decimals as i32)
}
