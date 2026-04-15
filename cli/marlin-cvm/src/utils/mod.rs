use crate::configs::global::EXTRA_DECIMALS;

pub mod bandwidth;

pub fn format_usdc(value: u64) -> f64 {
    value as f64 / 10f64.powi(6)
}

pub fn format_rate(value: u64) -> f64 {
    value as f64 * 3600f64 / 10f64.powi(EXTRA_DECIMALS as i32 + 6)
}
