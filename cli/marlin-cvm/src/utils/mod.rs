use crate::configs::global::EXTRA_DECIMALS;

pub mod bandwidth;

pub fn format_usdc(value: u64) -> f64 {
    value as f64 / 10f64.powi(6)
}
