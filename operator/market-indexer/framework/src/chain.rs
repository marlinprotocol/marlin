use anyhow::Result;

use crate::events::JobEvent;

/// Trait every chain must implement
pub trait ChainHandler {
    /// Fetch latest block/checkpoint/slot for the chain
    fn fetch_latest_block(&mut self) -> Result<u64>;

    /// Fetch logs
    fn fetch_logs(&self, start_block: u64, end_block: u64) -> Result<Vec<JobEvent>>;
}
