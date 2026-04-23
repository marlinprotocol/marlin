use serde::{Deserialize, Serialize};

/// Define the event structs we want to capture and store in the database
#[derive(Debug, Serialize, Deserialize)]
pub struct JobOpened {
    pub job_id: u64,
    pub timestamp: u64,
    pub metadata: Vec<u8>,
    pub owner: String,
    pub provider: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JobClosed {
    pub job_id: u64,
    pub timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JobDeposited {
    pub job_id: u64,
    pub timestamp: u64,
    pub amount: u64,
    pub from: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JobSettled {
    pub job_id: u64,
    pub timestamp: u64,
    pub amount: u64,
    pub to: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JobMetadataUpdated {
    pub job_id: u64,
    pub timestamp: u64,
    pub metadata: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JobWithdrew {
    pub job_id: u64,
    pub timestamp: u64,
    pub amount: u64,
    pub to: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JobRateRevised {
    pub job_id: u64,
    pub timestamp: u64,
    pub new_rate: u64,
}

#[derive(Debug)]
pub enum JobEvent {
    Opened(JobOpened),
    Closed(JobClosed),
    Deposited(JobDeposited),
    Withdrew(JobWithdrew),
    Settled(JobSettled),
    RateRevised(JobRateRevised),
    MetadataUpdated(JobMetadataUpdated),
}
