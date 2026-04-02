use serde_json::Value;
use diesel::prelude::*;



#[derive(Clone, Debug, diesel_derive_enum::DbEnum)]
#[ExistingTypePath = "crate::schema::sql_types::EventName"]
pub enum JobEventName {
    Opened,
    Closed,
    Deposited,
    Settled,
    MetadataUpdated,
    Withdrew,
    ReviseRateInitiated,
    ReviseRateCancelled,
    ReviseRateFinalized,
}

/// A structured representation of the data to be inserted into the `job_events` table
#[derive(Clone, Debug, Insertable, Queryable)]
#[diesel(table_name = crate::schema::job_events)]
pub struct JobEventRecord {
    pub job_id: String,
    pub event_name: JobEventName,
    pub event_data: Value,
}
