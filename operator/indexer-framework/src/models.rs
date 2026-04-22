use diesel::prelude::*;

#[derive(Clone, Debug, diesel_derive_enum::DbEnum, PartialEq)]
#[ExistingTypePath = "crate::schema::sql_types::EventName"]
#[DbValueStyle = "PascalCase"]
pub enum JobEventName {
    Opened,
    Closed,
    Deposited,
    Settled,
    MetadataUpdated,
    Withdrew,
    RateRevised,
}

/// A structured representation of the data to be queried from the `job_events` table
#[derive(Clone, Debug, Queryable)]
#[diesel(table_name = crate::schema::job_events)]
pub struct JobEventRecord {
    pub id: i64,
    pub job_id: i64,
    pub event_name: JobEventName,
    pub event_data: Vec<u8>,
}

/// A structured representation of the data to be inserted into the `job_events` table
#[derive(Clone, Debug, Insertable)]
#[diesel(table_name = crate::schema::job_events)]
pub struct NewJobEventRecord {
    pub job_id: i64,
    pub event_name: JobEventName,
    pub event_data: Vec<u8>,
}
