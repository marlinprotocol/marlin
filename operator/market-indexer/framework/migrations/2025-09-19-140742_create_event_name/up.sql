CREATE TYPE event_name AS ENUM (
'Opened', 
'Closed', 
'Deposited', 
'Settled', 
'MetadataUpdated', 
'Withdrew', 
'ReviseRateInitiated',
'ReviseRateCancelled',
'ReviseRateFinalized'
);