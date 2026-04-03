use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::ops::DerefMut;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use diesel::{Connection, ExpressionMethods, PgConnection, QueryDsl, RunQueryDsl};
use indexer_framework::events::JobEvent;
use indexer_framework::models::{JobEventName, JobEventRecord};
use indexer_framework::schema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc::{self, Sender};
use tokio::time::sleep;
use tokio::time::{Duration, Instant};
use tokio_retry::strategy::ExponentialBackoff;
use tokio_retry::Retry;
use tracing::{error, info, info_span, Instrument};

// IMPORTANT: do not import SystemTime, use a SystemContext

// Basic architecture:
// One task listening to job events in the db
// One task per job managing its lifetime
// One channel per job task to forward events from the main task to the job task
// A registry of active jobs with corresponding channels
// The main task starts from scratch, processes all events and never exits
// The job tasks exit only when done or on unrecoverable errors

// Main task
// Should never exit
// Read events sequentially from the DB and send on the relevant channel
// Never process the same event twice
pub async fn main_task(
    infra_provider: impl InfraProvider + Send + Sync + Clone + 'static,
    db_url: String,
    regions: &'static [String],
    rates: &'static [RegionalRates],
    gb_rates: &'static [GBRateCard],
    address_whitelist: &'static [String],
    address_blacklist: &'static [String],
    // without job_id.id set
    job_id: JobId,
    job_registry: JobRegistry,
) {
    let mut last_processed_id = -1i64;
    // Start from 1s, multiply by 2 each time, max of 64s
    let backoff_policy = ExponentialBackoff::from_millis(2)
        .factor(500)
        .max_delay(Duration::from_secs(64));

    // main task loop, implements exponential backoff on errors
    // the loop cannot error outside the retry section
    loop {
        let Ok(events) = Retry::spawn(backoff_policy.clone(), async || {
            info!("Connecting to DB endpoint...");
            let mut conn = PgConnection::establish(&db_url)
                .context("failed to connect to the provided db url")?;
            info!("Connected to DB endpoint");

            info!(after = last_processed_id, "Fetching events...");
            fetch_job_events(&mut conn, last_processed_id).await
        })
        .await
        else {
            // should never happen with our backoff policy, simply loop
            error!("backoff policy exited, should never happen!!!");
            continue;
        };

        for event in events {
            // create job task on open
            if event.event_name == JobEventName::Opened {
                // create job task
                info!(id = event.job_id as u64, "New job");

                // prepare with correct job id
                let mut job_id = job_id.clone();
                job_id.id = event.job_id as u64;

                // skip if this job has already been terminated
                if job_registry.is_job_terminated(job_id.id) {
                    info!(job_id.id, "Skipping already terminated job");
                    last_processed_id = event.id;
                    continue;
                }

                // job task already exists, should never happen!!!
                // print error for now and continue
                if job_registry
                    .active_jobs
                    .lock()
                    .unwrap()
                    .contains_key(&job_id.id)
                {
                    error!(job_id.id, "Encountered already running job");
                    last_processed_id = event.id;
                    continue;
                }

                // create channel and store sender in registry
                let (tx, rx) = mpsc::channel::<JobEventRecord>(100);
                job_registry
                    .active_jobs
                    .lock()
                    .unwrap()
                    .insert(job_id.id, tx);

                // spawn job task with channel receiver
                tokio::spawn(
                    job_task(
                        RealSystemContext {},
                        rx,
                        infra_provider.clone(),
                        job_id,
                        regions,
                        3,
                        rates,
                        gb_rates,
                        address_whitelist,
                        address_blacklist,
                        job_registry.clone(),
                    )
                    .instrument(info_span!(parent: None, "job", id = event.job_id as u64)),
                );
            }

            let sender = job_registry
                .active_jobs
                .lock()
                .unwrap()
                .get(&(event.job_id as u64))
                .map(Clone::clone);

            let event_id = event.id;

            // might happen that job is inactive here while not on contract
            // so events still come in without an active job
            // just ignore for now
            if let Some(sender) = sender {
                if let Err(err) = sender.send(event).await {
                    // might happen if job exits after we retrieved the channel
                    // just ignore for now
                    // log so we know frequency
                    error!(?err, "Channel sender error");
                }
            }

            last_processed_id = event_id;
        }
    }
}

// Job task
// Exit only when done or on unrecoverable errors
// Read events from channel and process
async fn job_task(
    context: impl SystemContext + Send + Sync,
    mut events_stream: mpsc::Receiver<JobEventRecord>,
    mut infra_provider: impl InfraProvider + Send + Sync,
    job_id: JobId,
    allowed_regions: &[String],
    infra_delay_duration: u64,
    rates: &[RegionalRates],
    gb_rates: &[GBRateCard],
    address_whitelist: &[String],
    address_blacklist: &[String],
    job_registry: JobRegistry,
) -> JobResult {
    let mut state = JobState::new(
        &context,
        job_id.clone(),
        infra_delay_duration,
        allowed_regions,
    );

    // usually tracks the result of the last log processed
    let mut job_result = JobResult::Success;

    // The processing loop follows this:
    // Keep processing events till you hit an unsuccessful processing
    //
    // If result is Internal, these are likely bugs, simply break out and leave the infra as is
    // If result is Done, the job is naturally "done", schedule termination
    // If result is Failed, the job ran into a user error, schedule termination
    // If job is insolvent, schedule termination
    //
    // Once job is successfully terminated, break out
    //
    // Insolvency and heartbeats only matter when job is not already scheduled for termination
    'event: loop {
        // compute time to insolvency
        let insolvency_duration = state.insolvency_duration();
        info!(duration = insolvency_duration.as_secs(), "Insolvency after");

        // compute infra change delay
        let infra_delay_timeout = state
            .infra_change_time
            .saturating_duration_since(Instant::now());

        // NOTE: some stuff like cargo fmt does not work inside this macro
        // extract as much stuff as possible outside it
        tokio::select! {
            // order matters
            // first process all logs because they might end up closing the job
            // then process insolvency because it might end up closing the job
            // then infra changes
            // then heartbeat
            // this ensures that any log which results in a job getting closed or insolvent
            // is given priority and the job is terminated even if other infra changes are
            // scheduled
            biased;

            // keep processing logs till the processing is successful
            log = events_stream.recv(), if job_result == JobResult::Success => {
                job_result = match log {
                    Some(log) => {
                        match parse_event(log.event_name, log.event_data) {
                            Ok(event) => state.process_event(event, rates, gb_rates, address_whitelist, address_blacklist),
                            Err(result) => result
                        }
                    }
                    None => {
                        error!("log stream ended, should never happen");
                        JobResult::Internal
                    }
                };

                match job_result {
                    // just proceed
                    JobResult::Success => {},
                    // terminate
                    JobResult::Done => {
                        state.schedule_termination(0);
                    },
                    // terminate
                    JobResult::Failed => {
                        state.schedule_termination(0);
                    },
                    // break
                    JobResult::Internal => break 'event,
                };
            }

            // insolvency check
            // enable when processing is successful
            () = sleep(insolvency_duration), if job_result == JobResult::Success => {
                state.handle_insolvency();
                job_result = JobResult::Done;
            }

            // infra delayed spin up check
            // should only happen if scheduled
            () = sleep(infra_delay_timeout), if state.infra_change_scheduled => {
                let res = state.change_infra(&mut infra_provider).await;
                if res && !state.infra_state {
                    // successful termination, exit
                    break 'event;
                }
            }

            // running instance heartbeat check
            // should only happen if infra change is not scheduled
            () = sleep(Duration::from_secs(10)), if job_result == JobResult::Success => {
                state.heartbeat_check(&mut infra_provider).await;
            }
        }
    }

    if job_result == JobResult::Done || job_result == JobResult::Failed {
        job_registry.add_terminated_job(job_id.id.clone());
    }

    job_registry.remove_active_job(job_id.id);

    job_result
}

struct JobState<'a> {
    // NOTE: not sure if dyn is a good idea, revisit later
    context: &'a (dyn SystemContext + Send + Sync),

    job_id: JobId,
    launch_delay: u64,
    allowed_regions: &'a [String],

    balance: u64,
    last_settled: Duration,
    rate: u64,
    min_rate: u64,
    bandwidth: u64,

    eif_url: String,
    instance_type: String,
    region: String,
    init_params: Box<[u8]>,

    // whether instance should exist or not
    infra_state: bool,
    // how long to wait for infra change
    infra_change_time: Instant,
    // whether to schedule change
    infra_change_scheduled: bool,
}

static EXTRA_DECIMALS: u32 = 6;

impl<'a> JobState<'a> {
    fn new(
        context: &'a (dyn SystemContext + Send + Sync),
        job_id: JobId,
        launch_delay: u64,
        allowed_regions: &'a [String],
    ) -> JobState<'a> {
        // solvency metrics
        // default of 5s
        JobState {
            context,
            job_id,
            launch_delay,
            allowed_regions,
            balance: 5,
            last_settled: context.now_timestamp(),
            rate: 1,
            min_rate: u64::MAX,
            bandwidth: 0,
            eif_url: String::new(),
            instance_type: "c6a.xlarge".to_string(),
            region: "ap-south-1".to_string(),
            init_params: Box::new([0; 0]),
            infra_state: false,
            infra_change_time: Instant::now(),
            infra_change_scheduled: false,
        }
    }

    fn insolvency_duration(&self) -> Duration {
        let now_ts = self.context.now_timestamp();

        if self.rate == 0 {
            Duration::from_secs(0)
        } else {
            // solvent for balance / rate seconds from last_settled
            Duration::from_secs(
                (self.balance as u128 * 10u128.pow(EXTRA_DECIMALS) / self.rate as u128)
                    .clamp(0, u64::MAX as u128) as u64,
            )
            .saturating_sub(now_ts.saturating_sub(self.last_settled))
        }
    }

    async fn heartbeat_check(&mut self, mut infra_provider: impl InfraProvider) {
        let Ok(is_enclave_running) = infra_provider
            .check_enclave_running(&self.job_id, &self.region)
            .await
            .inspect_err(|err| error!(?err, "Failed to retrieve enclave state"))
        else {
            return;
        };

        if is_enclave_running {
            return;
        }

        info!("Enclave not running, scheduling new launch");
        self.schedule_launch(0);
    }

    fn handle_insolvency(&mut self) {
        info!("INSOLVENCY");
        self.schedule_termination(0);
    }

    fn schedule_launch(&mut self, delay: u64) {
        self.infra_change_scheduled = true;
        self.infra_change_time = Instant::now()
            .checked_add(Duration::from_secs(delay))
            .unwrap();
        self.infra_state = true;
        info!("Instance launch scheduled");
    }

    fn schedule_termination(&mut self, delay: u64) {
        self.infra_change_scheduled = true;
        self.infra_change_time = Instant::now()
            .checked_add(Duration::from_secs(delay))
            .unwrap();
        self.infra_state = false;
        info!("Instance termination scheduled");
    }

    // exists to implement rescheduling of infra changes on errors
    async fn change_infra(&mut self, infra_provider: impl InfraProvider) -> bool {
        let res = self.change_infra_impl(infra_provider).await;
        if res {
            // successful
            self.infra_change_scheduled = false;
        } else {
            // failed, reschedule with small delay
            self.infra_change_time = Instant::now() + Duration::from_secs(2);
        }

        res
    }

    // on errors, return false, will be rescheduled after a short delay
    async fn change_infra_impl(&mut self, mut infra_provider: impl InfraProvider) -> bool {
        if self.infra_state {
            // launch mode
            let res = infra_provider
                .spin_up(
                    &self.job_id,
                    self.instance_type.as_str(),
                    &self.region,
                    0,
                    0,
                    self.bandwidth,
                    &self.eif_url,
                    &self.init_params,
                )
                .await;
            if let Err(err) = res {
                error!(?err, "Instance launch failed");
                return false;
            }

            true
        } else {
            // terminate mode
            let res = infra_provider
                .spin_down(&self.job_id, &self.region, self.bandwidth)
                .await;
            if let Err(err) = res {
                error!(?err, "Failed to terminate instance");
                return false;
            }

            true
        }
    }

    // return
    // JobResult::Success on successful processing of a log
    // JobResult::Done on successful processing of a log which ends a job
    // JobResult::Failed on unrecoverable errors
    // JobResult::Internal on internal errors, usually bugs
    pub fn process_event(
        &mut self,
        event: JobEvent,
        rates: &[RegionalRates],
        gb_rates: &[GBRateCard],
        address_whitelist: &[String],
        address_blacklist: &[String],
    ) -> JobResult {
        info!(event = ?event, "New event");

        // NOTE: jobs should be killed fully if any individual event would kill it
        // regardless of future events
        // helps preserve consistency on restarts where events are procesed all at once
        // e.g. do not spin up if job goes below min_rate and then goes above min_rate

        match event {
            JobEvent::Opened(event) => {
                info!(event.metadata, event.owner, event.provider, "OPENED");

                // handle metadata
                if let Err(err) = self
                    .decode_metadata(event.metadata, false)
                    .context("failed to decode metadata")
                {
                    error!(?err);
                    return JobResult::Failed;
                }

                // check if region is supported
                if !self.allowed_regions.contains(&self.region) {
                    error!(self.region, "Region not supported, exiting job");
                    return JobResult::Failed;
                }

                // blacklist whitelist check
                let allowed =
                    whitelist_blacklist_check(event.owner, address_whitelist, address_blacklist);
                if !allowed {
                    error!("failed whitelist/blacklist check");
                    // blacklisted or not whitelisted address
                    return JobResult::Failed;
                }

                // check if instance type is supported
                // set min rate if so
                let mut supported = false;
                for entry in rates {
                    if entry.region == self.region {
                        for card in &entry.rate_cards {
                            if card.instance == self.instance_type {
                                self.min_rate = card.min_rate;
                                supported = true;
                                break;
                            }
                        }
                        break;
                    }
                }

                if !supported {
                    error!(self.instance_type, "Instance type not supported");
                    return JobResult::Failed;
                }

                JobResult::Success
            }
            JobEvent::Settled(event) => {
                info!(
                    event.amount,
                    self.rate,
                    self.balance,
                    last_settled = self.last_settled.as_secs(),
                    "SETTLED",
                );
                // update solvency metrics
                self.balance -= event.amount;
                self.last_settled = Duration::from_secs(event.timestamp);
                info!(
                    event.amount,
                    self.rate,
                    self.balance,
                    last_settled = self.last_settled.as_secs(),
                    "SETTLED",
                );

                JobResult::Success
            }
            JobEvent::Closed(_) => JobResult::Done,
            JobEvent::Deposited(event) => {
                info!(
                    event.amount,
                    self.rate,
                    self.balance,
                    last_settled = self.last_settled.as_secs(),
                    "DEPOSITED",
                );
                // update solvency metrics
                self.balance += event.amount;
                info!(
                    event.amount,
                    self.rate,
                    self.balance,
                    last_settled = self.last_settled.as_secs(),
                    "DEPOSITED",
                );

                JobResult::Success
            }
            JobEvent::Withdrew(event) => {
                info!(
                    event.amount,
                    self.rate,
                    self.balance,
                    last_settled = self.last_settled.as_secs(),
                    "WITHDREW",
                );
                // update solvency metrics
                self.balance -= event.amount;
                info!(
                    event.amount,
                    self.rate,
                    self.balance,
                    last_settled = self.last_settled.as_secs(),
                    "WITHDREW",
                );

                JobResult::Success
            }
            JobEvent::RateRevised(event) => {
                info!(
                    self.rate,
                    self.bandwidth,
                    event.new_rate,
                    self.balance,
                    last_settled = self.last_settled.as_secs(),
                    "RATE_REVISED",
                );

                self.rate = event.new_rate;
                if self.rate < self.min_rate {
                    info!("Revised job rate below min rate, shut down");
                    return JobResult::Done;
                }

                // compute bandwidth
                for entry in gb_rates {
                    if entry.region_code == self.region {
                        let gb_cost = entry.rate;
                        let bandwidth_rate = self.rate - self.min_rate;

                        self.bandwidth = ((bandwidth_rate as u128).saturating_mul(1024 * 1024 * 8)
                            / gb_cost as u128)
                            .clamp(0, u64::MAX as u128)
                            as u64;
                        break;
                    }
                }

                // schedule launch
                self.schedule_launch(self.launch_delay);

                info!(
                    self.rate,
                    self.bandwidth,
                    self.balance,
                    last_settled = self.last_settled.as_secs(),
                    "RATE_REVISED",
                );

                JobResult::Success
            }
            JobEvent::MetadataUpdated(event) => {
                info!(event.metadata, "METADATA_UPDATED");

                if let Err(err) = self.decode_metadata(event.metadata, true) {
                    error!(id = event.job_id, ?err);
                    return JobResult::Failed;
                }

                // schedule change immediately if not already scheduled
                if !self.infra_change_scheduled {
                    self.schedule_launch(0);
                }

                JobResult::Success
            }
        }
    }

    fn decode_metadata(&mut self, metadata: String, update: bool) -> Result<()> {
        let metadata_json =
            serde_json::from_str::<Value>(&metadata).context("Error reading metadata")?;

        let Some(instance) = metadata_json["instance"].as_str() else {
            return Err(anyhow!("Instance type not set"));
        };
        if update && self.instance_type != instance {
            return Err(anyhow!("Instance type change not allowed"));
        } else {
            self.instance_type = instance.to_string();
            info!(self.instance_type, "Instance type set");
        }

        let Some(region) = metadata_json["region"].as_str() else {
            return Err(anyhow!("Job region not set"));
        };
        if update && self.region != region {
            return Err(anyhow!("Region change not allowed"));
        } else {
            self.region = region.to_string();
            info!(self.region, "Job region set");
        }

        let Some(url) = metadata_json["url"].as_str() else {
            return Err(anyhow!("EIF url not found! Exiting job"));
        };
        self.eif_url = url.to_string();

        let Ok(init_params) =
            BASE64_STANDARD.decode(metadata_json["init_params"].as_str().unwrap_or(""))
        else {
            return Err(anyhow!("failed to decode init params"));
        };
        self.init_params = init_params.into_boxed_slice();

        Ok(())
    }
}

// Registry to track jobs
#[derive(Clone)]
pub struct JobRegistry {
    active_jobs: Arc<Mutex<HashMap<u64, Sender<JobEventRecord>>>>,
    terminated_jobs: Arc<Mutex<HashSet<u64>>>,
    db_url: String,
}

impl JobRegistry {
    pub async fn new(db_url: String) -> Result<Self> {
        Ok(JobRegistry {
            active_jobs: Arc::new(Mutex::new(HashMap::new())),
            terminated_jobs: Arc::new(Mutex::new(HashSet::new())),
            db_url,
        })
    }

    fn add_terminated_job(&self, job_id: u64) {
        self.terminated_jobs.lock().unwrap().insert(job_id);
    }

    fn remove_active_job(&self, job_id: u64) {
        self.active_jobs.lock().unwrap().remove(&job_id);
    }

    fn is_job_terminated(&self, job_id: u64) -> bool {
        let Ok(mut conn) = PgConnection::establish(&self.db_url)
            .context("failed to connect to the provided db url")
            .inspect_err(|e| error!(?e))
        else {
            // conservative answer
            return false;
        };

        schema::terminated_jobs::table
            .count()
            .filter(schema::terminated_jobs::job_id.eq(job_id as i64))
            .get_result(&mut conn)
            == Ok(1)
    }

    async fn save_to_disk(&self) -> Result<usize> {
        // swap to get the terminated jobs and start a new set
        // WARN: the terminated jobs are simply dropped on errors
        // it is fine for now since we only use it as an optimization
        let mut job_ids = HashSet::new();
        std::mem::swap(
            self.terminated_jobs.lock().unwrap().deref_mut(),
            &mut job_ids,
        );

        if job_ids.is_empty() {
            return Ok(0);
        }

        let mut conn = PgConnection::establish(&self.db_url)
            .context("failed to connect to the provided db url")?;

        diesel::insert_into(schema::terminated_jobs::table)
            .values(
                job_ids
                    .into_iter()
                    .map(|x| schema::terminated_jobs::job_id.eq(x as i64))
                    .collect::<Vec<_>>(),
            )
            .on_conflict_do_nothing()
            .execute(&mut conn)
            .context("failed to insert terminated jobs")
    }

    pub async fn run_periodic_save(self, interval_secs: u64) {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;
            match self.save_to_disk().await {
                Ok(inserted) => {
                    info!("Job registry saved to disk: {} terminated jobs", inserted);
                }
                Err(e) => {
                    error!("Failed to save job registry: {:?}", e);
                }
            }
        }
    }
}

async fn fetch_job_events(
    conn: &mut PgConnection,
    last_processed_id: i64,
) -> Result<Vec<JobEventRecord>> {
    schema::job_events::table
        .select(schema::job_events::all_columns)
        .filter(schema::job_events::id.gt(last_processed_id))
        .order_by(schema::job_events::id.asc())
        .limit(1000)
        .load::<JobEventRecord>(conn)
        .context("failed to load events")
}

fn parse_event(event_name: JobEventName, event_data: Value) -> Result<JobEvent, JobResult> {
    match event_name {
        JobEventName::Opened => Ok(JobEvent::Opened(
            serde_json::from_value(event_data.clone())
                .inspect_err(|err| error!(?err, data = ?event_data, "OPENED: Decode failure"))
                .map_err(|_| JobResult::Internal)?,
        )),
        JobEventName::Closed => Ok(JobEvent::Closed(
            serde_json::from_value(event_data.clone())
                .inspect_err(|err| error!(?err, data = ?event_data, "CLOSED: Decode failure"))
                .map_err(|_| JobResult::Internal)?,
        )),
        JobEventName::Deposited => Ok(JobEvent::Deposited(
            serde_json::from_value(event_data.clone())
                .inspect_err(|err| error!(?err, data = ?event_data, "DEPOSITED: Decode failure"))
                .map_err(|_| JobResult::Internal)?,
        )),
        JobEventName::Settled => Ok(JobEvent::Settled(
            serde_json::from_value(event_data.clone())
                .inspect_err(|err| error!(?err, data = ?event_data, "SETTLED: Decode failure"))
                .map_err(|_| JobResult::Internal)?,
        )),
        JobEventName::MetadataUpdated => Ok(JobEvent::MetadataUpdated(
            serde_json::from_value(event_data.clone())
                .inspect_err(
                    |err| error!(?err, data = ?event_data, "METADATA_UPDATED: Decode failure"),
                )
                .map_err(|_| JobResult::Internal)?,
        )),
        JobEventName::Withdrew => Ok(JobEvent::Withdrew(
            serde_json::from_value(event_data.clone())
                .inspect_err(|err| error!(?err, data = ?event_data, "WITHDREW: Decode failure"))
                .map_err(|_| JobResult::Internal)?,
        )),
        JobEventName::RateRevised => Ok(JobEvent::RateRevised(
            serde_json::from_value(event_data.clone())
                .inspect_err(|err| error!(?err, data = ?event_data, "RATE_REVISED: Decode failure"))
                .map_err(|_| JobResult::Internal)?,
        )),
    }
}

fn whitelist_blacklist_check(
    owner: String,
    address_whitelist: &[String],
    address_blacklist: &[String],
) -> bool {
    // check whitelist
    if !address_whitelist.is_empty() {
        info!("Checking address whitelist...");
        if address_whitelist.iter().any(|s| s == &owner) {
            info!("ADDRESS ALLOWED!");
        } else {
            info!("ADDRESS NOT ALLOWED!");
            return false;
        }
    }

    // check blacklist
    if !address_blacklist.is_empty() {
        info!("Checking address blacklist...");
        if address_blacklist.iter().any(|s| s == &owner) {
            info!("ADDRESS NOT ALLOWED!");
            return false;
        } else {
            info!("ADDRESS ALLOWED!");
        }
    }

    true
}

#[derive(PartialEq, Debug)]
enum JobResult {
    // success
    Success,
    // done, should still terminate instance, if any
    Done,
    // error, should terminate instance, if any
    Failed,
    // error, likely internal bug, exit but do not terminate instance
    Internal,
}

// Identify jobs not only by the id, but also by the operator, contract and the chain
// This is needed to cleanly support multiple operators/contracts/chains at the infra level
#[derive(Clone)]
pub struct JobId {
    pub id: u64,
    pub operator: String,
    pub contract: String,
    pub chain: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RegionalRates {
    pub region: String,
    pub rate_cards: Vec<RateCard>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RateCard {
    pub instance: String,
    pub min_rate: u64,
    pub cpu: u32,
    pub memory: u32,
    pub arch: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GBRateCard {
    pub region: String,
    pub region_code: String,
    pub rate: u64,
}

pub trait InfraProvider {
    fn spin_up(
        &mut self,
        job: &JobId,
        instance_type: &str,
        region: &str,
        req_mem: i64,
        req_vcpu: i32,
        bandwidth: u64,
        image_url: &str,
        init_params: &[u8],
    ) -> impl Future<Output = Result<()>> + Send;

    fn spin_down(
        &mut self,
        job: &JobId,
        region: &str,
        bandwidth: u64,
    ) -> impl Future<Output = Result<()>> + Send;

    fn get_job_ip(&self, job: &JobId, region: &str) -> impl Future<Output = Result<String>> + Send;

    fn check_enclave_running(
        &mut self,
        job: &JobId,
        region: &str,
    ) -> impl Future<Output = Result<bool>> + Send;
}

impl<T> InfraProvider for &mut T
where
    T: InfraProvider + Send + Sync,
{
    async fn spin_up(
        &mut self,
        job: &JobId,
        instance_type: &str,
        region: &str,
        req_mem: i64,
        req_vcpu: i32,
        bandwidth: u64,
        image_url: &str,
        init_params: &[u8],
    ) -> Result<()> {
        (**self)
            .spin_up(
                job,
                instance_type,
                region,
                req_mem,
                req_vcpu,
                bandwidth,
                image_url,
                init_params,
            )
            .await
    }

    async fn spin_down(&mut self, job: &JobId, region: &str, bandwidth: u64) -> Result<()> {
        (**self).spin_down(job, region, bandwidth).await
    }

    async fn get_job_ip(&self, job: &JobId, region: &str) -> Result<String> {
        (**self).get_job_ip(job, region).await
    }

    async fn check_enclave_running(&mut self, job: &JobId, region: &str) -> Result<bool> {
        (**self).check_enclave_running(job, region).await
    }
}

// Trait to encapsulate behavior that should be simulated in tests
trait SystemContext {
    fn now_timestamp(&self) -> Duration;
}

struct RealSystemContext {}

impl SystemContext for RealSystemContext {
    fn now_timestamp(&self) -> Duration {
        use std::time::SystemTime;
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
    }
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------
//                                                                  TESTS
// --------------------------------------------------------------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};

    use alloy_primitives::hex::FromHex;
    use alloy_primitives::{B256, U256};
    use indexer_framework::models::JobEventRecord;
    use tokio::sync::mpsc;
    use tokio::time::{sleep, Duration, Instant};

    use crate::market;
    use crate::test::{
        self, compute_address_word, compute_instance_id, Action, TestAws, TestAwsOutcome,
    };

    use super::{JobResult, SystemContext};

    struct TestSystemContext {
        start: Instant,
    }

    impl SystemContext for TestSystemContext {
        fn now_timestamp(&self) -> Duration {
            Instant::now() - self.start
        }
    }

    #[cfg(test)]
    impl market::JobRegistry {
        pub fn new_test() -> Self {
            market::JobRegistry {
                active_jobs: Arc::new(Mutex::new(HashMap::new())),
                terminated_jobs: Arc::new(Mutex::new(HashSet::new())),
                db_url: "db_url".to_string(),
            }
        }
    }

    struct JobManagerParams {
        job_id: market::JobId,
        allowed_regions: Vec<String>,
        address_whitelist: Vec<String>,
        address_blacklist: Vec<String>,
    }

    struct TestResults {
        res: JobResult,
        outcomes: Vec<TestAwsOutcome>,
    }

    async fn run_test(
        start_time: Instant,
        logs: Vec<(u64, Action)>,
        job_manager_params: JobManagerParams,
        test_results: TestResults,
    ) {
        let context = TestSystemContext { start: start_time };

        let job_num = B256::from_hex(&job_manager_params.job_id.id).unwrap();
        let job_logs: Vec<(u64, JobEventRecord)> = logs
            .into_iter()
            .enumerate()
            .map(|x| (x.1 .0, test::get_event(x.1 .1, x.0 as i64, job_num)))
            .collect();

        let (tx, rx) = mpsc::channel::<JobEventRecord>(10);
        let mut aws: TestAws = Default::default();
        let job_registry = market::JobRegistry::new_test();

        tokio::spawn(async move {
            for (moment, event) in job_logs {
                let delay = start_time + Duration::from_secs(moment) - Instant::now();
                sleep(delay).await;
                if let Err(err) = tx.send(event).await {
                    println!("{}", err);
                }
            }
        });

        let res = market::job_task(
            context,
            rx,
            &mut aws,
            job_manager_params.job_id,
            &job_manager_params.allowed_regions,
            300,
            &test::get_rates(),
            &test::get_gb_rates(),
            &job_manager_params.address_whitelist,
            &job_manager_params.address_blacklist,
            job_registry,
        )
        .await;

        assert!(aws.instances.is_empty());

        assert_eq!(res, test_results.res);
        assert_eq!(aws.outcomes, test_results.outcomes);
    }

    #[tokio::test(start_paused = true)]
    async fn test_instance_launch_after_delay_on_spin_up() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (301, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(301),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_init_params() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"init_params\":\"c29tZSBwYXJhbXM=\"}".to_string(),31000000000000u64,31000u64,0)),
            (301, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: b"some params".to_vec().into_boxed_slice(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(301),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_instance_launch_with_debug_mode_on_spin_up() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"debug\":true}".to_string(),31000000000000u64,31000u64,0)),
            (301, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(301),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_instance_launch_after_delay_on_spin_up_with_specific_family() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (301, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(301),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_deposit_withdraw_settle() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (40, Action::Deposit(500)),
            (60, Action::Withdraw(500)),
            (100, Action::Settle(2, 6)),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_revise_rate_cancel() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (50, Action::ReviseRateInitiated(32000000000000u64)),
            (100, Action::ReviseRateFinalized(32000000000000u64)),
            (150, Action::ReviseRateInitiated(60000000000000u64)),
            (200, Action::ReviseRateCancelled),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_unsupported_region() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-east-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Failed,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id,
                region: "ap-east-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_region_not_found() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Failed,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id,
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_instance_type_not_found() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Failed,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id,
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_unsupported_instance() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.vsmall\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Failed,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id,
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_eif_url_not_found() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"instance\":\"c6a.vsmall\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Failed,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id,
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_min_rate() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),29000000000000u64,31000u64,0)),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id,
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_rate_exceed_balance() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,0u64,0)),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id,
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    // NOTE: This scenario should be impossible based on how the contract should be written
    // Nevertheless, the cp should handle it to be defensive, so we test
    #[tokio::test(start_paused = true)]
    async fn test_withdrawal_exceed_rate() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (350, Action::Withdraw(30000u64)),
            (500, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(350),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_revise_rate_lower_higher() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (350, Action::ReviseRateInitiated(29000000000000u64)),
            (400, Action::ReviseRateFinalized(29000000000000u64)),
            (450, Action::ReviseRateInitiated(31000000000000u64)),
            (500, Action::ReviseRateFinalized(31000000000000u64)),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(350),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_address_whitelisted() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (500, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![compute_address_word("owner")],
            address_blacklist: vec![],
        };

        // real owner of the job is compute_address_word("owner")
        // expected to deploy

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(500),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_address_not_whitelisted() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (500, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![compute_address_word("notowner")],
            address_blacklist: vec![],
        };

        // real owner of the job is compute_address_word("owner")
        // expected to not deploy

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id,
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_address_blacklisted() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (500, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![compute_address_word("owner")],
        };

        // real owner of the job is compute_address_word("owner")
        // expected to not deploy

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(0),
                job: job_id,
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_address_not_blacklisted() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (500, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![compute_address_word("notowner")],
        };

        // real owner of the job is compute_address_word("owner")
        // expected to deploy

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(500),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    // Tests for whitelist blacklist checks
    #[tokio::test]
    async fn test_whitelist_blacklist_check_no_list() {
        let address_whitelist = vec![];
        let address_blacklist = vec![];

        assert!(market::whitelist_blacklist_check(
            compute_address_word("owner"),
            &address_whitelist,
            &address_blacklist
        ));
    }

    #[tokio::test]
    async fn test_whitelist_blacklist_check_whitelisted() {
        let address_whitelist = vec![
            compute_address_word("owner"),
            compute_address_word("notowner"),
        ];
        let address_blacklist = vec![];

        assert!(market::whitelist_blacklist_check(
            compute_address_word("owner"),
            &address_whitelist,
            &address_blacklist
        ));
    }

    #[tokio::test]
    async fn test_whitelist_blacklist_check_not_whitelisted() {
        let address_whitelist = vec![
            compute_address_word("notownereither"),
            compute_address_word("notowner"),
        ];
        let address_blacklist = vec![];

        assert!(!market::whitelist_blacklist_check(
            compute_address_word("owner"),
            &address_whitelist,
            &address_blacklist
        ));
    }

    #[tokio::test]
    async fn test_whitelist_blacklist_check_blacklisted() {
        let address_whitelist = vec![];
        let address_blacklist = vec![
            compute_address_word("owner"),
            compute_address_word("notowner"),
        ];

        assert!(!market::whitelist_blacklist_check(
            compute_address_word("owner"),
            &address_whitelist,
            &address_blacklist
        ));
    }

    #[tokio::test]
    async fn test_whitelist_blacklist_check_not_blacklisted() {
        let address_whitelist = vec![];
        let address_blacklist = vec![
            compute_address_word("notownereither"),
            compute_address_word("notowner"),
        ];

        assert!(market::whitelist_blacklist_check(
            compute_address_word("owner"),
            &address_whitelist,
            &address_blacklist
        ));
    }

    #[tokio::test]
    async fn test_whitelist_blacklist_check_neither() {
        let address_whitelist = vec![
            compute_address_word("notownereither"),
            compute_address_word("notowner"),
        ];
        let address_blacklist = vec![
            compute_address_word("definitelynotownereither"),
            compute_address_word("definitelynotowner"),
        ];

        assert!(!market::whitelist_blacklist_check(
            compute_address_word("owner"),
            &address_whitelist,
            &address_blacklist
        ));
    }

    #[tokio::test]
    async fn test_whitelist_blacklist_check_both() {
        let address_whitelist = vec![
            compute_address_word("owner"),
            compute_address_word("notowner"),
        ];
        let address_blacklist = vec![
            compute_address_word("owner"),
            compute_address_word("definitelynotowner"),
        ];

        assert!(!market::whitelist_blacklist_check(
            compute_address_word("owner"),
            &address_whitelist,
            &address_blacklist
        ));
    }

    #[test]
    fn test_parse_compute_rates() {
        let contents = "[{\"region\": \"ap-south-1\", \"rate_cards\": [{\"instance\": \"c6a.48xlarge\", \"min_rate\": \"2469600000000000000000\", \"cpu\": 192, \"memory\": 384, \"arch\": \"amd64\"}, {\"instance\": \"m7g.xlarge\", \"min_rate\": \"150000000\", \"cpu\": 4, \"memory\": 8, \"arch\": \"arm64\"}]}]";
        let rates: Vec<market::RegionalRates> = serde_json::from_str(contents).unwrap();

        assert_eq!(rates.len(), 1);
        assert_eq!(
            rates[0],
            market::RegionalRates {
                region: "ap-south-1".to_owned(),
                rate_cards: vec![
                    market::RateCard {
                        instance: "c6a.48xlarge".to_owned(),
                        min_rate: U256::from_str_radix("2469600000000000000000", 10).unwrap(),
                        cpu: 192,
                        memory: 384,
                        arch: String::from("amd64")
                    },
                    market::RateCard {
                        instance: "m7g.xlarge".to_owned(),
                        min_rate: U256::from(150000000u64),
                        cpu: 4,
                        memory: 8,
                        arch: String::from("arm64")
                    }
                ]
            }
        );
    }

    #[test]
    fn test_parse_bandwidth_rates() {
        let contents = "[{\"region\": \"Asia South (Mumbai)\", \"region_code\": \"ap-south-1\", \"rate\": \"8264900000000000000000\"}, {\"region\": \"US East (N.Virginia)\", \"region_code\": \"us-east-1\", \"rate\": \"10000\"}]";
        let rates: Vec<market::GBRateCard> = serde_json::from_str(contents).unwrap();

        assert_eq!(rates.len(), 2);
        assert_eq!(
            rates[0],
            market::GBRateCard {
                region: "Asia South (Mumbai)".to_owned(),
                region_code: "ap-south-1".to_owned(),
                rate: U256::from_str_radix("8264900000000000000000", 10).unwrap(),
            }
        );
        assert_eq!(
            rates[1],
            market::GBRateCard {
                region: "US East (N.Virginia)".to_owned(),
                region_code: "us-east-1".to_owned(),
                rate: U256::from(10000u16),
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_eif_update_before_spin_up() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (100, Action::MetadataUpdated("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/updated-enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string())),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/updated-enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_debug_update_before_spin_up() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"debug\":true}".to_string(),31000000000000u64,31000u64,0)),
            (100, Action::MetadataUpdated("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string())),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_other_metadata_update_before_spin_up() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            // instance type has also been updated in the metadata. should fail this job.
            (100, Action::MetadataUpdated("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/updated-enclave.eif\",\"instance\":\"c6a.large\",\"memory\":4096,\"vcpu\":2}".to_string())),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Failed,
            outcomes: vec![TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                time: start_time + Duration::from_secs(100),
                job: job_id,
                region: "ap-south-1".into(),
            })],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_init_params_update_before_spin_up() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (100, Action::MetadataUpdated("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"init_params\":\"c29tZSBwYXJhbXM=\"}".to_string())),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: b"some params".to_vec().into_boxed_slice(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_metadata_update_event_with_no_updates_before_spin_up() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (100, Action::MetadataUpdated("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string())),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_eif_update_after_spin_up() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (400, Action::MetadataUpdated("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/updated-enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string())),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(400),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/updated-enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_other_metadata_update_after_spin_up() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            // init params have also been updated in the metadata. should fail this job.
            (400, Action::MetadataUpdated("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/updated-enclave.eif\",\"instance\":\"c6a.large\",\"memory\":4096,\"vcpu\":2}".to_string())),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Failed,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(400),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_init_params_update_after_spin_up() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (400, Action::MetadataUpdated("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2,\"init_params\":\"c29tZSBwYXJhbXM=\"}".to_string())),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(400),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: b"some params".to_vec().into_boxed_slice(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_metadata_update_event_with_no_updates_after_spin_up() {
        let start_time = Instant::now();
        let job_id = 1;

        let logs = vec![
            (0, Action::Open("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string(),31000000000000u64,31000u64,0)),
            (400, Action::MetadataUpdated("{\"region\":\"ap-south-1\",\"url\":\"https://example.com/enclave.eif\",\"instance\":\"c6a.xlarge\",\"memory\":4096,\"vcpu\":2}".to_string())),
            (505, Action::Close),
        ];

        let job_manager_params = JobManagerParams {
            job_id: market::JobId {
                id: job_id.clone(),
                operator: "abc".into(),
                contract: "xyz".into(),
                chain: "123".into(),
            },
            allowed_regions: vec!["ap-south-1".to_owned()],
            address_whitelist: vec![],
            address_blacklist: vec![],
        };

        let test_results = TestResults {
            res: JobResult::Done,
            outcomes: vec![
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(300),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinUp(test::SpinUpOutcome {
                    time: start_time + Duration::from_secs(400),
                    job: job_id.clone(),
                    instance_type: "c6a.xlarge".into(),
                    region: "ap-south-1".into(),
                    req_mem: 4096,
                    req_vcpu: 2,
                    bandwidth: 76,
                    image_url: "https://example.com/enclave.eif".into(),
                    init_params: [].into(),
                    contract_address: "xyz".into(),
                    chain_id: "123".into(),
                    instance_id: compute_instance_id(0),
                }),
                TestAwsOutcome::SpinDown(test::SpinDownOutcome {
                    time: start_time + Duration::from_secs(505),
                    job: job_id,
                    region: "ap-south-1".into(),
                }),
            ],
        };

        run_test(start_time, logs, job_manager_params, test_results).await;
    }
}
