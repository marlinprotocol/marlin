use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use aya::maps::HashMap;
use clap::Parser;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

const START_CAPACITY: u64 = 1 << 20; // 1 MiB

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "/sys/fs/bpf/xdp/globals/config_map")]
    config_map_path: String,

    #[arg(long, default_value = "/sys/fs/bpf/xdp/globals/state_map")]
    state_map_path: String,

    #[arg(long, default_value = "ratelimits.json")]
    file: PathBuf,

    #[arg(long, default_value = "0.0.0.0:3000")]
    addr: String,
}

#[derive(Clone)]
struct AppState {
    config_map_path: String,
    state_map_path: String,
    file_path: PathBuf,
    // Mutex to synchronize access to the file and maps
    lock: Arc<Mutex<()>>,
}

#[derive(Deserialize)]
struct AddRequest {
    ip: Ipv4Addr,
    rate: u64, // bytes per second
}

#[derive(Deserialize)]
struct RemoveRequest {
    ip: Ipv4Addr,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct RateConfig {
    rate: u64, // bytes per 2^30 ns
    fill_time: u64, // multiples of 2^10 ns
}

// SAFETY: RateConfig is a POD type
unsafe impl aya::Pod for RateConfig {}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct BucketState {
    lock: u32, // bpf_spin_lock is u32
    last_time: u64, // multiples of 2^10 ns
    tokens: u64,
}

// SAFETY: BucketState is a POD type
unsafe impl aya::Pod for BucketState {}

#[derive(Serialize, Deserialize, Clone)]
struct Entry {
    ip: Ipv4Addr,
    rate: u64, // bytes per 2^30 ns
    fill_time: u64, // multiples of 2^10 ns
}

#[derive(Serialize)]
struct StatusEntry {
    ip: Ipv4Addr,
    rate: u64, // bytes per 2^30 ns
    fill_time: u64, // multiples of 2^10 ns
    tokens: Option<u64>,
    last_time: Option<u64>, // multiples of 2^10 ns
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    // Load initial entries
    info!("Loading initial entries from {:?}", args.file);
    if let Err(e) = load_entries(&args.config_map_path, &args.state_map_path, &args.file) {
        warn!("Failed to load initial entries: {}", e);
        // Continue anyway? Or exit? Let's exit if we can't load the state we're supposed to have.
        // But maybe the file doesn't exist yet, which load_entries handles gracefully (returns empty).
        // If it returns error, it's a real error.
        return Err(e);
    }

    let state = AppState {
        config_map_path: args.config_map_path,
        state_map_path: args.state_map_path,
        file_path: args.file,
        lock: Arc::new(Mutex::new(())),
    };

    let app = Router::new()
        .route("/add", post(add_handler))
        .route("/remove", post(remove_handler))
        .route("/list", get(list_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr: SocketAddr = args.addr.parse().context("Invalid address format")?;
    info!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn add_handler(
    State(state): State<AppState>,
    Json(req): Json<AddRequest>,
) -> Result<Json<String>, (StatusCode, String)> {
    let _guard = state.lock.lock().await;

    match add_entry(
        &state.config_map_path,
        &state.state_map_path,
        &state.file_path,
        req.ip,
        req.rate,
    ) {
        Ok(_) => Ok(Json(format!("Added {}", req.ip))),
        Err(e) => {
            warn!("Failed to add entry: {:#}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

async fn remove_handler(
    State(state): State<AppState>,
    Json(req): Json<RemoveRequest>,
) -> Result<Json<String>, (StatusCode, String)> {
    let _guard = state.lock.lock().await;

    match remove_entry(
        &state.config_map_path,
        &state.state_map_path,
        &state.file_path,
        req.ip,
    ) {
        Ok(_) => Ok(Json(format!("Removed {}", req.ip))),
        Err(e) => {
            warn!("Failed to remove entry: {:#}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

async fn list_handler(
    State(state): State<AppState>,
) -> Result<Json<Vec<StatusEntry>>, (StatusCode, String)> {
    // Read from maps to get live status including tokens
    let _guard = state.lock.lock().await;

    match get_list_from_maps(&state.config_map_path, &state.state_map_path) {
        Ok(entries) => Ok(Json(entries)),
        Err(e) => {
            warn!("Failed to list entries: {:#}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

// --- Helper functions (synchronous logic, but run inside async handlers) ---

fn get_list_from_maps(config_path: &str, state_path: &str) -> Result<Vec<StatusEntry>> {
    let config_map = get_config_map(config_path)?;
    // We try to get state map, but if it fails we might still want to return config?
    // But for now, if state map is broken, we probably want to error out.
    let state_map = get_state_map(state_path)?;
    let mut entries = Vec::new();

    for item in config_map.iter() {
        let (key, config) = item?;
        let ip = Ipv4Addr::from(u32::from_be(key));

        let (tokens, last_time) = match state_map.get(&key, 0) {
            Ok(s) => (Some(s.tokens), Some(s.last_time)),
            Err(_) => (None, None),
        };

        entries.push(StatusEntry {
            ip,
            rate: config.rate,
            fill_time: config.fill_time,
            tokens,
            last_time,
        });
    }
    Ok(entries)
}

fn get_config_map(path: &str) -> Result<HashMap<aya::maps::MapData, u32, RateConfig>> {
    let map_data =
        aya::maps::MapData::from_pin(path).context("failed to load pinned config map")?;
    let map = aya::maps::Map::HashMap(map_data);
    let hash_map = HashMap::try_from(map).context("failed to convert to HashMap")?;
    Ok(hash_map)
}

fn get_state_map(path: &str) -> Result<HashMap<aya::maps::MapData, u32, BucketState>> {
    let map_data = aya::maps::MapData::from_pin(path).context("failed to load pinned state map")?;
    let map = aya::maps::Map::HashMap(map_data);
    let hash_map = HashMap::try_from(map).context("failed to convert to HashMap")?;
    Ok(hash_map)
}

fn ip_to_key(ip: Ipv4Addr) -> u32 {
    u32::from(ip).to_be()
}

fn add_entry(
    map_path: &str,
    state_map_path: &str,
    file_path: &PathBuf,
    ip: Ipv4Addr,
    mut rate: u64, // bytes per second
) -> Result<()> {
    if rate == 0 {
        bail!("Rate cannot be 0");
    }

    // Normalize rate to be in bytes per 2^30 ns
    rate = (((rate as u128) << 30) / 10u128.pow(9)).try_into()?;

    // Calculate fill_time to achieve 1 TiB (2^40 bytes) capacity
    // (2^40 bytes) / (rate bytes / 2^30 ns) / 2^10 ns
    // = 2^60 / rate
    let fill_time = (1u64 << 60) / rate;

    // 1. Update File
    let mut entries = read_file(file_path)?;
    entries.retain(|e| e.ip != ip);
    entries.push(Entry {
        ip,
        rate,
        fill_time,
    });
    write_file(file_path, &entries)?;
    info!("Updated file {:?}", file_path);

    let key = ip_to_key(ip);

    // 2. Update Config Map
    let mut config_map = get_config_map(map_path)?;
    let config = RateConfig { rate, fill_time };
    config_map.insert(key, config, 0)?; // 0 flags
    info!("Added {} to config map", ip);

    // 3. Update State Map
    let mut state_map = get_state_map(state_map_path)?;
    if state_map.get(&key, 0).is_err() {
        let state = BucketState {
            lock: 0,
            last_time: 0,
            tokens: START_CAPACITY,
        };
        state_map.insert(key, state, 0)?;
        info!("Initialized state for {} in state map", ip);
    }

    Ok(())
}

fn remove_entry(
    map_path: &str,
    state_map_path: &str,
    file_path: &PathBuf,
    ip: Ipv4Addr,
) -> Result<()> {
    let key = ip_to_key(ip);

    // 1. Update State Map
    let mut state_map = get_state_map(state_map_path)?;
    match state_map.remove(&key) {
        Ok(_) => info!("Removed {} from state map", ip),
        Err(e) => warn!("Failed to remove from state map: {}", e),
    }

    // 2. Update Config Map
    let mut config_map = get_config_map(map_path)?;
    match config_map.remove(&key) {
        Ok(_) => info!("Removed {} from config map", ip),
        Err(e) => warn!("Failed to remove from config map: {}", e),
    }

    // 3. Update File
    let mut entries = read_file(file_path)?;
    let initial_len = entries.len();
    entries.retain(|e| e.ip != ip);
    if entries.len() != initial_len {
        write_file(file_path, &entries)?;
        info!("Removed {} from file {:?}", ip, file_path);
    } else {
        warn!("IP {} not found in file {:?}", ip, file_path);
    }

    Ok(())
}

fn load_entries(map_path: &str, state_map_path: &str, file_path: &PathBuf) -> Result<()> {
    let entries = read_file(file_path)?;
    let mut config_map = get_config_map(map_path)?;
    let mut state_map = get_state_map(state_map_path)?;

    for entry in entries {
        let key = ip_to_key(entry.ip);
        let config = RateConfig {
            rate: entry.rate,
            fill_time: entry.fill_time,
        };
        config_map.insert(key, config, 0)?;

        if state_map.get(&key, 0).is_err() {
            let state = BucketState {
                lock: 0,
                last_time: 0,
                tokens: START_CAPACITY,
            };
            state_map.insert(key, state, 0)?;
        }

        info!("Loaded {}", entry.ip);
    }
    info!("Loaded all entries from file {:?}", file_path);
    Ok(())
}

fn read_file(path: &PathBuf) -> Result<Vec<Entry>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path)?;
    if content.trim().is_empty() {
        return Ok(Vec::new());
    }
    let entries: Vec<Entry> = serde_json::from_str(&content)?;
    Ok(entries)
}

fn write_file(path: &PathBuf, entries: &[Entry]) -> Result<()> {
    let content = serde_json::to_string_pretty(entries)?;
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, content)?;
    fs::rename(tmp_path, path)?;
    Ok(())
}
