use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use aya::maps::HashMap;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

const START_CAPACITY: u64 = 1_000_000;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long, default_value = "/sys/fs/bpf/xdp/globals/config_map")]
    config_map_path: String,

    #[arg(long, default_value = "/sys/fs/bpf/xdp/globals/state_map")]
    state_map_path: String,

    #[arg(short, long, default_value = "ratelimits.json")]
    file: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Add {
        #[arg(long)]
        ip: Ipv4Addr,
        #[arg(long, help = "Tokens (bytes) per 2^30 ns (~1 sec)")]
        rate: u64,
    },
    Remove {
        #[arg(long)]
        ip: Ipv4Addr,
    },
    Load,
    Show,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct RateConfig {
    rate: u64,
    fill_time: u64,
}

// SAFETY: RateConfig is a POD type
unsafe impl aya::Pod for RateConfig {}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct BucketState {
    lock: u32, // bpf_spin_lock is u32
    last_time: u64,
    tokens: u64,
}

// SAFETY: BucketState is a POD type
unsafe impl aya::Pod for BucketState {}

#[derive(Serialize, Deserialize, Clone)]
struct Entry {
    ip: Ipv4Addr,
    rate: u64,
    fill_time: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Add { ip, rate } => {
            add_entry(
                &cli.config_map_path,
                &cli.state_map_path,
                &cli.file,
                ip,
                rate,
            )?;
        }
        Commands::Remove { ip } => {
            remove_entry(&cli.config_map_path, &cli.state_map_path, &cli.file, ip)?;
        }
        Commands::Load => {
            load_entries(&cli.config_map_path, &cli.state_map_path, &cli.file)?;
        }
        Commands::Show => {
            show_entries(&cli.config_map_path, &cli.state_map_path)?;
        }
    }

    Ok(())
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
    // Convert IP to network byte order u32
    u32::from(ip).to_be()
}

fn add_entry(
    map_path: &str,
    state_map_path: &str,
    file_path: &PathBuf,
    ip: Ipv4Addr,
    rate: u64,
) -> Result<()> {
    if rate == 0 {
        bail!("Rate cannot be 0");
    }
    // Calculate fill_time to achieve 1 TiB (2^40 bytes) capacity
    // 2^40 = rate * fill_time / 2^20  =>  rate * fill_time = 2^60
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

    // 2. Update Config Map
    let mut config_map = get_config_map(map_path)?;
    let key = ip_to_key(ip);
    let config = RateConfig { rate, fill_time };
    config_map.insert(key, config, 0)?; // 0 flags
    info!("Added {} to config map", ip);

    // 3. Update State Map
    let mut state_map = get_state_map(state_map_path)?;
    let state = BucketState {
        lock: 0,
        last_time: 0, // 0 means "start from beginning/boot", so first packet will likely trigger max refill
        tokens: START_CAPACITY,
    };
    state_map.insert(key, state, 0)?;
    info!("Initialized state for {} in state map", ip);

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

        // For load, we also reset/init the state
        let state = BucketState {
            lock: 0,
            last_time: 0,
            tokens: START_CAPACITY,
        };
        state_map.insert(key, state, 0)?;

        info!("Loaded {}", entry.ip);
    }
    info!("Loaded all entries from file {:?}", file_path);
    Ok(())
}

fn show_entries(map_path: &str, state_map_path: &str) -> Result<()> {
    let config_map = get_config_map(map_path)?;
    // We can also try to show state, but it might change rapidly
    let state_map = get_state_map(state_map_path)?;

    println!(
        "{:<15} | {:<12} | {:<12} | {:<12} | {:<12}",
        "IP", "Rate", "Fill Time", "Tokens", "Last Time"
    );
    println!("{}", "-".repeat(75));

    for item in config_map.iter() {
        let (key, config) = item?;
        let ip = Ipv4Addr::from(u32::from_be(key));

        let state_info = match state_map.get(&key, 0) {
            Ok(s) => format!("{:<12} | {:<12}", s.tokens, s.last_time),
            Err(_) => format!("{:<12} | {:<12}", "N/A", "N/A"),
        };

        println!(
            "{:<15} | {:<12} | {:<12} | {}",
            ip, config.rate, config.fill_time, state_info
        );
    }
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
    fs::write(path, content)?;
    Ok(())
}
