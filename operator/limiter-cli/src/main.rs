use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use aya::maps::HashMap;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long, default_value = "/sys/fs/bpf/config_map")]
    map_path: String,

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
            add_entry(&cli.map_path, &cli.file, ip, rate)?;
        }
        Commands::Remove { ip } => {
            remove_entry(&cli.map_path, &cli.file, ip)?;
        }
        Commands::Load => {
            load_entries(&cli.map_path, &cli.file)?;
        }
        Commands::Show => {
            show_entries(&cli.map_path)?;
        }
    }

    Ok(())
}

fn get_map(path: &str) -> Result<HashMap<aya::maps::MapData, u32, RateConfig>> {
    let map_data = aya::maps::MapData::from_pin(path).context("failed to load pinned map")?;
    let map = aya::maps::Map::HashMap(map_data);
    let hash_map = HashMap::try_from(map).context("failed to convert to HashMap")?;
    Ok(hash_map)
}

fn ip_to_key(ip: Ipv4Addr) -> u32 {
    // Convert IP to network byte order u32
    // 1.2.3.4 -> 0x01020304 (Big Endian)
    // Map expects key in Network Byte Order because ip->saddr is __be32
    u32::from(ip).to_be()
}

// NOTE: the map should never contain entries that are not in the file

fn add_entry(map_path: &str, file_path: &PathBuf, ip: Ipv4Addr, rate: u64) -> Result<()> {
    if rate == 0 {
        bail!("Rate cannot be 0");
    }
    // Calculate fill_time to achieve 1 TiB (2^40 bytes) capacity
    // Capacity = Rate * FillTime
    // Rate (bytes/sec) ~ rate (arg)
    // FillTime (sec) ~ fill_time (arg)
    // Precise: Capacity = (rate / 2^30) * (fill_time * 2^10) = rate * fill_time / 2^20
    // We want Capacity = 2^40
    // 2^40 = rate * fill_time / 2^20
    // rate * fill_time = 2^60
    // fill_time = 2^60 / rate
    let fill_time = (1u64 << 60) / rate;

    // 1. Update File
    let mut entries = read_file(file_path)?;
    // Remove existing if any
    entries.retain(|e| e.ip != ip);
    entries.push(Entry {
        ip,
        rate,
        fill_time,
    });
    write_file(file_path, &entries)?;
    info!("Updated file {:?}", file_path);

    // 2. Update Map
    let mut map = get_map(map_path)?;
    let key = ip_to_key(ip);
    let val = RateConfig { rate, fill_time };
    map.insert(key, val, 0)?; // 0 flags
    info!("Added {} to map", ip);

    Ok(())
}

fn remove_entry(map_path: &str, file_path: &PathBuf, ip: Ipv4Addr) -> Result<()> {
    // 1. Update Map
    let mut map = get_map(map_path)?;
    let key = ip_to_key(ip);
    match map.remove(&key) {
        Ok(_) => info!("Removed {} from map", ip),
        Err(e) => warn!("Failed to remove from map (might not exist): {}", e),
    }

    // 2. Update File
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

fn load_entries(map_path: &str, file_path: &PathBuf) -> Result<()> {
    let entries = read_file(file_path)?;
    let mut map = get_map(map_path)?;

    for entry in entries {
        let key = ip_to_key(entry.ip);
        let val = RateConfig {
            rate: entry.rate,
            fill_time: entry.fill_time,
        };
        map.insert(key, val, 0)?;
        info!("Loaded {}", entry.ip);
    }
    info!("Loaded all entries from file {:?}", file_path);
    Ok(())
}

fn show_entries(map_path: &str) -> Result<()> {
    let map = get_map(map_path)?;
    println!("{:<20} | {:<20} | {:<20}", "IP", "Rate", "Fill Time");
    println!("{}", "-".repeat(66));

    for item in map.iter() {
        let (key, val) = item?;
        let ip = Ipv4Addr::from(u32::from_be(key));
        println!("{:<20} | {:<20} | {:<20}", ip, val.rate, val.fill_time);
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
