use axum::{Json, extract::State, http::StatusCode};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::sync::Arc;
use std::sync::Mutex;

pub struct AppState {
    pub bandwidth_available: Mutex<u64>,
    pub interface: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateJobRequest {
    pub job_id: String,
    pub private_ip: String,
    pub bandwidth_limit: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteJobRequest {
    pub job_id: String,
    pub private_ip: String,
    pub bandwidth: u64,
}

pub async fn create_job(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateJobRequest>,
) -> (StatusCode, Json<CreateJobRequest>) {
    let mut available = state.bandwidth_available.lock().unwrap();

    if *available < payload.bandwidth_limit {
        error!(
            "Insufficient bandwidth for job {}: required {}, available {}",
            payload.job_id, payload.bandwidth_limit, *available
        );
        return (StatusCode::BAD_REQUEST, Json(payload));
    }

    info!(
        "Acquired bandwidth lock. Available: {}, requested: {}",
        *available, payload.bandwidth_limit
    );
    info!("Received job request: {:?}", payload);

    match allocate_class_id(&state.interface) {
        Ok(class_id) => {
            info!("Allocated Class ID: 1:{}", class_id);
            if let Err(e) = setup_tc(&state.interface, class_id, &payload) {
                error!("Error setting up TC: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(payload));
            }
        }
        Err(e) => {
            error!("Failed to allocate class ID: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(payload));
        }
    }

    *available -= payload.bandwidth_limit;
    info!(
        "Job {} created. Remaining bandwidth: {}",
        payload.job_id, *available
    );

    (StatusCode::CREATED, Json(payload))
}

pub async fn delete_job(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<DeleteJobRequest>,
) -> (StatusCode, Json<DeleteJobRequest>) {
    let mut available = state.bandwidth_available.lock().unwrap();
    info!("Acquired lock for job deletion: {}", payload.job_id);

    if let Err(e) = cleanup_tc(&state.interface, &payload.private_ip) {
        error!("Error cleaning up TC for {}: {}", payload.private_ip, e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(payload));
    }

    *available += payload.bandwidth;
    info!(
        "Job {} deleted. Bandwidth restored: {}. Current available: {}",
        payload.job_id, payload.bandwidth, *available
    );

    (StatusCode::OK, Json(payload))
}

fn allocate_class_id(interface: &str) -> Result<u16, Box<dyn std::error::Error>> {
    let output = Command::new("tc")
        .args(["class", "show", "dev", interface])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "tc class show failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut existing_ids = std::collections::HashSet::new();

    for line in stdout.lines() {
        // Example: class htb 1:1 parent 1: leaf 8001: prio 0 rate ...
        if let Some(pos) = line.find("class htb 1:") {
            let start = pos + "class htb 1:".len();
            if let Some(end) = line[start..].find(' ') {
                if let Ok(id) = line[start..start + end].parse::<u16>() {
                    existing_ids.insert(id);
                }
            } else if let Ok(id) = line[start..].parse::<u16>() {
                existing_ids.insert(id);
            }
        }
    }

    for id in 1..=9999 {
        if !existing_ids.contains(&id) {
            return Ok(id);
        }
    }

    Err("No available Class IDs".into())
}

fn setup_tc(
    interface: &str,
    class_id: u16,
    payload: &CreateJobRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Add TC Class
    let class_output = Command::new("tc")
        .args([
            "class",
            "add",
            "dev",
            interface,
            "parent",
            "1:",
            "classid",
            &format!("1:{}", class_id),
            "htb",
            "rate",
            &format!("{}bit", payload.bandwidth_limit),
            "burst",
            "4000m",
        ])
        .output()?;

    if !class_output.status.success() {
        return Err(format!(
            "tc class add failed: {}",
            String::from_utf8_lossy(&class_output.stderr)
        )
        .into());
    }

    // 2. Add TC Filter
    let filter_output = Command::new("tc")
        .args([
            "filter",
            "add",
            "dev",
            interface,
            "protocol",
            "ip",
            "parent",
            "1:0",
            "prio",
            "1",
            "u32",
            "match",
            "ip",
            "src",
            &payload.private_ip,
            "flowid",
            &format!("1:{}", class_id),
        ])
        .output()?;

    if !filter_output.status.success() {
        return Err(format!(
            "tc filter add failed: {}",
            String::from_utf8_lossy(&filter_output.stderr)
        )
        .into());
    }

    info!(
        "Successfully set up TC for job {} on interface {}",
        payload.job_id, interface
    );
    Ok(())
}

fn cleanup_tc(
    interface: &str,
    private_ip: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 1. Find filter based on IP
    let output = Command::new("tc")
        .args(["filter", "show", "dev", interface, "parent", "1:"])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "tc filter show failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse IP to hex for matching in u32 output
    let ip_bytes: Vec<u8> = private_ip
        .split('.')
        .map(|s| s.parse::<u8>().unwrap_or(0))
        .collect();
    if ip_bytes.len() != 4 {
        return Err("Invalid IPv4 address".into());
    }
    let ip_hex = format!(
        "{:02x}{:02x}{:02x}{:02x}",
        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
    );

    let mut found_filter_handle = None;
    let mut found_class_id = None;
    let mut prev_line = "";
    for line in stdout.lines() {
        // Example: filter parent 1: protocol ip pref 1 u32 chain 0 fh 800::800 order 2048 key eq at 12 mask ffffffff match 0a000001 at 12 flowid 1:1
        if line.contains(&ip_hex) {
            found_filter_handle = prev_line
                .split("fh ")
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .map(|s| s.to_string());
            found_class_id = prev_line
                .split("flowid ")
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .map(|s| s.to_string());
            break;
        }
        prev_line = line;
    }

    if let (Some(handle), Some(classid)) = (found_filter_handle, found_class_id) {
        info!(
            "Found filter handle {} and class ID {} for IP {}",
            handle, classid, private_ip
        );

        // 2. Delete Filter
        let del_filter = Command::new("tc")
            .args([
                "filter", "del", "dev", interface, "parent", "1:", "protocol", "ip", "pref", "1",
                "handle", &handle, "u32",
            ])
            .output()?;

        if !del_filter.status.success() {
            return Err(format!(
                "tc filter del failed: {}",
                String::from_utf8_lossy(&del_filter.stderr)
            )
            .into());
        }

        // 3. Delete Class
        let del_class = Command::new("tc")
            .args([
                "class", "del", "dev", interface, "parent", "1:", "classid", &classid,
            ])
            .output()?;

        if !del_class.status.success() {
            return Err(format!(
                "tc class del failed: {}",
                String::from_utf8_lossy(&del_class.stderr)
            )
            .into());
        }

        info!("Successfully cleaned up TC for IP {}", private_ip);
    } else {
        warn!("No TC configuration found for IP {}", private_ip);
    }

    Ok(())
}
