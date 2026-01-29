use axum::{Json, extract::State, http::StatusCode};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::process::Command;
use std::sync::Arc;
use std::sync::Mutex;

pub struct AppState {
    pub bandwidth_available: Mutex<u64>,
    pub ongoing_jobs: Mutex<HashSet<String>>,
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
    {
        let ongoing_jobs = state.ongoing_jobs.lock().unwrap();
        if ongoing_jobs.contains(&payload.job_id) {
            info!("Job {} already exists, returning success.", payload.job_id);
            return (StatusCode::CREATED, Json(payload));
        }
    }

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
    {
        let mut ongoing_jobs = state.ongoing_jobs.lock().unwrap();
        ongoing_jobs.insert(payload.job_id.clone());
    }

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
    {
        let ongoing_jobs = state.ongoing_jobs.lock().unwrap();
        if !ongoing_jobs.contains(&payload.job_id) {
            info!(
                "Job {} not found in ongoing list, returning success.",
                payload.job_id
            );
            return (StatusCode::OK, Json(payload));
        }
    }

    let mut available = state.bandwidth_available.lock().unwrap();
    info!("Acquired lock for job deletion: {}", payload.job_id);

    if let Err(e) = cleanup_tc(&state.interface, &payload.private_ip) {
        // This path is actually hard to reach now as cleanup_tc handles its errors internally,
        // but we keep it for safety if cleanup_tc logic changes or fatal errors occur.
        error!("Error cleaning up TC for {}: {}", payload.private_ip, e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(payload));
    }

    *available += payload.bandwidth;
    {
        let mut ongoing_jobs = state.ongoing_jobs.lock().unwrap();
        ongoing_jobs.remove(&payload.job_id);
    }

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
        .output();

    let output = match output {
        Ok(out) => out,
        Err(e) => {
            error!("Failed to execute tc filter show: {}", e);
            return Ok(()); // Move on successfully
        }
    };

    if !output.status.success() {
        error!(
            "tc filter show failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(()); // Move on successfully
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

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
        let del_filter_res = Command::new("tc")
            .args([
                "filter", "del", "dev", interface, "parent", "1:", "protocol", "ip", "pref", "1",
                "handle", &handle, "u32",
            ])
            .output();

        match del_filter_res {
            Ok(out) if !out.status.success() => {
                error!(
                    "tc filter del failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            Err(e) => error!("Failed to execute tc filter del: {}", e),
            _ => info!("Successfully deleted filter for IP {}", private_ip),
        }

        // 3. Delete Class
        let del_class_res = Command::new("tc")
            .args([
                "class", "del", "dev", interface, "parent", "1:", "classid", &classid,
            ])
            .output();

        match del_class_res {
            Ok(out) if !out.status.success() => {
                error!(
                    "tc class del failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            Err(e) => error!("Failed to execute tc class del: {}", e),
            _ => info!(
                "Successfully deleted class {} for IP {}",
                classid, private_ip
            ),
        }

        info!("Finished TC cleanup attempt for IP {}", private_ip);
    } else {
        warn!("No TC configuration found for IP {}", private_ip);
    }

    Ok(())
}
