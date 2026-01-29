use axum::{Json, extract::State, http::StatusCode};
use futures::stream::{StreamExt, TryStreamExt};
use log::{error, info, warn};
use netlink_packet_core::{
    DefaultNla, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST, NetlinkMessage,
};
use netlink_packet_route::tc::{
    TcAttribute, TcFilterU32Option, TcHandle, TcMessage, TcOption, TcU32Key, TcU32Selector,
};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use rtnetlink::new_connection;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct struct_tc_ratespec {
    cell_log: u8,
    __reserved: u8,
    overhead: u16,
    cell_align: i16,
    mpu: u16,
    rate: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct struct_tc_htb_opt {
    rate: struct_tc_ratespec,
    ceil: struct_tc_ratespec,
    buffer: u32,
    cbuffer: u32,
    quantum: u32,
    level: u32,
    prio: u32,
}

impl struct_tc_htb_opt {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(std::mem::size_of::<Self>());
        unsafe {
            let ptr = self as *const Self as *const u8;
            bytes.extend_from_slice(std::slice::from_raw_parts(ptr, std::mem::size_of::<Self>()));
        }
        bytes
    }
}

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
    let mut available = state.bandwidth_available.lock().await;

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

    match allocate_class_id(&state.interface).await {
        Ok(class_id) => {
            info!("Allocated Class ID: 1:{}", class_id);
            if let Err(e) = setup_tc(&state.interface, class_id, &payload).await {
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

    // Lock is released when available goes out of scope
    (StatusCode::CREATED, Json(payload))
}

pub async fn delete_job(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<DeleteJobRequest>,
) -> (StatusCode, Json<DeleteJobRequest>) {
    let mut available = state.bandwidth_available.lock().await;
    info!("Acquired lock for job deletion: {}", payload.job_id);

    if let Err(e) = cleanup_tc(&state.interface, &payload.private_ip).await {
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

async fn allocate_class_id(
    interface: &str,
) -> Result<u16, Box<dyn std::error::Error + Send + Sync>> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    let mut links = handle
        .link()
        .get()
        .match_name(interface.to_string())
        .execute();
    let link = if let Some(link) = links.try_next().await? {
        link
    } else {
        return Err(format!("Interface {} not found", interface).into());
    };
    let if_index = link.header.index;

    // List all classes on the interface
    let mut classes = handle.traffic_class(if_index as i32).get().execute();
    let mut existing_ids = std::collections::HashSet::new();

    while let Some(res) = classes.next().await {
        let msg = res?;
        let handle_u32 = u32::from(msg.header.handle);
        let major = (handle_u32 >> 16) as u16;
        let minor = (handle_u32 & 0xFFFF) as u16;

        if major == 1 {
            existing_ids.insert(minor);
        }
    }

    // Find unused ID between 1 and 9999
    for id in 1..=9999 {
        if !existing_ids.contains(&id) {
            return Ok(id);
        }
    }

    Err("No available Class IDs".into())
}

async fn setup_tc(
    interface: &str,
    class_id: u16,
    payload: &CreateJobRequest,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (connection, mut handle, _) = new_connection()?;
    tokio::spawn(connection);

    let mut links = handle
        .link()
        .get()
        .match_name(interface.to_string())
        .execute();
    let link = if let Some(link) = links.try_next().await? {
        link
    } else {
        return Err(format!("Interface {} not found", interface).into());
    };
    let if_index = link.header.index;

    // 1. Add TC Class (HTB)
    let mut htb_opt = struct_tc_htb_opt::default();
    htb_opt.rate.rate = payload.bandwidth_limit as u32;
    htb_opt.ceil.rate = payload.bandwidth_limit as u32;
    htb_opt.buffer = 200000;
    htb_opt.cbuffer = 200000;

    let mut msg = TcMessage::default();
    msg.header.index = if_index as i32;
    msg.header.parent = TcHandle { major: 1, minor: 0 };
    msg.header.handle = TcHandle {
        major: 1,
        minor: class_id,
    };
    msg.header.family = AddressFamily::Unspec;

    msg.attributes.push(TcAttribute::Kind("htb".to_string()));
    msg.attributes
        .push(TcAttribute::Options(vec![TcOption::Other(
            DefaultNla::new(1, htb_opt.to_bytes()),
        )]));

    let mut nl_msg = NetlinkMessage::from(RouteNetlinkMessage::NewTrafficClass(msg));
    nl_msg.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;

    let mut response = handle.request(nl_msg)?;
    while let Some(_) = response.next().await {}

    // 2. Add TC Filter (u32)
    let ip_bytes: Vec<u8> = payload
        .private_ip
        .split('.')
        .map(|s| s.parse::<u8>().unwrap_or(0))
        .collect();
    if ip_bytes.len() != 4 {
        return Err("Invalid IPv4 address".into());
    }
    let ip_u32 = u32::from_be_bytes([ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]]);

    let mut key = TcU32Key::default();
    key.mask = 0xffffffff;
    key.val = ip_u32;
    key.off = 12;
    key.offmask = 0;

    let mut selector = TcU32Selector::default();
    selector.keys.push(key);
    selector.nkeys = 1;

    handle
        .traffic_filter(if_index as i32)
        .add()
        .parent(u32::from(TcHandle { major: 1, minor: 0 }))
        .priority(1)
        .protocol(0x0800) // ETH_P_IP
        .u32(&[
            TcFilterU32Option::Selector(selector),
            TcFilterU32Option::ClassId(TcHandle {
                major: 1,
                minor: class_id,
            }),
        ])?
        .execute()
        .await?;

    Ok(())
}

async fn cleanup_tc(
    interface: &str,
    private_ip: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (connection, mut handle, _) = new_connection()?;
    tokio::spawn(connection);

    let mut links = handle
        .link()
        .get()
        .match_name(interface.to_string())
        .execute();
    let link = if let Some(link) = links.try_next().await? {
        link
    } else {
        return Err(format!("Interface {} not found", interface).into());
    };
    let if_index = link.header.index;

    let ip_bytes: Vec<u8> = private_ip
        .split('.')
        .map(|s| s.parse::<u8>().unwrap_or(0))
        .collect();
    if ip_bytes.len() != 4 {
        return Err("Invalid IPv4 address".into());
    }
    let target_ip_u32 = u32::from_be_bytes([ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]]);

    // 1. Find filter based on IP
    let mut filters_stream = handle.traffic_filter(if_index as i32).get().execute();

    let mut found_filter_handle = None;
    let mut found_filter_info = None;
    let mut found_class_id = None;

    while let Some(res) = filters_stream.next().await {
        let msg = res?;
        let mut matches_ip = false;
        let mut class_id = None;

        for attr in &msg.attributes {
            if let TcAttribute::Options(opts) = attr {
                for opt in opts {
                    if let TcOption::U32(u32_opt) = opt {
                        match u32_opt {
                            TcFilterU32Option::Selector(sel) => {
                                for key in &sel.keys {
                                    if key.off == 12
                                        && key.val == target_ip_u32
                                        && key.mask == 0xffffffff
                                    {
                                        matches_ip = true;
                                    }
                                }
                            }
                            TcFilterU32Option::ClassId(cid) => {
                                class_id = Some(*cid);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        if matches_ip {
            found_filter_handle = Some(msg.header.handle);
            found_filter_info = Some(msg.header.info);
            found_class_id = class_id;
            break;
        }
    }

    if let Some(filter_handle) = found_filter_handle {
        info!("Found filter {:?} for IP {}", filter_handle, private_ip);

        // 2. Delete Filter
        let mut del_msg = TcMessage::default();
        del_msg.header.index = if_index as i32;
        del_msg.header.handle = filter_handle;
        del_msg.header.parent = TcHandle { major: 1, minor: 0 };
        del_msg.header.info = found_filter_info.unwrap_or(0);

        let mut nl_msg = NetlinkMessage::from(RouteNetlinkMessage::DelTrafficFilter(del_msg));
        nl_msg.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = handle.request(nl_msg)?;
        while let Some(_) = response.next().await {}

        if let Some(class_id) = found_class_id {
            info!("Deleting class {:?}", class_id);
            // 3. Delete Class
            let mut del_msg = TcMessage::default();
            del_msg.header.index = if_index as i32;
            del_msg.header.handle = class_id;
            del_msg.header.parent = TcHandle { major: 1, minor: 0 };

            let mut nl_msg = NetlinkMessage::from(RouteNetlinkMessage::DelTrafficClass(del_msg));
            nl_msg.header.flags = NLM_F_REQUEST | NLM_F_ACK;

            let mut response = handle.request(nl_msg)?;
            while let Some(_) = response.next().await {}
        }
    } else {
        warn!("No filter found for IP {}", private_ip);
    }

    Ok(())
}
