use axum::{
    Router,
    routing::{delete, get, post},
};
use clap::Parser;
use futures::stream::{StreamExt, TryStreamExt};
use log::{error, info};
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_REPLACE, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::{
    RouteNetlinkMessage,
    tc::{TcAttribute, TcHandle, TcMessage},
};
use rtnetlink::new_connection;
use tokio::net::TcpListener;

mod handlers;
use handlers::{AppState, create_job, delete_job};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Address to listen on
    #[arg(short, long, default_value = "127.0.0.1:3000")]
    address: String,

    /// Network interface to apply Traffic Control
    #[arg(short, long, default_value = "lo")]
    interface: String,

    /// Total available bandwidth
    #[arg(short, long, default_value = "10000000000")]
    bandwidth: u64,
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let args = Args::parse();

    // Initialize Traffic Control
    if let Err(e) = init_tc(&args.interface).await {
        error!("Failed to initialize TC: {}", e);
        // We might want to exit here if TC is critical
        // std::process::exit(1);
    }

    let shared_state = Arc::new(AppState {
        bandwidth_available: Mutex::new(args.bandwidth),
        interface: args.interface.clone(),
    });

    // build our application with a single route
    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/job", post(create_job))
        .route("/job", delete(delete_job))
        .with_state(shared_state);

    // run our app with hyper, listening globally on port 3000
    let listener = TcpListener::bind(&args.address).await.unwrap();
    info!("Listening on {}", args.address);
    axum::serve(listener, app).await.unwrap();
}

async fn init_tc(interface_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let (connection, mut handle, _) = new_connection()?;
    tokio::spawn(connection);

    let mut links = handle
        .link()
        .get()
        .match_name(interface_name.to_string())
        .execute();
    let link = if let Some(link) = links.try_next().await? {
        link
    } else {
        return Err(format!("Interface {} not found", interface_name).into());
    };

    let index = link.header.index;
    info!("Found interface {} with index {}", interface_name, index);

    // Manual QDisc construction to ensure HTB kind is set
    // TC_H_ROOT is 0xFFFFFFFF
    let mut tc_msg = TcMessage::with_index(index as i32);
    // Explicitly convert u32 to TcHandle if needed, or assume From<u32>
    tc_msg.header.handle = TcHandle::from(0x10000u32);
    tc_msg.header.parent = TcHandle::from(0xFFFFFFFFu32);
    tc_msg.attributes.push(TcAttribute::Kind("htb".to_string()));

    let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewQueueDiscipline(tc_msg));
    // Use REPLACE to overwrite existing qdisc (like 'tc qdisc replace') avoiding EEXIST
    req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;

    let mut response_stream = handle.request(req)?;
    while let Some(msg) = response_stream.next().await {
        if let NetlinkPayload::Error(err) = msg.payload {
            if let Some(code) = err.code {
                if code.get() != 0 {
                    return Err(format!("TC Netlink Error: {}", code).into());
                }
            }
        }
    }

    info!("Initialized TC (HTB root qdisc) on {}", interface_name);
    Ok(())
}
