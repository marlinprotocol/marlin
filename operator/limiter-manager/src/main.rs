use axum::{
    Router,
    routing::{delete, get, post},
};
use clap::Parser;
use log::{error, info};
use std::process::Command;
use tokio::net::TcpListener;

mod handlers;
use handlers::{AppState, create_job, delete_job};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;

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
    if let Err(e) = init_tc(&args.interface) {
        error!("Failed to initialize TC: {}", e);
        // We might want to exit here if TC is critical
        // std::process::exit(1);
    }

    let shared_state = Arc::new(AppState {
        bandwidth_available: Mutex::new(args.bandwidth),
        ongoing_jobs: Mutex::new(HashSet::new()),
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

fn init_tc(interface_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("tc")
        .args([
            "qdisc",
            "add",
            "dev",
            interface_name,
            "root",
            "handle",
            "1:",
            "htb",
        ])
        .output()?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        if err.contains("File exists") {
            info!(
                "Root qdisc already exists on {}, skipping add.",
                interface_name
            );
        } else {
            return Err(format!("tc qdisc add failed: {}", err).into());
        }
    }

    info!("Initialized TC (HTB root qdisc) on {}", interface_name);
    Ok(())
}
