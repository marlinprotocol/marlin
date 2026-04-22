use clap::{Parser, Subcommand};
use commands::{
    close::CloseArgs, deploy::DeployArgs, deposit::DepositArgs, derive::KmsDeriveArgs,
    image_id::ImageArgs, kms_contract::KmsContractArgs, list::ListArgs, simulate::SimulateArgs,
    update::UpdateArgs, verify::VerifyArgs, withdraw::WithdrawArgs,
};

mod arch;
mod args;
mod commands;
mod configs;
mod deployment;
mod utils;

use tracing_subscriber::EnvFilter;

fn setup_logging() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}

#[derive(Parser)]
#[command(version, about = "Oyster CVM command line utility")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Simulate(SimulateArgs),
    Deploy(DeployArgs),
    Verify(VerifyArgs),
    List(ListArgs),
    Update(UpdateArgs),
    Deposit(DepositArgs),
    Close(CloseArgs),
    Withdraw(WithdrawArgs),
    ComputeImageId(ImageArgs),
    KmsDerive(KmsDeriveArgs),
    KmsContract(KmsContractArgs),
}

#[tokio::main]
async fn main() {
    setup_logging();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Simulate(args) => args.run().await,
        Commands::Verify(args) => args.run().await,
        Commands::Deploy(args) => args.run().await,
        Commands::List(args) => args.run().await,
        Commands::Update(args) => args.run().await,
        Commands::Deposit(args) => args.run().await,
        Commands::Close(args) => args.run().await,
        Commands::Withdraw(args) => args.run().await,
        Commands::ComputeImageId(args) => args.run(),
        Commands::KmsDerive(args) => args.run().await,
        Commands::KmsContract(args) => args.run().await,
    };

    if let Err(e) = result {
        tracing::error!("Error: {e:#}");
        std::process::exit(1);
    }
}
