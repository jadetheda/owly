//! Standalone daemon binary `owly-kdeconnectd`.

use std::process::ExitCode;

use clap::Parser;
use owly_kdeconnect::{DaemonArgs, run_daemon};

#[derive(Parser)]
#[command(
    name = "owly-kdeconnectd",
    version,
    about = "Bridges Owly (AWDL + AirDrop) and Apple BLE endpoints into KDE Connect without requiring the KDE Connect app on the phone."
)]
struct Cli {
    /// The bus owlyd is on, when it isn't the system bus.
    #[arg(long, hide = true)]
    bus: Option<String>,

    #[command(flatten)]
    args: DaemonArgs,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    match rt.block_on(run_daemon(cli.bus.as_deref(), cli.args)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("owly-kdeconnectd: {e}");
            ExitCode::from(2)
        }
    }
}
