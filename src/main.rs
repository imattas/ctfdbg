//! Binary entry point. Parses CLI then hands off to either the GUI or
//! a script/command-only mode.

use clap::Parser;
use ctfdbg::{
    cli::Cli,
    config::DebugConfig,
    gui,
};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Logging
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(cli.log_level.as_str()));
    tracing_subscriber::registry()
        .with(fmt::layer().with_target(false))
        .with(filter)
        .init();

    tracing::info!("ctfdbg starting");

    let cfg = DebugConfig::from_cli(&cli);

    // Headless / script mode
    if cli.headless {
        return ctfdbg::commands::executor::run_headless(cfg, cli.script.as_deref());
    }

    // GUI mode
    gui::run(cfg).map_err(|e| anyhow::anyhow!("GUI error: {e}"))
}
