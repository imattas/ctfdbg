//! Binary entry point. Parses CLI then hands off to either the GUI or
//! a script/command-only mode.

use clap::Parser;
use ctfdbg::{cli::Cli, config::DebugConfig};
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

    // GUI mode (only when built with the `gui` feature and not asked for headless).
    #[cfg(feature = "gui")]
    {
        if !cli.headless {
            return ctfdbg::gui::run(cfg).map_err(|e| anyhow::anyhow!("GUI error: {e}"));
        }
    }

    // Headless / script mode (also the only mode when built without `gui`).
    ctfdbg::commands::executor::run_headless(cfg, cli.script.as_deref())
}
