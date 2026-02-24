use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

mod commands;

#[derive(Parser)]
#[command(
    name = "openice",
    version,
    about = "OpenICE — Precision AI Agent Containment & Execution Control Platform"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Increase log verbosity (repeat for more: -v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Config directory path
    #[arg(short, long, default_value = "./config", global = true)]
    config: PathBuf,

    /// Log actions without executing them
    #[arg(long, global = true)]
    dry_run: bool,

    /// Override log file path
    #[arg(long, global = true)]
    log_file: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan for target processes and report (no enforcement)
    Scan {
        /// Policy profile to match against
        #[arg(long)]
        policy: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Start enforcement loop with specified mode
    Enforce {
        /// Operating mode: observe, contain, quarantine, lockdown
        #[arg(long)]
        mode: String,

        /// Scan interval in seconds
        #[arg(long, default_value = "5")]
        interval: u64,

        /// Run one enforcement pass then exit
        #[arg(long)]
        once: bool,

        /// Policy profile to match against
        #[arg(long)]
        policy: Option<String>,
    },

    /// Immediately quarantine a target (kill + block + clean)
    Quarantine {
        /// Process name, PID, or executable path
        target: String,
    },

    /// Show active enforcements, rules, and blocked processes
    Status,

    /// Manage containment policies
    Policy {
        #[command(subcommand)]
        action: PolicyCommands,
    },

    /// Undo enforcement actions
    Rollback {
        /// Undo last N actions
        #[arg(long, default_value = "1")]
        last: usize,

        /// Undo all recorded actions
        #[arg(long)]
        all: bool,
    },

    /// View or export audit log
    Log {
        /// Show last N entries
        #[arg(long, default_value = "50")]
        tail: usize,

        /// Export full log to file
        #[arg(long)]
        export: Option<PathBuf>,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Filter by event kind
        #[arg(long)]
        filter: Option<String>,
    },
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Load a policy JSON file
    Add {
        /// Path to the policy JSON file
        file: PathBuf,
    },

    /// Remove a loaded policy
    Remove {
        /// Policy profile name
        name: String,
    },

    /// List all loaded policies
    List,

    /// Validate a policy file without loading
    Validate {
        /// Path to the policy JSON file
        file: PathBuf,
    },

    /// Display full policy details
    Show {
        /// Policy profile name
        name: String,
    },
}

fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        unsafe {
            let mut token = windows::Win32::Foundation::HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION::default();
            let mut size = 0u32;
            let result = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut size,
            );
            let _ = CloseHandle(token);
            result.is_ok() && elevation.TokenIsElevated != 0
        }
    }

    #[cfg(not(windows))]
    {
        // On non-Windows, check if running as root
        unsafe { libc::geteuid() == 0 }
    }
}

fn setup_logging(verbose: u8) {
    let filter = match verbose {
        0 => "warn,openice=info",
        1 => "info,openice=debug",
        2 => "debug",
        _ => "trace",
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .with_target(false)
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    setup_logging(cli.verbose);

    if !is_elevated() {
        eprintln!("WARNING: OpenICE is not running with elevated privileges.");
        eprintln!("Some enforcement actions may fail. Run as Administrator for full functionality.");
        eprintln!();
    }

    match cli.command {
        Commands::Scan { policy, json } => {
            commands::scan::run(&cli.config, policy.as_deref(), json, cli.dry_run).await
        }
        Commands::Enforce {
            mode,
            interval,
            once,
            policy,
        } => {
            commands::enforce::run(
                &cli.config,
                &mode,
                interval,
                once,
                policy.as_deref(),
                cli.dry_run,
                cli.log_file.as_deref(),
            )
            .await
        }
        Commands::Quarantine { target } => {
            commands::quarantine::run(
                &cli.config,
                &target,
                cli.dry_run,
                cli.log_file.as_deref(),
            )
            .await
        }
        Commands::Status => commands::status::run().await,
        Commands::Policy { action } => match action {
            PolicyCommands::Add { file } => commands::policy::add(&file).await,
            PolicyCommands::Remove { name } => commands::policy::remove(&name).await,
            PolicyCommands::List => commands::policy::list(&cli.config).await,
            PolicyCommands::Validate { file } => commands::policy::validate(&file).await,
            PolicyCommands::Show { name } => commands::policy::show(&cli.config, &name).await,
        },
        Commands::Rollback { last, all } => commands::rollback::run(last, all).await,
        Commands::Log {
            tail,
            export,
            json,
            filter,
        } => commands::log::run(tail, export.as_deref(), json, filter.as_deref()).await,
    }
}
