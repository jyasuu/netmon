//! netmon — Network Traffic Monitor
//!
//! Three modes:
//!   tui          Interactive full-screen TUI (default)
//!   log          Continuously append beautified reports to a file
//!   prometheus   Export Prometheus metrics over HTTP
mod collector;
mod logger;
mod prometheus;
mod tui;
mod types;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(
    name = "netmon",
    version = "0.2.0",
    about = "Network traffic monitor: TUI • log-file • Prometheus exporter"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Interactive TUI (default when no subcommand given)
    Tui {
        /// Refresh interval ms
        #[arg(short, long, default_value = "1000")]
        interval: u64,
        /// Filter display to PID
        #[arg(short, long)]
        pid: Option<u32>,
        /// Filter display to port
        #[arg(long)]
        port: Option<u16>,
        /// Show only LISTEN sockets
        #[arg(short, long)]
        listen: bool,
    },
    /// Append formatted monitoring reports to a file continuously
    Log {
        /// Output file (appended)
        #[arg(short, long, default_value = "netmon.log")]
        output: String,
        /// Collection interval ms
        #[arg(short, long, default_value = "5000")]
        interval: u64,
    },
    /// Serve Prometheus /metrics endpoint over HTTP
    Prometheus {
        /// HTTP listen port
        #[arg(short, long, default_value = "9090")]
        port: u16,
        /// Collection interval ms
        #[arg(short, long, default_value = "5000")]
        interval: u64,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Graceful shutdown flag, shared across threads
    let running = Arc::new(AtomicBool::new(true));
    install_signal_handler(running.clone());

    match cli.command.unwrap_or(Cmd::Tui {
        interval: 1000,
        pid: None,
        port: None,
        listen: false,
    }) {
        Cmd::Tui {
            interval,
            pid,
            port,
            listen,
        } => {
            tui::run(interval, pid, port, listen)?;
        }
        Cmd::Log { output, interval } => {
            logger::run(&output, interval, running)?;
        }
        Cmd::Prometheus { port, interval } => {
            prometheus::run(port, interval, running)?;
        }
    }
    Ok(())
}

fn install_signal_handler(running: Arc<AtomicBool>) {
    // Spawn a thread that blocks on SIGINT/SIGTERM via sigwait, then sets
    // the stop flag. Avoids the ctrlc crate while staying safe.
    std::thread::Builder::new()
        .name("signal-handler".into())
        .spawn(move || {
            #[cfg(unix)]
            unsafe {
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, libc::SIGINT);
                libc::sigaddset(&mut set, libc::SIGTERM);
                // Block signals in this thread so sigwait can catch them
                libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
                let mut sig = 0i32;
                libc::sigwait(&set, &mut sig);
                eprintln!("\nnetmon: caught signal {sig}, shutting down…");
                running.store(false, Ordering::SeqCst);
            }
            #[cfg(not(unix))]
            {
                // On non-unix just sleep; Ctrl-C kills process normally
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(3600));
                }
            }
        })
        .expect("failed to spawn signal handler thread");
}
