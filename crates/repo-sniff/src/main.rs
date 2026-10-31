mod clone;
mod target;

use std::path::Path;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

use crate::target::Target;

/// Statically scan a repository for signs of malicious or suspicious code.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a local directory or a remote git repository.
    Scan {
        /// Path to a local directory or a git URL (https://, ssh://, git@...).
        target: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan { target } => scan(Target::parse(&target)),
    }
}

fn scan(target: Target) -> Result<()> {
    match target {
        Target::Local(path) => {
            let root = path
                .canonicalize()
                .with_context(|| format!("cannot access {}", path.display()))?;
            if !root.is_dir() {
                bail!("{} is not a directory", root.display());
            }
            scan_dir(&root)
        }
        Target::Remote(url) => {
            println!("Cloning {url}");
            // `checkout` must stay alive until the scan ends: dropping it
            // deletes the cloned files.
            let checkout = clone::shallow_clone(&url)?;
            scan_dir(checkout.path())
        }
    }
}

fn scan_dir(root: &Path) -> Result<()> {
    println!("Scanning {}", root.display());
    Ok(())
}
