mod target;

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
            println!("Scanning {}", root.display());
            Ok(())
        }
        Target::Remote(url) => bail!("remote targets are not supported yet: {url}"),
    }
}
