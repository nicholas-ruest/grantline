#![forbid(unsafe_code)]

use clap::{Parser, Subcommand, ValueEnum};
use grantline::{ActionRequest, ChainReport, Decision, Mandate, authorize, verify_chain};
use serde::de::DeserializeOwned;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Verify that each child mandate only narrows its parent.
    VerifyChain {
        /// JSON file containing a root-to-leaf array of mandates.
        #[arg(value_name = "CHAIN.json")]
        chain: PathBuf,
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
    },
    /// Evaluate one proposed action against a mandate.
    Authorize {
        #[arg(value_name = "MANDATE.json")]
        mandate: PathBuf,
        #[arg(value_name = "REQUEST.json")]
        request: PathBuf,
        #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
        format: OutputFormat,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("grantline: {message}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<ExitCode, String> {
    match Cli::parse().command {
        Command::VerifyChain { chain, format } => {
            let mandates: Vec<Mandate> = read_json(&chain)?;
            let report = verify_chain(&mandates);
            print_chain_report(&report, format)?;
            Ok(decision_code(report.valid))
        }
        Command::Authorize {
            mandate,
            request,
            format,
        } => {
            let mandate: Mandate = read_json(&mandate)?;
            let request: ActionRequest = read_json(&request)?;
            let decision = authorize(&mandate, &request);
            print_decision(&decision, format)?;
            Ok(decision_code(decision.allowed))
        }
    }
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    serde_json::from_str(&contents)
        .map_err(|error| format!("invalid JSON in {}: {error}", path.display()))
}

fn print_chain_report(report: &ChainReport, format: OutputFormat) -> Result<(), String> {
    match format {
        OutputFormat::Json => print_json(report),
        OutputFormat::Human => {
            if report.valid {
                println!(
                    "ALLOW chain: {} mandates, {} links, leaf {}",
                    report.mandates,
                    report.links_checked,
                    report.leaf_id.as_deref().unwrap_or("<none>")
                );
            } else {
                println!("DENY chain: {} violation(s)", report.violations.len());
                print_violations(&report.violations);
            }
            Ok(())
        }
    }
}

fn print_decision(decision: &Decision, format: OutputFormat) -> Result<(), String> {
    match format {
        OutputFormat::Json => print_json(decision),
        OutputFormat::Human => {
            if decision.allowed {
                println!(
                    "ALLOW action: mandate {} delegates to {}",
                    decision.mandate_id, decision.delegate
                );
            } else {
                println!("DENY action: {} violation(s)", decision.violations.len());
                print_violations(&decision.violations);
            }
            Ok(())
        }
    }
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<(), String> {
    let rendered = serde_json::to_string_pretty(value)
        .map_err(|error| format!("cannot serialize report: {error}"))?;
    println!("{rendered}");
    Ok(())
}

fn print_violations(violations: &[grantline::Violation]) {
    for violation in violations {
        println!(
            "- {} at {}: {}",
            violation.code, violation.path, violation.message
        );
    }
}

fn decision_code(allowed: bool) -> ExitCode {
    if allowed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}
