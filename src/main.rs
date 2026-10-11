use anyhow::{bail, Context, Result};
use clap::Parser;
use colored::Colorize;
use dnsbench::wire::RecordType;
use dnsbench::{
    audit_propagation, format_benchmark_table, format_propagation_report,
    get_default_public_resolvers, get_system_resolvers, run_benchmark, Resolver,
};
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "dnsbench",
    about = "A fast, concurrent multi-resolver DNS benchmarking and propagation auditing CLI tool",
    version
)]
struct Args {
    /// Domain name to benchmark or audit (e.g. "google.com", "cloudflare.com")
    #[arg(default_value = "google.com")]
    domain: String,

    /// DNS record type to query (A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, CAA)
    #[arg(short = 't', long = "type", default_value = "A")]
    record_type: String,

    /// Number of query iterations per resolver for latency distribution calculation
    #[arg(short = 'n', long, default_value_t = 5)]
    iterations: usize,

    /// Maximum concurrent queries in flight
    #[arg(short = 'c', long, default_value_t = 10)]
    concurrency: usize,

    /// Custom DNS resolver(s) [host:port or IP] (can specify multiple times)
    #[arg(short = 'r', long = "resolver")]
    resolvers: Vec<String>,

    /// Benchmark only system-configured resolvers (from /etc/resolv.conf)
    #[arg(long)]
    system_only: bool,

    /// Benchmark only global public resolvers (Cloudflare, Google, Quad9, etc.)
    #[arg(long)]
    public_only: bool,

    /// Use TCP transport instead of UDP for queries
    #[arg(long)]
    tcp: bool,

    /// Run DNS propagation and answer consistency audit across resolvers
    #[arg(long, alias = "check")]
    audit: bool,

    /// Query timeout in milliseconds
    #[arg(long, default_value_t = 2000)]
    timeout: u64,

    /// Output results as JSON for scripting and automation
    #[arg(short = 'j', long, alias = "ndjson")]
    json: bool,

    /// Disable ANSI color formatting
    #[arg(long)]
    no_color: bool,
}

fn resolve_custom_address(addr_str: &str) -> Result<SocketAddr> {
    let normalized = if !addr_str.contains(':') {
        format!("{}:53", addr_str)
    } else {
        addr_str.to_string()
    };

    use std::net::ToSocketAddrs;
    let mut addrs = normalized
        .to_socket_addrs()
        .with_context(|| format!("Failed to resolve DNS resolver address '{}'", addr_str))?;

    addrs
        .next()
        .context(format!("No IP address found for '{}'", addr_str))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.no_color {
        colored::control::set_override(false);
    }

    let qtype = match RecordType::from_str(&args.record_type) {
        Some(t) => t,
        None => bail!("Unknown or unsupported DNS record type '{}'", args.record_type),
    };

    let mut resolvers: Vec<Resolver> = Vec::new();

    // 1. Custom resolvers if specified
    for (i, r_str) in args.resolvers.iter().enumerate() {
        let addr = resolve_custom_address(r_str)?;
        resolvers.push(Resolver {
            name: format!("Custom #{}", i + 1),
            addr,
            provider: "Custom".to_string(),
        });
    }

    // 2. Default resolver pool selection
    if resolvers.is_empty() {
        if args.system_only {
            resolvers.extend(get_system_resolvers());
        } else if args.public_only {
            resolvers.extend(get_default_public_resolvers());
        } else {
            // Default: system + public resolvers
            resolvers.extend(get_system_resolvers());
            resolvers.extend(get_default_public_resolvers());
        }
    }

    if resolvers.is_empty() {
        bail!("No DNS resolvers configured or discovered.");
    }

    let timeout = Duration::from_millis(args.timeout);

    if args.audit {
        eprintln!(
            "{} Auditing propagation for {} ({}) across {} resolvers...",
            "●".cyan(),
            args.domain.bold(),
            qtype.as_str().yellow(),
            resolvers.len()
        );

        let report = audit_propagation(&resolvers, &args.domain, qtype, args.tcp, timeout).await;

        if args.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            let output = format_propagation_report(&report, !args.no_color);
            print!("{}", output);
        }
    } else {
        eprintln!(
            "{} Benchmarking {} resolvers for {} ({}, {} iteration(s) each)...",
            "●".cyan(),
            resolvers.len(),
            args.domain.bold(),
            qtype.as_str().yellow(),
            args.iterations
        );

        let results = run_benchmark(
            &resolvers,
            &args.domain,
            qtype,
            args.iterations,
            args.concurrency,
            args.tcp,
            timeout,
        )
        .await;

        if args.json {
            println!("{}", serde_json::to_string_pretty(&results)?);
        } else {
            let table = format_benchmark_table(&results, &args.domain, qtype, !args.no_color);
            print!("{}", table);
        }
    }

    Ok(())
}
