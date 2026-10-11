use anyhow::{bail, Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Semaphore;

pub mod wire;

pub use wire::{DnsRecord, DnsResponse, Rcode, RecordType};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resolver {
    pub name: String,
    pub addr: SocketAddr,
    pub provider: String,
}

pub fn get_default_public_resolvers() -> Vec<Resolver> {
    vec![
        Resolver {
            name: "Cloudflare 1".to_string(),
            addr: "1.1.1.1:53".parse().unwrap(),
            provider: "Cloudflare".to_string(),
        },
        Resolver {
            name: "Cloudflare 2".to_string(),
            addr: "1.0.0.1:53".parse().unwrap(),
            provider: "Cloudflare".to_string(),
        },
        Resolver {
            name: "Google 1".to_string(),
            addr: "8.8.8.8:53".parse().unwrap(),
            provider: "Google".to_string(),
        },
        Resolver {
            name: "Google 2".to_string(),
            addr: "8.8.4.4:53".parse().unwrap(),
            provider: "Google".to_string(),
        },
        Resolver {
            name: "Quad9".to_string(),
            addr: "9.9.9.9:53".parse().unwrap(),
            provider: "Quad9".to_string(),
        },
        Resolver {
            name: "OpenDNS".to_string(),
            addr: "208.67.222.222:53".parse().unwrap(),
            provider: "Cisco OpenDNS".to_string(),
        },
        Resolver {
            name: "AdGuard".to_string(),
            addr: "94.140.14.14:53".parse().unwrap(),
            provider: "AdGuard".to_string(),
        },
    ]
}

pub fn get_system_resolvers() -> Vec<Resolver> {
    let mut out = Vec::new();
    if let Ok(contents) = fs::read_to_string("/etc/resolv.conf") {
        for line in contents.lines() {
            let line = line.trim();
            if line.starts_with("nameserver") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let ip = parts[1];
                    let addr_str = if ip.contains(':') {
                        format!("[{}]:53", ip)
                    } else {
                        format!("{}:53", ip)
                    };
                    if let Ok(addr) = addr_str.parse() {
                        out.push(Resolver {
                            name: format!("System ({})", ip),
                            addr,
                            provider: "Local/OS".to_string(),
                        });
                    }
                }
            }
        }
    }

    if out.is_empty() {
        if let Ok(addr) = "127.0.0.53:53".parse() {
            out.push(Resolver {
                name: "System Local".to_string(),
                addr,
                provider: "systemd-resolved".to_string(),
            });
        }
    }
    out
}

pub async fn query_dns(
    server: SocketAddr,
    domain: &str,
    qtype: RecordType,
    use_tcp: bool,
    timeout: Duration,
) -> Result<(DnsResponse, Duration)> {
    let query_id = rand::random::<u16>();
    let query_bytes = wire::encode_dns_query(query_id, domain, qtype, true);

    let start = Instant::now();

    let response = if use_tcp {
        tokio::time::timeout(timeout, async {
            let mut stream = TcpStream::connect(server)
                .await
                .with_context(|| format!("Failed to connect TCP to {}", server))?;

            // Write 2-byte length prefix + query
            let len = query_bytes.len() as u16;
            stream.write_all(&len.to_be_bytes()).await?;
            stream.write_all(&query_bytes).await?;

            // Read 2-byte response length
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await?;
            let resp_len = u16::from_be_bytes(len_buf) as usize;

            // Read response
            let mut resp_buf = vec![0u8; resp_len];
            stream.read_exact(&mut resp_buf).await?;
            wire::decode_dns_response(&resp_buf)
        })
        .await
        .map_err(|_| anyhow::anyhow!("Timeout waiting for TCP response from {}", server))??
    } else {
        tokio::time::timeout(timeout, async {
            let socket = UdpSocket::bind("0.0.0.0:0")
                .await
                .context("Failed to bind ephemeral UDP client socket")?;

            socket.send_to(&query_bytes, server).await?;

            let mut resp_buf = vec![0u8; 4096];
            let (n, _) = socket.recv_from(&mut resp_buf).await?;
            wire::decode_dns_response(&resp_buf[..n])
        })
        .await
        .map_err(|_| anyhow::anyhow!("Timeout waiting for UDP response from {}", server))??
    };

    let elapsed = start.elapsed();
    if response.id != query_id {
        bail!(
            "Mismatched transaction ID: expected 0x{:04x}, got 0x{:04x}",
            query_id,
            response.id
        );
    }

    Ok((response, elapsed))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStats {
    pub min_ms: f64,
    pub mean_ms: f64,
    pub p50_ms: f64,
    pub p90_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    pub std_dev_ms: f64,
    pub sent_count: usize,
    pub success_count: usize,
    pub timeout_count: usize,
    pub error_count: usize,
    pub loss_rate: f64,
}

pub fn calculate_stats(
    mut durations: Vec<f64>,
    sent_count: usize,
    timeout_count: usize,
    error_count: usize,
) -> LatencyStats {
    let success_count = durations.len();
    let loss_rate = if sent_count > 0 {
        ((sent_count - success_count) as f64 / sent_count as f64) * 100.0
    } else {
        0.0
    };

    if durations.is_empty() {
        return LatencyStats {
            min_ms: 0.0,
            mean_ms: 0.0,
            p50_ms: 0.0,
            p90_ms: 0.0,
            p95_ms: 0.0,
            p99_ms: 0.0,
            max_ms: 0.0,
            std_dev_ms: 0.0,
            sent_count,
            success_count: 0,
            timeout_count,
            error_count,
            loss_rate,
        };
    }

    durations.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let min_ms = *durations.first().unwrap();
    let max_ms = *durations.last().unwrap();
    let sum: f64 = durations.iter().sum();
    let mean_ms = sum / (durations.len() as f64);

    let variance: f64 = durations
        .iter()
        .map(|v| (v - mean_ms).powi(2))
        .sum::<f64>()
        / (durations.len() as f64);
    let std_dev_ms = variance.sqrt();

    let calc_p = |p: f64| -> f64 {
        let idx = ((durations.len() - 1) as f64 * p).round() as usize;
        durations[idx.min(durations.len() - 1)]
    };

    let p50_ms = calc_p(0.50);
    let p90_ms = calc_p(0.90);
    let p95_ms = calc_p(0.95);
    let p99_ms = calc_p(0.99);

    LatencyStats {
        min_ms,
        mean_ms,
        p50_ms,
        p90_ms,
        p95_ms,
        p99_ms,
        max_ms,
        std_dev_ms,
        sent_count,
        success_count,
        timeout_count,
        error_count,
        loss_rate,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverBenchmark {
    pub resolver: Resolver,
    pub stats: LatencyStats,
    pub sample_answers: Vec<String>,
}

pub async fn run_benchmark(
    resolvers: &[Resolver],
    domain: &str,
    qtype: RecordType,
    iterations: usize,
    concurrency: usize,
    use_tcp: bool,
    timeout: Duration,
) -> Vec<ResolverBenchmark> {
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut tasks = Vec::new();

    for resolver in resolvers {
        let res_clone = resolver.clone();
        let dom_clone = domain.to_string();
        let sem_clone = sem.clone();

        let task = tokio::spawn(async move {
            let mut durations = Vec::with_capacity(iterations);
            let mut timeouts = 0;
            let mut errors = 0;
            let mut sample_answers = Vec::new();

            for _ in 0..iterations {
                let _permit = sem_clone.acquire().await.unwrap();
                match query_dns(res_clone.addr, &dom_clone, qtype, use_tcp, timeout).await {
                    Ok((resp, dur)) => {
                        durations.push(dur.as_secs_f64() * 1000.0);
                        if sample_answers.is_empty() && !resp.answers.is_empty() {
                            sample_answers = resp.answers.into_iter().map(|a| a.data).collect();
                        }
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        if err_str.contains("Timeout") {
                            timeouts += 1;
                        } else {
                            errors += 1;
                        }
                    }
                }
            }

            let stats = calculate_stats(durations, iterations, timeouts, errors);
            ResolverBenchmark {
                resolver: res_clone,
                stats,
                sample_answers,
            }
        });

        tasks.push(task);
    }

    let mut results = Vec::new();
    for task in tasks {
        if let Ok(res) = task.await {
            results.push(res);
        }
    }

    // Sort by p50 latency (lowest first); put 100% loss at end
    results.sort_by(|a, b| {
        if a.stats.success_count == 0 && b.stats.success_count > 0 {
            std::cmp::Ordering::Greater
        } else if b.stats.success_count == 0 && a.stats.success_count > 0 {
            std::cmp::Ordering::Less
        } else {
            a.stats
                .p50_ms
                .partial_cmp(&b.stats.p50_ms)
                .unwrap_or(std::cmp::Ordering::Equal)
        }
    });

    results
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnswerGroup {
    pub answers: Vec<String>,
    pub resolvers: Vec<String>,
    pub count: usize,
    pub percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationReport {
    pub domain: String,
    pub record_type: RecordType,
    pub total_queried: usize,
    pub total_responded: usize,
    pub total_failed: usize,
    pub answer_groups: Vec<AnswerGroup>,
    pub has_drift: bool,
}

pub async fn audit_propagation(
    resolvers: &[Resolver],
    domain: &str,
    qtype: RecordType,
    use_tcp: bool,
    timeout: Duration,
) -> PropagationReport {
    let mut answer_map: HashMap<Vec<String>, Vec<String>> = HashMap::new();
    let mut total_responded = 0;
    let mut total_failed = 0;

    let mut tasks = Vec::new();
    for r in resolvers {
        let r_clone = r.clone();
        let dom = domain.to_string();
        tasks.push(tokio::spawn(async move {
            match query_dns(r_clone.addr, &dom, qtype, use_tcp, timeout).await {
                Ok((resp, _)) => {
                    let mut ans: Vec<String> = resp.answers.into_iter().map(|a| a.data).collect();
                    ans.sort();
                    Ok((r_clone.name, ans))
                }
                Err(_) => Err(r_clone.name),
            }
        }));
    }

    for task in tasks {
        if let Ok(res) = task.await {
            match res {
                Ok((name, ans)) => {
                    total_responded += 1;
                    answer_map.entry(ans).or_default().push(name);
                }
                Err(_) => {
                    total_failed += 1;
                }
            }
        }
    }

    let mut answer_groups = Vec::new();
    for (answers, mut resolver_names) in answer_map {
        resolver_names.sort();
        let count = resolver_names.len();
        let percentage = if total_responded > 0 {
            (count as f64 / total_responded as f64) * 100.0
        } else {
            0.0
        };

        answer_groups.push(AnswerGroup {
            answers,
            resolvers: resolver_names,
            count,
            percentage,
        });
    }

    answer_groups.sort_by(|a, b| b.count.cmp(&a.count));
    let has_drift = answer_groups.len() > 1;

    PropagationReport {
        domain: domain.to_string(),
        record_type: qtype,
        total_queried: resolvers.len(),
        total_responded,
        total_failed,
        answer_groups,
        has_drift,
    }
}

pub fn format_benchmark_table(
    benchmarks: &[ResolverBenchmark],
    domain: &str,
    qtype: RecordType,
    color: bool,
) -> String {
    let mut out = String::new();
    let header_title = format!("DNS Benchmark: {} ({})", domain, qtype.as_str());
    if color {
        let _ = writeln!(out, "\n{}", header_title.bold().cyan());
    } else {
        let _ = writeln!(out, "\n{}", header_title);
    }

    let header_line = format!(
        "{:<20} {:<18} {:>8} {:>8} {:>8} {:>8} {:>8} {:>7}",
        "Resolver", "Endpoint", "p50 (ms)", "p95 (ms)", "Min", "Max", "StdDev", "Loss"
    );
    let sep = "-".repeat(95);

    if color {
        let _ = writeln!(out, "{}", header_line.bold());
        let _ = writeln!(out, "{}", sep.dimmed());
    } else {
        let _ = writeln!(out, "{}", header_line);
        let _ = writeln!(out, "{}", sep);
    }

    for (rank, b) in benchmarks.iter().enumerate() {
        let name_display = if rank == 0 && b.stats.success_count > 0 {
            if color {
                format!("★ {}", b.resolver.name).green().bold().to_string()
            } else {
                format!("* {}", b.resolver.name)
            }
        } else {
            b.resolver.name.clone()
        };

        let loss_str = format!("{:.0}%", b.stats.loss_rate);
        let loss_styled = if b.stats.loss_rate > 0.0 && color {
            loss_str.red().to_string()
        } else {
            loss_str
        };

        if b.stats.success_count == 0 {
            let _ = writeln!(
                out,
                "{:<20} {:<18} {:>8} {:>8} {:>8} {:>8} {:>8} {:>7}",
                name_display, b.resolver.addr, "FAIL", "FAIL", "-", "-", "-", loss_styled
            );
        } else {
            let _ = writeln!(
                out,
                "{:<20} {:<18} {:>8.1} {:>8.1} {:>8.1} {:>8.1} {:>8.1} {:>7}",
                name_display,
                b.resolver.addr,
                b.stats.p50_ms,
                b.stats.p95_ms,
                b.stats.min_ms,
                b.stats.max_ms,
                b.stats.std_dev_ms,
                loss_styled
            );
        }
    }

    out
}

pub fn format_propagation_report(report: &PropagationReport, color: bool) -> String {
    let mut out = String::new();

    let title = format!(
        "DNS Propagation & Consistency Report: {} ({})",
        report.domain,
        report.record_type.as_str()
    );
    if color {
        let _ = writeln!(out, "\n{}", title.bold().cyan());
    } else {
        let _ = writeln!(out, "\n{}", title);
    }

    let summary = format!(
        "Queried: {} | Responded: {} | Failed: {}",
        report.total_queried, report.total_responded, report.total_failed
    );
    let _ = writeln!(out, "{}\n", summary);

    if report.has_drift {
        let warning = "⚠ DRIFT DETECTED: Resolvers returned conflicting records!"
            .red()
            .bold();
        if color {
            let _ = writeln!(out, "{}\n", warning);
        } else {
            let _ = writeln!(
                out,
                "WARNING: DRIFT DETECTED: Resolvers returned conflicting records!\n"
            );
        }
    } else {
        let ok_msg = "✔ CONSISTENT: All responding resolvers return identical records."
            .green()
            .bold();
        if color {
            let _ = writeln!(out, "{}\n", ok_msg);
        } else {
            let _ = writeln!(
                out,
                "OK: CONSISTENT: All responding resolvers return identical records.\n"
            );
        }
    }

    for (i, group) in report.answer_groups.iter().enumerate() {
        let answers_str = if group.answers.is_empty() {
            "<NO RECORDS / NODATA>".to_string()
        } else {
            group.answers.join(", ")
        };

        let badge = format!(
            "Group #{}: {} resolvers ({:.1}%)",
            i + 1,
            group.count,
            group.percentage
        );
        if color {
            let _ = writeln!(out, "{} -> {}", badge.bold().yellow(), answers_str.bold());
        } else {
            let _ = writeln!(out, "{} -> {}", badge, answers_str);
        }

        let resolver_list = group.resolvers.join(", ");
        let _ = writeln!(out, "   Resolvers: {}\n", resolver_list);
    }

    out
}
