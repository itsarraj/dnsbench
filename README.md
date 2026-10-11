# dnsbench

A fast, concurrent multi-resolver DNS benchmarking and propagation auditing CLI tool.

`dnsbench` replaces slow manual `dig @...` shell loops and clunky web tools with an instant, parallel command-line utility. It queries multiple public resolvers (Cloudflare, Google, Quad9, OpenDNS, AdGuard) and local system resolvers in parallel, computing statistical latency distributions (min, p50, p95, p99, stddev, loss) and auditing record propagation consistency across global networks. Built with a pure-Rust RFC 1035 wire protocol engine.

---

## Status

**Status: Complete & Verified**
- Pure-Rust RFC 1035 wire format encoder and decoder verified (labels, compression pointers, A, AAAA, CNAME, MX, TXT, NS, SOA records).
- Concurrent benchmarking verified against live mock UDP resolvers: percentile latency calculation, packet loss tracking, and latency ranking.
- Propagation and answer drift detection verified: flags discrepancies and groups resolvers by matching responses.
- Supports both UDP and TCP DNS transports.
- *Deferred*: DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) are planned for a subsequent release.

---

## Features

- **Zero C Dependencies**: Built from scratch with a native asynchronous RFC 1035 wire codec.
- **Concurrent Resolver Benchmarking**: Measures latency distributions across multiple resolvers simultaneously:
  - Computes `Min`, `Mean`, `p50`, `p90`, `p95`, `p99`, `Max`, `StdDev`, and `Packet Loss %`.
  - Automatically highlights and ranks the fastest resolver for your network.
- **Built-in Public Resolver Pool**: Includes Cloudflare (`1.1.1.1`, `1.0.0.1`), Google (`8.8.8.8`, `8.8.4.4`), Quad9 (`9.9.9.9`), OpenDNS (`208.67.222.222`), AdGuard (`94.140.14.14`), and automatically discovers local resolvers from `/etc/resolv.conf`.
- **Propagation & Drift Auditor (`--audit`)**:
  - Checks if record updates (IP migrations, CNAME rotations, DKIM/SPF additions) have propagated across global resolvers.
  - Groups resolvers returning identical records and flags answer discrepancies.
- **Full Record Type Support**: Query `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `PTR`, `SRV`, `CAA`.
- **Dual Transport**: Supports standard UDP queries with optional TCP fallback (`--tcp`).
- **Structured JSON Output**: Output raw results as JSON (`--json`) for automated health checks, CI/CD validation, and dashboards.

---

## Installation

```bash
cargo install --path .
```

---

## Usage

### 1. Benchmark Resolvers

Benchmark default public and local system resolvers against a domain:
```bash
dnsbench google.com
```

Benchmark 20 iterations per resolver over TCP:
```bash
dnsbench -n 20 --tcp cloudflare.com
```

Benchmark specific record types (e.g. MX or TXT):
```bash
dnsbench -t MX github.com
dnsbench -t TXT _dmarc.google.com
```

Benchmark custom internal or private resolvers:
```bash
dnsbench -r 10.0.0.53 -r 192.168.1.1 -r 1.1.1.1 internal.corp
```

### 2. DNS Propagation & Drift Audit

Audit propagation across all resolvers after a DNS record update:
```bash
dnsbench --audit mynewapp.com
```

Audit TXT / DKIM record propagation:
```bash
dnsbench --audit -t TXT google._domainkey.example.com
```

### 3. Automation & JSON Output

Emit full benchmark statistics as JSON:
```bash
dnsbench --json rust-lang.org | jq '.[0]'
```

---

## CLI Reference

| Option | Description | Default |
|---|---|---|
| `[DOMAIN]` | Domain name to query | `google.com` |
| `-t, --type <TYPE>` | Record type (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, etc.) | `A` |
| `-n, --iterations <N>` | Number of queries per resolver | `5` |
| `-c, --concurrency <N>` | Maximum concurrent queries in flight | `10` |
| `-r, --resolver <ADDR>` | Custom resolver address(es) (repeatable) | None |
| `--system-only` | Benchmark only local resolvers from `/etc/resolv.conf` | False |
| `--public-only` | Benchmark only public resolvers | False |
| `--tcp` | Query via TCP transport instead of UDP | False |
| `--audit`, `--check` | Run propagation & answer consistency audit | False |
| `--timeout <MS>` | Per-query timeout in milliseconds | `2000` |
| `-j, --json` | Output structured JSON | False |
| `--no-color` | Disable ANSI terminal styling | Color enabled |

---

## License

MIT License. Copyright (c) 2026 Animesh Raj.
