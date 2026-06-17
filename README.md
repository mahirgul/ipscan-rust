# 🚀 ipscan

[![GitHub Actions Build Status](https://github.com/mahirgul/ipscan-rust/actions/workflows/release.yml/badge.svg)](https://github.com/mahirgul/ipscan-rust/actions/workflows/release.yml)
[![Crates.io Version](https://img.shields.io/crates/v/ipscan?style=flat-square&color=orange)](https://crates.io/crates/ipscan)
[![Crates.io Downloads](https://img.shields.io/crates/d/ipscan?style=flat-square&color=green)](https://crates.io/crates/ipscan)
[![License](https://img.shields.io/crates/l/ipscan?style=flat-square&color=blue)](https://crates.io/crates/ipscan)
[![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgray.svg?style=flat-square)](#)

A high-performance, asynchronous IP and Port Scanner written in Rust. Designed for fast network discovery using concurrent TCP checks and conflict-free single-socket UDP probing with dynamic client IP injection.

---

## ✨ Features

- **⚡ Asynchronous TCP Scanning**: High-speed, concurrent 3-way handshake checking using Tokio's work-stealing thread pool.
- **📡 Single-Socket UDP Scanning**: Probes thousands of UDP targets concurrently using a single local port socket, completely avoiding `AddrInUse` (Address already in use) conflicts.
- **🏷️ Dynamic IP Injection (NEC Mode)**: Automatically detects the scanning machine's routing IP and dynamically patches it into the UDP packet payload (solving destination routing issues for device discovery).
- **🔧 Local Source Port Binding**: Allows outgoing traffic to originate from a fixed port of your choice (e.g. `-s 20111` or `-s 53` for DNS traversal).
- **📥 Custom UDP Payloads**: Send arbitrary hex-encoded packets to match custom services.
- **⏹️ Graceful Interrupt Handling**: Pressing `Ctrl+C` instantly interrupts the scan, compiles results collected up to that moment, writes them sorted to the output file, and exits cleanly.
- **🎯 Multiple Range Formats**: Supports single IPs, numeric ranges (`192.168.1.1-100`), and CIDR notations (`192.168.1.0/24`).

---

## 📦 Installation & Setup

You can install `ipscan` directly from **crates.io** or build it from source.

### Option A: Install from Crates.io (Recommended)
```bash
cargo install ipscan
```

### Option B: Build from Source
```bash
# Clone the repository
git clone https://github.com/mahirgul/ipscan-rust.git
cd ipscan-rust

# Build optimized release binary
cargo build --release
```
The compiled binary will be placed in `./target/release/ipscan` (or `ipscan.exe` on Windows).

---

## 🛠️ Command-Line Interface

Run the binary without parameters to fall back to the interactive mode:
```bash
ipscan
```

### Options Guide

| Flag | Long Flag | Description | Default |
| :--- | :--- | :--- | :--- |
| `-i` | `--ip` | Target IP, CIDR block, or range (e.g., `10.9.6.0/24`, `192.168.1.1-100`) | *Prompted if omitted* |
| `-P` | `--protocol` | Protocol to scan (`TCP` or `UDP`) | *Prompted if omitted* |
| `-p` | `--port` | Target port number (1-65535) | *Prompted if omitted* |
| `-s` | `--source-port` | Outgoing local source port (0 for random OS-allocated) | `0` |
| `-t` | `--timeout` | Connection timeout in milliseconds | `1000` |
| `-c` | `--concurrency` | Maximum simultaneous connections / packets | `200` |
| `-o` | `--output` | Output text file path for saving active IP addresses | `results.txt` |
| `-d` | `--data` | Custom hex-encoded payload to send for UDP scans | `""` |
| | `--nec` | Enables special NEC UDP payload with dynamic local IP injection | `false` |

---

## 💡 Practical Examples

### 1. NEC UDP Discovery Scan
Scan a Class C subnet on port `3530` using the local source port `20111` with a 2-second timeout:
```bash
ipscan -i 10.9.6.0/24 -P UDP -p 3530 -s 20111 --nec -t 2000
```
*This binds to local port `20111`, queries the local routing table, dynamically injects your host IP into the last 4 bytes of the payload, sends it to all targets, and listens for replies.*

### 2. High-Speed TCP Port Scan
Scan a range of IPs on port `80` with a concurrency limit of `500` and a fast `200ms` timeout:
```bash
ipscan -i 192.168.1.1-150 -P TCP -p 80 -c 500 -t 200 -o web_servers.txt
```

### 3. Custom UDP Payload Scan
Send a custom hex payload (`AABBCCDD`) to port `5000`:
```bash
ipscan -i 192.168.1.0/24 -P UDP -p 5000 -d "AA BB CC DD"
```

---

## 🤖 CI/CD Release Automation

The repository includes a GitHub Actions CI workflow in `.github/workflows/release.yml` that builds and packages binaries for:
- **Windows** (`x86_64-pc-windows-msvc`)
- **Linux** (`x86_64-unknown-linux-gnu`)
- **macOS** (`x86_64-apple-darwin` / Apple Silicon)

### How to trigger a release:
1. Tag your commit: `git tag v1.0.0`
2. Push the tag: `git push origin v1.0.0`
3. GitHub Actions will compile the binaries, upload them to a new GitHub Release, and automatically publish the updated crate to `crates.io`. (Make sure you configure `CRATES_IO_TOKEN` in your repository secrets!).
