# ipscan

A high-performance, asynchronous IP and Port Scanner written in Rust, designed for both TCP and UDP port scanning with advanced networking features.

## Features

- **Asynchronous TCP Scanning**: Conducts concurrent 3-way handshake checks across target IP ranges using Tokio's thread pool.
- **Single-Socket UDP Scanning**: Employs a high-performance single-socket listener/sender architecture to scan thousands of UDP targets concurrently without local port binding conflicts (`AddrInUse`).
- **Dynamic IP Payload Injection (NEC Mode)**: Automatically detects the local routing IP address and dynamically injects it into the UDP payload (useful for custom device discovery protocols like NEC where the device replies to the IP specified inside the payload).
- **Custom Hex Payload Support**: Allows sending any custom hex-encoded payload for UDP discovery.
- **Local Source Port Binding**: Supports binding outbound scan traffic to a specific local source port (e.g., `-s 20111` or `-s 53`).
- **Graceful Shutdown (`Ctrl+C`)**: Captures interrupts, immediately halts active scans, sorts discovered active IPs, and saves them to the output file before exiting.
- **Multiple IP Formats**: Supports single IPs, ranges (e.g., `192.168.1.1-50`), and CIDR blocks (e.g., `192.168.1.0/24`).

---

## Installation & Build

Ensure you have [Rust and Cargo](https://rustup.rs/) installed.

```bash
# Clone the repository
git clone https://github.com/your-username/ipscan.git
cd ipscan

# Build optimized release binary
cargo build --release
```

The compiled binary will be available at `./target/release/ipscan` (or `ipscan.exe` on Windows).

---

## Usage Examples

Run without parameters to fall back to interactive prompting mode:
```bash
./ipscan
```

### Command-Line Arguments

| Flag | Long Flag | Description | Default |
| :--- | :--- | :--- | :--- |
| `-i` | `--ip` | Target IP, CIDR block, or range (e.g., `10.9.6.0/24`, `192.168.1.1-100`) | *Prompted if omitted* |
| `-P` | `--protocol` | Protocol to scan (`TCP` or `UDP`) | *Prompted if omitted* |
| `-p` | `--port` | Target port number (1-65535) | *Prompted if omitted* |
| `-s` | `--source-port` | Outgoing local source port (0 for random OS-allocated) | `0` |
| `-t` | `--timeout` | Socket connection timeout in milliseconds | `1000` |
| `-c` | `--concurrency` | Maximum simultaneous connections / packets | `200` |
| `-o` | `--output` | Output text file path for saving active IP addresses | `results.txt` |
| `-d` | `--data` | Custom hex-encoded payload to send for UDP scans | `""` |
| | `--nec` | Enables special NEC UDP payload with dynamic local IP injection | `false` |

---

### Examples

#### 1. NEC UDP Discovery Scan
Scan a Class C subnet on port `3530` using the local source port `20111` in NEC mode with a 2-second timeout:
```bash
./ipscan -i 10.9.6.0/24 -P UDP -p 3530 -s 20111 --nec -t 2000
```
*In this mode, the program automatically binds to local port `20111`, discovers the correct outgoing IP, writes it into the 12-byte payload `01 01 00 08 00 01 00 8f [Your-IP]`, sends it to all targets, and logs devices that reply.*

#### 2. Fast TCP Port Scan
Scan a range of IPs on port `80` with a concurrency limit of `500` and a fast `200ms` timeout:
```bash
./ipscan -i 192.168.1.1-150 -P TCP -p 80 -c 500 -t 200 -o web_servers.txt
```

#### 3. Custom UDP Payload Scan
Send a custom hex payload (e.g. `AABBCCDD`) to port `5000`:
```bash
./ipscan -i 192.168.1.0/24 -P UDP -p 5000 -d "AA BB CC DD"
```

---

## Multi-Platform Releases (GitHub Actions)

This repository includes a GitHub Actions CI workflow to compile and release the application for multiple platforms:
- **Windows** (`x86_64-pc-windows-msvc`)
- **Linux** (`x86_64-unknown-linux-gnu`)
- **macOS** (`x86_64-apple-darwin` / Apple Silicon)

To trigger a release:
1. Create a new tag: `git tag v1.0.0`
2. Push the tag: `git push origin v1.0.0`

GitHub Actions will automatically build the binaries, package them in `.zip` / `.tar.gz` files, and attach them to a new GitHub Release.
