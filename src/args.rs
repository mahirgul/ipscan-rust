use clap::Parser;

/// IP and Port Scanner - Rust High-Performance Tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// IP address, CIDR block, or range (e.g., 192.168.1.1, 192.168.1.0/24, 192.168.1.1-50)
    #[arg(short, long)]
    pub ip: Option<String>,

    /// Protocol (TCP or UDP)
    #[arg(short = 'P', long)]
    pub protocol: Option<String>,

    /// Port number to scan (1-65535)
    #[arg(short, long)]
    pub port: Option<u16>,

    /// Source port for outgoing connections (0 or omitted binds to a random system port)
    #[arg(short = 's', long)]
    pub source_port: Option<u16>,

    /// Connection timeout in milliseconds
    #[arg(short, long)]
    pub timeout: Option<u64>,

    /// Max concurrency (simultaneous connections)
    #[arg(short, long)]
    pub concurrency: Option<usize>,

    /// Output text file path
    #[arg(short, long)]
    pub output: Option<String>,

    /// Hex-encoded data payload to send for UDP scans
    #[arg(short = 'd', long, default_value = "")]
    pub data: String,

    /// Send the special NEC UDP payload (010100080126008f0a1703f1)
    #[arg(long)]
    pub nec: bool,
}
