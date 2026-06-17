use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use ipnet::IpNet;
use std::fs::File;
use std::io::{self, Write};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// IP and Port Scanner - Rust High-Performance Tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// IP address, CIDR block, or range (e.g., 192.168.1.1, 192.168.1.0/24, 192.168.1.1-50)
    #[arg(short, long)]
    ip: Option<String>,

    /// Protocol (TCP or UDP)
    #[arg(short = 'P', long)]
    protocol: Option<String>,

    /// Port number to scan (1-65535)
    #[arg(short, long)]
    port: Option<u16>,

    /// Source port for outgoing connections (0 or omitted binds to a random system port)
    #[arg(short = 's', long)]
    source_port: Option<u16>,

    /// Connection timeout in milliseconds
    #[arg(short, long)]
    timeout: Option<u64>,

    /// Max concurrency (simultaneous connections)
    #[arg(short, long)]
    concurrency: Option<usize>,

    /// Output text file path
    #[arg(short, long)]
    output: Option<String>,

    /// Hex-encoded data payload to send for UDP scans
    #[arg(short = 'd', long, default_value = "")]
    data: String,

    /// Send the special NEC UDP payload (010100080126008f0a1703f1)
    #[arg(long)]
    nec: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Welcome message
    println!("\x1b[1;36m====================================================\x1b[0m");
    println!("\x1b[1;36m    IP & Port Scanner - Rust High-Performance Tool  \x1b[0m");
    println!("\x1b[1;36m====================================================\x1b[0m");
    println!();

    // Preprocess arguments to map "-nec" to "--nec"
    let mut args_list: Vec<String> = std::env::args().collect();
    for arg in args_list.iter_mut() {
        if arg == "-nec" {
            *arg = "--nec".to_string();
        }
    }
    let args = Args::parse_from(args_list);
    println!();

    // Load or prompt for IP list
    let ip_list = if let Some(ip_arg) = args.ip {
        match parse_ip_range(&ip_arg) {
            Ok(ips) => ips,
            Err(e) => {
                println!("\x1b[1;31mError in CLI IP range argument: {}\x1b[0m", e);
                prompt_ip_list()
            }
        }
    } else {
        prompt_ip_list()
    };

    // Load or prompt for protocol
    let protocol = if let Some(proto_arg) = args.protocol {
        let proto = proto_arg.to_uppercase();
        if proto == "TCP" || proto == "UDP" {
            proto
        } else {
            println!(
                "\x1b[1;31mError: CLI protocol must be TCP or UDP. Falling back to interactive.\x1b[0m"
            );
            prompt_protocol()
        }
    } else {
        prompt_protocol()
    };

    // Load or prompt for port
    let port = if let Some(port_arg) = args.port {
        if port_arg > 0 {
            port_arg
        } else {
            println!(
                "\x1b[1;31mError: CLI port must be 1-65535. Falling back to interactive.\x1b[0m"
            );
            prompt_port()
        }
    } else {
        prompt_port()
    };

    // Load source port (0 means random/ephemeral port assigned by OS)
    let source_port = args.source_port.unwrap_or(0);

    // Load or prompt for timeout
    let timeout_ms = args.timeout.unwrap_or_else(prompt_timeout);

    // Load or prompt for concurrency
    let concurrency = args.concurrency.unwrap_or_else(prompt_concurrency);

    // Load or prompt for output file
    let output_file = args
        .output
        .unwrap_or_else(|| read_input("Enter output text file path", Some("results.txt")));

    // Load UDP payload from hex argument or --nec flag.
    // If --nec is enabled, we use a template payload where the last 4 bytes will be replaced
    // dynamically with the local IPv4 address of the interface used to contact the host.
    let udp_payload = if args.nec {
        parse_hex("010100080001008f00000000").unwrap()
    } else if !args.data.is_empty() {
        parse_hex(&args.data).unwrap_or_else(|| {
            println!("\x1b[1;31mError: Invalid hex data payload. Using empty payload.\x1b[0m");
            Vec::new()
        })
    } else {
        Vec::new()
    };

    println!();
    println!("\x1b[1;32m[+] Starting scan with the following parameters:\x1b[0m");
    println!("    - Total IPs to scan : {}", ip_list.len());
    println!("    - Protocol          : {}", protocol);
    println!("    - Target Port       : {}", port);
    if source_port > 0 {
        println!("    - Source Port       : {}", source_port);
    } else {
        println!("    - Source Port       : Random (OS managed)");
    }
    if protocol == "UDP" {
        if args.nec {
            println!("    - UDP Payload (Hex) : 010100080001008f[Local IP] (NEC Mode)");
        } else if !args.data.is_empty() {
            println!("    - UDP Payload (Hex) : {}", args.data);
        } else {
            println!("    - UDP Payload (Hex) : None (Empty)");
        }
    }
    println!("    - Connection Timeout: {} ms", timeout_ms);
    println!("    - Max Concurrency   : {}", concurrency);
    println!("    - Output File       : {}", output_file);
    println!();

    let pb = ProgressBar::new(ip_list.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} (ETA: {eta})")?
            .progress_chars("#>-"),
    );

    let mut active_ips = Vec::new();

    if protocol == "TCP" {
        let semaphore = Arc::new(Semaphore::new(concurrency));
        let mut tasks = Vec::new();
        let active_ips_shared = Arc::new(tokio::sync::Mutex::new(Vec::new()));

        for ip in ip_list {
            let sem = Arc::clone(&semaphore);
            let timeout_dur = Duration::from_millis(timeout_ms);
            let pb_clone = pb.clone();
            let active_ips_clone = Arc::clone(&active_ips_shared);

            tasks.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let is_open = check_ip_port(ip, port, source_port, timeout_dur).await;
                pb_clone.inc(1);
                if is_open {
                    let mut ips = active_ips_clone.lock().await;
                    ips.push(ip);
                }
            }));
        }

        tokio::select! {
            _ = async {
                for task in tasks {
                    let _ = task.await;
                }
            } => {}
            _ = tokio::signal::ctrl_c() => {
                println!();
                println!("\x1b[1;33m[!] Scan interrupted by Ctrl+C. Saving partial results...\x1b[0m");
            }
        }

        active_ips = active_ips_shared.lock().await.clone();
    } else {
        // UDP Single-Socket Scanning
        match scan_udp_single_socket(
            ip_list,
            port,
            source_port,
            udp_payload,
            args.nec,
            timeout_ms,
            concurrency,
            pb.clone(),
        )
        .await
        {
            Ok(ips) => active_ips = ips,
            Err(e) => {
                println!("\x1b[1;31mError during UDP scan: {}\x1b[0m", e);
            }
        }
    }

    pb.finish_with_message("Scan complete!");

    // Sort the active IPs
    active_ips.sort();

    println!();
    println!("\x1b[1;32m[+] Scan Finished!\x1b[0m");
    println!(
        "    - Found {} active device(s) listening on port {} ({})",
        active_ips.len(),
        port,
        protocol
    );
    println!();

    if !active_ips.is_empty() {
        println!("\x1b[1;36mActive IP Addresses:\x1b[0m");
        for ip in &active_ips {
            println!("  - {}", ip);
        }
        println!();

        // Save to file
        let mut file = File::create(&output_file)?;
        for ip in &active_ips {
            writeln!(file, "{}", ip)?;
        }
        println!(
            "\x1b[1;32m[+] Results successfully saved to: {}\x1b[0m",
            output_file
        );
    } else {
        println!(
            "\x1b[1;33m[-] No active devices were found listening on port {}.\x1b[0m",
            port
        );
    }

    Ok(())
}

fn read_input(prompt: &str, default: Option<&str>) -> String {
    if let Some(def) = default {
        print!("{} [Default: {}]: ", prompt, def);
    } else {
        print!("{}: ", prompt);
    }
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let trimmed = input.trim().to_string();
    if trimmed.is_empty() {
        default.unwrap_or("").to_string()
    } else {
        trimmed
    }
}

async fn check_ip_port(ip: IpAddr, port: u16, source_port: u16, timeout_dur: Duration) -> bool {
    let addr = SocketAddr::new(ip, port);

    // Create socket based on IP version
    let domain = match ip {
        IpAddr::V4(_) => socket2::Domain::IPV4,
        IpAddr::V6(_) => socket2::Domain::IPV6,
    };

    let socket =
        match socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP)) {
            Ok(s) => s,
            Err(_) => return false,
        };

    // Bind to the specified local source port if defined
    let local_addr = match ip {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), source_port),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), source_port),
    };

    // reuse_address can help with address-already-in-use errors when using fixed source ports rapidly
    let _ = socket.set_reuse_address(true);

    if socket.bind(&local_addr.into()).is_err() {
        return false;
    }

    if socket.set_nonblocking(true).is_err() {
        return false;
    }

    // Initiate non-blocking connection via socket2
    let _ = socket.connect(&addr.into());

    let std_socket: std::net::TcpStream = socket.into();
    let tokio_socket = match tokio::net::TcpStream::from_std(std_socket) {
        Ok(s) => s,
        Err(_) => return false,
    };

    match timeout(timeout_dur, tokio_socket.writable()).await {
        Ok(Ok(())) => {
            // Once writable, check if peer_addr is Ok to confirm connection success
            tokio_socket.peer_addr().is_ok()
        }
        _ => false,
    }
}

fn get_routing_ip(target_addr: SocketAddr) -> Option<IpAddr> {
    let bind_addr = if target_addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let temp_socket = std::net::UdpSocket::bind(bind_addr).ok()?;
    temp_socket.connect(target_addr).ok()?;
    let local_addr = temp_socket.local_addr().ok()?;
    Some(local_addr.ip())
}

#[allow(clippy::too_many_arguments)]
async fn scan_udp_single_socket(
    ip_list: Vec<IpAddr>,
    port: u16,
    source_port: u16,
    payload: Vec<u8>,
    is_nec: bool,
    timeout_ms: u64,
    concurrency: usize,
    pb: ProgressBar,
) -> anyhow::Result<Vec<IpAddr>> {
    use std::collections::HashSet;
    use tokio::sync::Mutex;

    let is_ipv6 = ip_list.first().is_some_and(|ip| ip.is_ipv6());
    let local_addr = if is_ipv6 {
        SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), source_port)
    } else {
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), source_port)
    };

    let domain = if is_ipv6 {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    let _ = socket.set_reuse_address(true);

    socket.bind(&local_addr.into())?;
    socket.set_nonblocking(true)?;

    let std_socket: std::net::UdpSocket = socket.into();
    let tokio_socket = Arc::new(tokio::net::UdpSocket::from_std(std_socket)?);

    let active_ips = Arc::new(Mutex::new(HashSet::new()));

    // Spawn listener task
    let tokio_socket_clone = Arc::clone(&tokio_socket);
    let active_ips_clone = Arc::clone(&active_ips);

    let listener_handle = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            match tokio_socket_clone.recv_from(&mut buf).await {
                Ok((_len, src_addr)) => {
                    let mut ips = active_ips_clone.lock().await;
                    ips.insert(src_addr.ip());
                }
                Err(e) => {
                    // ConnectionReset (WSAECONNRESET) is very common on Windows when sending to closed UDP ports.
                    // We must ignore it and continue listening.
                    if e.kind() == std::io::ErrorKind::ConnectionReset
                        || e.kind() == std::io::ErrorKind::ConnectionRefused
                    {
                        continue;
                    }
                    // For other errors, yield briefly to avoid 100% CPU usage if the socket enters a bad state
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        }
    });

    // Sender loop with rate limiting
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut send_tasks = Vec::new();

    for ip in ip_list {
        let sem = Arc::clone(&semaphore);
        let tokio_socket_send = Arc::clone(&tokio_socket);
        let payload_clone = payload.clone();
        let pb_send = pb.clone();

        send_tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let target_addr = SocketAddr::new(ip, port);

            let mut final_payload = payload_clone;
            if is_nec && final_payload.len() >= 12 {
                let routing_ip = get_routing_ip(target_addr);
                if let Some(IpAddr::V4(ipv4)) = routing_ip {
                    let octets = ipv4.octets();
                    let len = final_payload.len();
                    final_payload[len - 4..=len - 1].copy_from_slice(&octets);
                }
            }

            let _ = tokio_socket_send.send_to(&final_payload, target_addr).await;
            pb_send.inc(1);
        }));
    }

    tokio::select! {
        _ = async {
            for task in send_tasks {
                let _ = task.await;
            }
            // Wait for the timeout duration for replies to arrive
            tokio::time::sleep(Duration::from_millis(timeout_ms)).await;
        } => {}
        _ = tokio::signal::ctrl_c() => {
            println!();
            println!("\x1b[1;33m[!] Scan interrupted by Ctrl+C. Saving partial results...\x1b[0m");
        }
    }

    listener_handle.abort();

    let final_ips = active_ips
        .lock()
        .await
        .iter()
        .cloned()
        .collect::<Vec<IpAddr>>();
    Ok(final_ips)
}

fn parse_ip_range(input: &str) -> anyhow::Result<Vec<IpAddr>> {
    let input = input.trim();

    // 1. Try parsing as CIDR (e.g., 192.168.1.0/24)
    if let Ok(net) = input.parse::<IpNet>() {
        return Ok(net.hosts().collect());
    }

    // 2. Try parsing as IP range with dash (e.g., 192.168.1.1-192.168.1.100 or 192.168.1.1-100)
    if input.contains('-') {
        let parts: Vec<&str> = input.split('-').map(|s| s.trim()).collect();
        if parts.len() == 2 {
            let start_ip_str = parts[0];
            let end_ip_str = parts[1];

            if let Ok(start_ip) = start_ip_str.parse::<IpAddr>() {
                if let Ok(end_ip) = end_ip_str.parse::<IpAddr>() {
                    // Start and end are fully qualified IPs (e.g., 192.168.1.1-192.168.1.100)
                    return ip_range_between(start_ip, end_ip);
                } else if let Ok(end_octet) = end_ip_str.parse::<u8>() {
                    // End is just a number (e.g., 192.168.1.1-100)
                    if let IpAddr::V4(ipv4) = start_ip {
                        let octets = ipv4.octets();
                        if end_octet >= octets[3] {
                            let mut ips = Vec::new();
                            for o3 in octets[3]..=end_octet {
                                ips.push(IpAddr::V4(std::net::Ipv4Addr::new(
                                    octets[0], octets[1], octets[2], o3,
                                )));
                            }
                            return Ok(ips);
                        } else {
                            anyhow::bail!(
                                "End octet ({}) must be greater than or equal to start octet ({})",
                                end_octet,
                                octets[3]
                            );
                        }
                    }
                }
            }
        }
    }

    // 3. Try parsing as a single IP address
    if let Ok(ip) = input.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    anyhow::bail!(
        "Invalid IP format. Supported options: single IP (e.g., 192.168.1.1), CIDR (e.g., 192.168.1.0/24), IP range (e.g., 192.168.1.1-50 or 192.168.1.1-192.168.1.50)"
    )
}

fn ip_range_between(start: IpAddr, end: IpAddr) -> anyhow::Result<Vec<IpAddr>> {
    match (start, end) {
        (IpAddr::V4(start_v4), IpAddr::V4(end_v4)) => {
            let start_u32 = u32::from(start_v4);
            let end_u32 = u32::from(end_v4);
            if start_u32 > end_u32 {
                anyhow::bail!("Start IP must be less than or equal to End IP");
            }
            let ips = (start_u32..=end_u32)
                .map(|ip_u32| IpAddr::V4(std::net::Ipv4Addr::from(ip_u32)))
                .collect();
            Ok(ips)
        }
        (IpAddr::V6(start_v6), IpAddr::V6(end_v6)) => {
            let start_u128 = u128::from(start_v6);
            let end_u128 = u128::from(end_v6);
            if start_u128 > end_u128 {
                anyhow::bail!("Start IP must be less than or equal to End IP");
            }
            // Limit V6 range generation to a reasonable size to prevent OOM
            let diff = end_u128 - start_u128;
            if diff > 100_000 {
                anyhow::bail!("IPv6 range is too large (maximum size is 100,000 addresses)");
            }
            let ips = (start_u128..=end_u128)
                .map(|ip_u128| IpAddr::V6(std::net::Ipv6Addr::from(ip_u128)))
                .collect();
            Ok(ips)
        }
        _ => anyhow::bail!("IP version mismatch (cannot mix IPv4 and IPv6 in range)"),
    }
}

fn prompt_ip_list() -> Vec<IpAddr> {
    loop {
        let ip_input = read_input(
            "Enter IP, CIDR, or Range (e.g. 192.168.1.0/24, 192.168.1.1-50)",
            None,
        );
        if ip_input.is_empty() {
            println!("\x1b[1;31mError: Input cannot be empty.\x1b[0m");
            continue;
        }
        match parse_ip_range(&ip_input) {
            Ok(ips) => {
                if ips.is_empty() {
                    println!("\x1b[1;31mError: No valid IP addresses found in the range.\x1b[0m");
                    continue;
                }
                break ips;
            }
            Err(e) => {
                println!("\x1b[1;31mError: {}\x1b[0m", e);
            }
        }
    }
}

fn prompt_protocol() -> String {
    loop {
        let proto_input = read_input("Enter Protocol (TCP/UDP)", Some("TCP")).to_uppercase();
        if proto_input == "TCP" || proto_input == "UDP" {
            break proto_input;
        }
        println!("\x1b[1;31mError: Please enter TCP or UDP.\x1b[0m");
    }
}

fn prompt_port() -> u16 {
    loop {
        let port_input = read_input("Enter Port to scan (1-65535)", None);
        match port_input.parse::<u16>() {
            Ok(p) if p > 0 => break p,
            _ => println!("\x1b[1;31mError: Please enter a valid port number (1-65535).\x1b[0m"),
        }
    }
}

fn prompt_timeout() -> u64 {
    loop {
        let timeout_input = read_input("Enter connection timeout in milliseconds", Some("1000"));
        match timeout_input.parse::<u64>() {
            Ok(t) if t > 0 => break t,
            _ => println!("\x1b[1;31mError: Please enter a valid timeout in milliseconds.\x1b[0m"),
        }
    }
}

fn prompt_concurrency() -> usize {
    loop {
        let concurrency_input = read_input(
            "Enter max concurrency (simultaneous connections)",
            Some("200"),
        );
        match concurrency_input.parse::<usize>() {
            Ok(c) if c > 0 => break c,
            _ => println!("\x1b[1;31mError: Please enter a valid concurrency number.\x1b[0m"),
        }
    }
}

fn parse_hex(hex: &str) -> Option<Vec<u8>> {
    let clean_hex: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    if !clean_hex.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(clean_hex.len() / 2);
    for i in (0..clean_hex.len()).step_by(2) {
        let byte_str = &clean_hex[i..i + 2];
        let byte = u8::from_str_radix(byte_str, 16).ok()?;
        bytes.push(byte);
    }
    Some(bytes)
}
