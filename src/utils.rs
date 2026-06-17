use ipnet::IpNet;
use std::io::{self, Write};
use std::net::IpAddr;

pub fn read_input(prompt: &str, default: Option<&str>) -> String {
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

pub fn parse_ip_range(input: &str) -> anyhow::Result<Vec<IpAddr>> {
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

    // 4. Try resolving as a domain/hostname
    use std::net::ToSocketAddrs;
    if let Ok(addrs) = (input, 0).to_socket_addrs() {
        let ips: Vec<IpAddr> = addrs.map(|addr| addr.ip()).collect();
        if !ips.is_empty() {
            return Ok(ips);
        }
    }

    anyhow::bail!(
        "Invalid IP/Host format. Supported options: single IP (e.g., 192.168.1.1), domain (e.g., localhost), CIDR (e.g., 192.168.1.0/24), IP range (e.g., 192.168.1.1-50)"
    )
}

pub fn ip_range_between(start: IpAddr, end: IpAddr) -> anyhow::Result<Vec<IpAddr>> {
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

pub fn prompt_ip_list() -> Vec<IpAddr> {
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

pub fn prompt_protocol() -> String {
    loop {
        let proto_input = read_input("Enter Protocol (TCP/UDP)", Some("TCP")).to_uppercase();
        if proto_input == "TCP" || proto_input == "UDP" {
            break proto_input;
        }
        println!("\x1b[1;31mError: Please enter TCP or UDP.\x1b[0m");
    }
}

pub fn prompt_port() -> u16 {
    loop {
        let port_input = read_input("Enter Port to scan (1-65535)", None);
        match port_input.parse::<u16>() {
            Ok(p) if p > 0 => break p,
            _ => println!("\x1b[1;31mError: Please enter a valid port number (1-65535).\x1b[0m"),
        }
    }
}

pub fn prompt_timeout() -> u64 {
    loop {
        let timeout_input = read_input("Enter connection timeout in milliseconds", Some("1000"));
        match timeout_input.parse::<u64>() {
            Ok(t) if t > 0 => break t,
            _ => println!("\x1b[1;31mError: Please enter a valid timeout in milliseconds.\x1b[0m"),
        }
    }
}

pub fn prompt_concurrency() -> usize {
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

pub fn parse_hex(hex: &str) -> Option<Vec<u8>> {
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
