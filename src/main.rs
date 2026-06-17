use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs::File;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

mod args;
mod scanner;
mod utils;

use args::Args;

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
        match utils::parse_ip_range(&ip_arg) {
            Ok(ips) => ips,
            Err(e) => {
                println!("\x1b[1;31mError in CLI IP range argument: {}\x1b[0m", e);
                utils::prompt_ip_list()
            }
        }
    } else {
        utils::prompt_ip_list()
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
            utils::prompt_protocol()
        }
    } else {
        utils::prompt_protocol()
    };

    // Load or prompt for port
    let port = if let Some(port_arg) = args.port {
        if port_arg > 0 {
            port_arg
        } else {
            println!(
                "\x1b[1;31mError: CLI port must be 1-65535. Falling back to interactive.\x1b[0m"
            );
            utils::prompt_port()
        }
    } else {
        utils::prompt_port()
    };

    // Load source port (0 means random/ephemeral port assigned by OS)
    let source_port = args.source_port.unwrap_or(0);

    // Load or prompt for timeout
    let timeout_ms = args.timeout.unwrap_or_else(utils::prompt_timeout);

    // Load or prompt for concurrency
    let concurrency = args.concurrency.unwrap_or_else(utils::prompt_concurrency);

    // Load or prompt for output file
    let output_file = args
        .output
        .unwrap_or_else(|| utils::read_input("Enter output text file path", Some("results.txt")));

    // Load UDP payload from hex argument or --nec flag.
    let udp_payload = if args.nec {
        utils::parse_hex("010100080001008f00000000").unwrap()
    } else if !args.data.is_empty() {
        utils::parse_hex(&args.data).unwrap_or_else(|| {
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
                let is_open = scanner::check_ip_port(ip, port, source_port, timeout_dur).await;
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
        match scanner::scan_udp_single_socket(
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
