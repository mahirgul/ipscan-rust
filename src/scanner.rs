use indicatif::ProgressBar;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::timeout;

pub async fn check_ip_port(ip: IpAddr, port: u16, source_port: u16, timeout_dur: Duration) -> bool {
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
    #[cfg(not(target_os = "windows"))]
    let _ = socket.set_reuse_port(true);

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

pub fn get_routing_ip(target_addr: SocketAddr) -> Option<IpAddr> {
    let bind_addr = if target_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let temp_socket = std::net::UdpSocket::bind(bind_addr).ok()?;
    temp_socket.connect(target_addr).ok()?;
    let local_addr = temp_socket.local_addr().ok()?;
    Some(local_addr.ip())
}

#[allow(clippy::too_many_arguments)]
pub async fn scan_udp_single_socket(
    ip_list: Vec<IpAddr>,
    port: u16,
    source_port: u16,
    payload: Vec<u8>,
    is_nec: bool,
    timeout_ms: u64,
    concurrency: usize,
    pb: ProgressBar,
) -> anyhow::Result<Vec<IpAddr>> {
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
    let target_ips_set: Arc<HashSet<IpAddr>> = Arc::new(ip_list.iter().cloned().collect());

    // Spawn listener task
    let tokio_socket_clone = Arc::clone(&tokio_socket);
    let active_ips_clone = Arc::clone(&active_ips);
    let target_ips_set_clone = Arc::clone(&target_ips_set);

    let listener_handle = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            match tokio_socket_clone.recv_from(&mut buf).await {
                Ok((_len, src_addr)) => {
                    let ip = src_addr.ip();
                    if target_ips_set_clone.contains(&ip) {
                        let mut ips = active_ips_clone.lock().await;
                        ips.insert(ip);
                    }
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
