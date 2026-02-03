use chrono::{DateTime, Local, Utc};
use clap::Parser;
use if_addrs::get_if_addrs;
use serde::Serialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const SSDP_ADDR: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const SSDP_PORT: u16 = 1900;
const MSEARCH_INTERVAL_SECS: u64 = 30;
const LOG_FILE: &str = "ssdp-packets.jsonl";

#[derive(Parser, Debug)]
#[command(name = "ssdp-fingerprint")]
#[command(about = "SSDP Device Fingerprinter - Listen for SSDP announcements and fingerprint devices")]
struct Args {
    /// List available network interfaces and exit
    #[arg(short = 'l', long)]
    list_interfaces: bool,

    /// Network interface to use (e.g., en0, eth0)
    #[arg(short, long)]
    interface: Option<String>,

    /// Local IP address to bind to (alternative to --interface)
    #[arg(short = 'b', long)]
    bind_ip: Option<Ipv4Addr>,
}

fn list_interfaces() {
    println!("Available network interfaces:");
    println!("{:-<60}", "");
    println!("{:<20} {:<20} {:<10}", "INTERFACE", "IPv4 ADDRESS", "TYPE");
    println!("{:-<60}", "");

    match get_if_addrs() {
        Ok(interfaces) => {
            for iface in interfaces {
                if let if_addrs::IfAddr::V4(v4) = &iface.addr {
                    let iface_type = if iface.is_loopback() {
                        "loopback"
                    } else if iface.name.starts_with("utun") || iface.name.starts_with("tun") {
                        "VPN/tunnel"
                    } else if iface.name.starts_with("en") || iface.name.starts_with("eth") {
                        "ethernet"
                    } else if iface.name.starts_with("wlan") || iface.name.starts_with("wl") {
                        "wireless"
                    } else if iface.name.starts_with("bridge") || iface.name.starts_with("br") {
                        "bridge"
                    } else {
                        "other"
                    };
                    println!("{:<20} {:<20} {:<10}", iface.name, v4.ip, iface_type);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to list interfaces: {}", e);
        }
    }
    println!("{:-<60}", "");
    println!("\nUsage: ssdp-fingerprint --interface <NAME> or --bind-ip <IP>");
}

fn resolve_interface_ip(args: &Args) -> Option<Ipv4Addr> {
    // If bind_ip is specified, use it directly
    if let Some(ip) = args.bind_ip {
        return Some(ip);
    }

    // If interface name is specified, look up its IP
    if let Some(ref iface_name) = args.interface {
        if let Ok(interfaces) = get_if_addrs() {
            for iface in interfaces {
                if iface.name == *iface_name {
                    if let if_addrs::IfAddr::V4(v4) = &iface.addr {
                        return Some(v4.ip);
                    }
                }
            }
        }
        eprintln!("Warning: Interface '{}' not found or has no IPv4 address", iface_name);
        return None;
    }

    // Fall back to auto-detection
    None
}

#[derive(Debug, Serialize)]
struct SsdpLogEntry {
    timestamp: DateTime<Utc>,
    timestamp_local: String,
    source_ip: String,
    source_port: u16,
    packet_type: String,
    status_line: String,
    headers: HashMap<String, String>,
    fingerprint: Option<DeviceFingerprint>,
    is_new_device: bool,
}

#[derive(Debug, Clone, Serialize)]
struct DeviceFingerprint {
    device_type: String,
    name: Option<String>,
}

struct SsdpPacket {
    packet_type: String,
    status_line: String,
    headers: HashMap<String, String>,
}

fn parse_ssdp_packet(data: &[u8]) -> Option<SsdpPacket> {
    let text = std::str::from_utf8(data).ok()?;
    let mut lines = text.lines();

    let first_line = lines.next()?.trim();
    let (packet_type, status_line) = if first_line.starts_with("NOTIFY") {
        ("NOTIFY".to_string(), first_line.to_string())
    } else if first_line.starts_with("M-SEARCH") {
        ("M-SEARCH".to_string(), first_line.to_string())
    } else if first_line.starts_with("HTTP/") {
        let status_line = first_line.to_string();
        let packet_type = if first_line.contains("200") {
            "HTTP 200 OK".to_string()
        } else {
            format!("HTTP RESPONSE ({})", first_line)
        };
        (packet_type, status_line)
    } else {
        return None;
    };

    let mut headers = HashMap::new();
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(pos) = line.find(':') {
            let key = line[..pos].trim().to_uppercase();
            let value = line[pos + 1..].trim().to_string();
            headers.insert(key, value);
        }
    }

    Some(SsdpPacket { packet_type, status_line, headers })
}

fn fingerprint_device(headers: &HashMap<String, String>) -> DeviceFingerprint {
    let server = headers.get("SERVER").cloned();
    let usn = headers.get("USN").cloned();

    let service_type = headers.get("NT")
        .or_else(|| headers.get("ST"))
        .cloned();

    let server_lower = server.as_ref().map(|s| s.to_lowercase()).unwrap_or_default();
    let st_lower = service_type.as_ref().map(|s| s.to_lowercase()).unwrap_or_default();

    let device_type = if server_lower.contains("castdevice") || st_lower.contains("dial-multiscreen") {
        "Chromecast"
    } else if server_lower.contains("roku") || st_lower.contains("roku") {
        "Roku"
    } else if server_lower.contains("sec_hhp_") || server_lower.contains("samsung") {
        "Samsung TV"
    } else if server_lower.contains("lg smart tv") || server_lower.contains("webos") {
        "LG TV"
    } else if server_lower.contains("sonos") {
        "Sonos"
    } else if server_lower.contains("ipbridge") || server_lower.contains("hue") {
        "Philips Hue"
    } else if server_lower.contains("darwin") || server_lower.contains("apple") {
        "Apple Device"
    } else if server_lower.contains("microsoft-windows") || server_lower.contains("windows/") {
        "Windows"
    } else if server_lower.contains("plex") {
        "Plex Media Server"
    } else if server_lower.contains("kodi") || server_lower.contains("xbmc") {
        "Kodi"
    } else if server_lower.contains("nvidia") {
        "NVIDIA Shield"
    } else if server_lower.contains("synology") {
        "Synology NAS"
    } else if server_lower.contains("qnap") {
        "QNAP NAS"
    } else if server_lower.contains("fingbox") {
        "Fing Fingbox"
    } else if st_lower.contains("mediarenderer") {
        "Media Renderer"
    } else if st_lower.contains("mediaserver") {
        "Media Server"
    } else if st_lower.contains("upnp:rootdevice") {
        "UPnP Device"
    } else {
        "Unknown"
    }
    .to_string();

    let name = extract_device_name(&usn, &server);

    DeviceFingerprint { device_type, name }
}

fn extract_device_name(usn: &Option<String>, server: &Option<String>) -> Option<String> {
    if let Some(usn) = usn {
        if let Some(start) = usn.find("uuid:") {
            let rest = &usn[start + 5..];
            if let Some(end) = rest.find("::") {
                return Some(rest[..end].to_string());
            }
            return Some(rest.to_string());
        }
    }
    server.as_ref().map(|s| {
        s.split_whitespace()
            .next()
            .unwrap_or("Unknown")
            .to_string()
    })
}

fn get_local_ip_auto() -> Option<Ipv4Addr> {
    // Try to find a non-loopback IPv4 address by checking default route
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    match socket.local_addr().ok()? {
        std::net::SocketAddr::V4(addr) => Some(*addr.ip()),
        _ => None,
    }
}

fn create_multicast_socket(local_ip: Ipv4Addr) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_reuse_address(true)?;

    #[cfg(unix)]
    socket.set_reuse_port(true)?;

    // Bind to INADDR_ANY on the SSDP port
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, SSDP_PORT);
    socket.bind(&addr.into())?;

    println!("Local IP for multicast: {}", local_ip);

    // Join multicast group on the specific interface
    socket.join_multicast_v4(&SSDP_ADDR, &local_ip)?;

    // Enable multicast loopback to see our own packets (useful for debugging)
    socket.set_multicast_loop_v4(true)?;

    println!("Joined multicast group {} on port {}", SSDP_ADDR, SSDP_PORT);

    // Convert socket2::Socket to std::net::UdpSocket
    let std_socket: UdpSocket = socket.into();

    Ok(std_socket)
}

fn open_log_file() -> io::Result<BufWriter<File>> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE)?;
    Ok(BufWriter::new(file))
}

fn write_log_entry(writer: &Arc<Mutex<BufWriter<File>>>, entry: &SsdpLogEntry) {
    if let Ok(json) = serde_json::to_string(entry) {
        if let Ok(mut w) = writer.lock() {
            let _ = writeln!(w, "{}", json);
            let _ = w.flush();
        }
    }
}

fn print_packet(entry: &SsdpLogEntry) {
    let marker = if entry.is_new_device { "NEW DEVICE" } else { "PACKET" };
    println!("[{}] {} from {}:{}", entry.timestamp_local, marker, entry.source_ip, entry.source_port);
    println!("  Type: {}", entry.packet_type);
    println!("  Status: {}", entry.status_line);

    if let Some(fp) = &entry.fingerprint {
        println!("  Fingerprint: {}", fp.device_type);
        if let Some(name) = &fp.name {
            println!("  Device Name: {}", name);
        }
    }

    println!("  Headers:");
    let mut sorted_headers: Vec<_> = entry.headers.iter().collect();
    sorted_headers.sort_by_key(|(k, _)| k.as_str());
    for (key, value) in sorted_headers {
        println!("    {}: {}", key, value);
    }
    println!();
}

fn process_packet(
    data: &[u8],
    source_ip: String,
    source_port: u16,
    seen_usns: &Arc<Mutex<HashSet<String>>>,
    log_writer: &Arc<Mutex<BufWriter<File>>>,
) {
    let Some(packet) = parse_ssdp_packet(data) else {
        return;
    };

    // Skip M-SEARCH requests (we only care about responses/notifications)
    if packet.packet_type == "M-SEARCH" {
        return;
    }

    let usn = packet.headers.get("USN").cloned().unwrap_or_default();

    let is_new_device = if !usn.is_empty() {
        let mut seen = seen_usns.lock().unwrap();
        if seen.contains(&usn) {
            false
        } else {
            seen.insert(usn.clone());
            true
        }
    } else {
        false
    };

    let fingerprint = fingerprint_device(&packet.headers);
    let now = Utc::now();

    let entry = SsdpLogEntry {
        timestamp: now,
        timestamp_local: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        source_ip,
        source_port,
        packet_type: packet.packet_type,
        status_line: packet.status_line,
        headers: packet.headers,
        fingerprint: Some(fingerprint),
        is_new_device,
    };

    write_log_entry(log_writer, &entry);
    print_packet(&entry);
}

fn start_msearch_listener(
    seen_usns: Arc<Mutex<HashSet<String>>>,
    log_writer: Arc<Mutex<BufWriter<File>>>,
    local_ip: Ipv4Addr,
) {
    thread::spawn(move || {
        // Bind to the specific interface IP to ensure M-SEARCH goes out on the right interface
        let bind_addr = SocketAddrV4::new(local_ip, 0);
        let socket = match UdpSocket::bind(bind_addr) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to create M-SEARCH socket on {}: {}", local_ip, e);
                return;
            }
        };

        let local_port = socket.local_addr().map(|a| a.port()).unwrap_or(0);
        println!("M-SEARCH listener on {}:{} (for unicast responses)", local_ip, local_port);

        let dest = SocketAddrV4::new(SSDP_ADDR, SSDP_PORT);
        let msearch = "M-SEARCH * HTTP/1.1\r\n\
                       HOST: 239.255.255.250:1900\r\n\
                       MAN: \"ssdp:discover\"\r\n\
                       MX: 3\r\n\
                       ST: ssdp:all\r\n\
                       \r\n";

        let _ = socket.set_read_timeout(Some(Duration::from_secs(MSEARCH_INTERVAL_SECS)));

        let mut buf = [0u8; 4096];

        loop {
            if let Err(e) = socket.send_to(msearch.as_bytes(), dest) {
                eprintln!("Failed to send M-SEARCH: {}", e);
            } else {
                let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
                println!("[{}] Sent M-SEARCH discovery request", timestamp);
            }

            let deadline = std::time::Instant::now() + Duration::from_secs(MSEARCH_INTERVAL_SECS);
            while std::time::Instant::now() < deadline {
                match socket.recv_from(&mut buf) {
                    Ok((len, addr)) => {
                        let source_ip = addr.ip().to_string();
                        let source_port = addr.port();
                        process_packet(&buf[..len], source_ip, source_port, &seen_usns, &log_writer);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                        break;
                    }
                    Err(e) => {
                        eprintln!("Error receiving M-SEARCH response: {}", e);
                        break;
                    }
                }
            }
        }
    });
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    // Handle --list-interfaces
    if args.list_interfaces {
        list_interfaces();
        return Ok(());
    }

    // Resolve the local IP to use
    let local_ip = resolve_interface_ip(&args)
        .or_else(get_local_ip_auto)
        .unwrap_or(Ipv4Addr::UNSPECIFIED);

    println!("SSDP Device Fingerprinter");
    println!("=========================");
    if args.interface.is_some() || args.bind_ip.is_some() {
        println!("Using interface IP: {}", local_ip);
    } else {
        println!("Auto-detected interface IP: {}", local_ip);
    }
    println!("Listening for SSDP announcements (multicast NOTIFY)");
    println!("Sending M-SEARCH every {} seconds (unicast responses)", MSEARCH_INTERVAL_SECS);
    println!("Logging packets to: {}\n", LOG_FILE);

    let log_writer = Arc::new(Mutex::new(open_log_file()?));
    let seen_usns: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

    let socket = create_multicast_socket(local_ip)?;

    // Start M-SEARCH sender/receiver thread for unicast responses
    start_msearch_listener(Arc::clone(&seen_usns), Arc::clone(&log_writer), local_ip);

    let mut buf = [0u8; 4096];

    println!("Waiting for packets...\n");

    // Main loop: listen for multicast NOTIFY packets
    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, addr)) => {
                let source_ip = addr.ip().to_string();
                let source_port = addr.port();
                process_packet(&buf[..len], source_ip, source_port, &seen_usns, &log_writer);
            }
            Err(e) => {
                eprintln!("Error receiving packet: {}", e);
            }
        }
    }
}
