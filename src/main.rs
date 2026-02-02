use chrono::{DateTime, Local, Utc};
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
        // Parse HTTP response: "HTTP/1.1 200 OK"
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

    // Use NT for NOTIFY packets, ST for M-SEARCH responses
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

fn create_multicast_socket() -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_reuse_address(true)?;

    #[cfg(unix)]
    socket.set_reuse_port(true)?;

    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, SSDP_PORT);
    socket.bind(&addr.into())?;

    socket.join_multicast_v4(&SSDP_ADDR, &Ipv4Addr::UNSPECIFIED)?;

    println!("Joined multicast group {} on port {}", SSDP_ADDR, SSDP_PORT);

    Ok(socket)
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
) {
    thread::spawn(move || {
        // Create a socket for M-SEARCH - bind to ephemeral port to receive unicast responses
        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to create M-SEARCH socket: {}", e);
                return;
            }
        };

        let local_port = socket.local_addr().map(|a| a.port()).unwrap_or(0);
        println!("M-SEARCH listener on port {} (for unicast responses)", local_port);

        let dest = SocketAddrV4::new(SSDP_ADDR, SSDP_PORT);
        let msearch = "M-SEARCH * HTTP/1.1\r\n\
                       HOST: 239.255.255.250:1900\r\n\
                       MAN: \"ssdp:discover\"\r\n\
                       MX: 3\r\n\
                       ST: ssdp:all\r\n\
                       \r\n";

        // Set read timeout so we can periodically send M-SEARCH
        let _ = socket.set_read_timeout(Some(Duration::from_secs(MSEARCH_INTERVAL_SECS)));

        let mut buf = [0u8; 4096];

        loop {
            // Send M-SEARCH
            if let Err(e) = socket.send_to(msearch.as_bytes(), dest) {
                eprintln!("Failed to send M-SEARCH: {}", e);
            } else {
                let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
                println!("[{}] Sent M-SEARCH discovery request", timestamp);
            }

            // Listen for responses until timeout
            let deadline = std::time::Instant::now() + Duration::from_secs(MSEARCH_INTERVAL_SECS);
            while std::time::Instant::now() < deadline {
                match socket.recv_from(&mut buf) {
                    Ok((len, addr)) => {
                        let source_ip = addr.ip().to_string();
                        let source_port = addr.port();
                        process_packet(&buf[..len], source_ip, source_port, &seen_usns, &log_writer);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // Timeout, continue to send next M-SEARCH
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                        // Timeout on Windows
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
    println!("SSDP Device Fingerprinter");
    println!("=========================");
    println!("Listening for SSDP announcements (multicast NOTIFY)");
    println!("Sending M-SEARCH every {} seconds (unicast responses)", MSEARCH_INTERVAL_SECS);
    println!("Logging packets to: {}\n", LOG_FILE);

    let log_writer = Arc::new(Mutex::new(open_log_file()?));
    let seen_usns: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

    let socket = create_multicast_socket()?;

    // Start M-SEARCH sender/receiver thread for unicast responses
    start_msearch_listener(Arc::clone(&seen_usns), Arc::clone(&log_writer));

    let mut buf = [0u8; 4096];

    // Main loop: listen for multicast NOTIFY packets
    loop {
        let (len, addr) = socket.recv_from(unsafe {
            std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut std::mem::MaybeUninit<u8>, buf.len())
        })?;

        let source_ip = addr.as_socket_ipv4().map(|a| a.ip().to_string()).unwrap_or_default();
        let source_port = addr.as_socket_ipv4().map(|a| a.port()).unwrap_or(0);

        process_packet(&buf[..len], source_ip, source_port, &seen_usns, &log_writer);
    }
}
