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
use std::time::{Duration, Instant};

const SSDP_ADDR: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
const SSDP_PORT: u16 = 1900;
const MSEARCH_INTERVAL_SECS: u64 = 30;
const BUFFER_WINDOW_SECS: u64 = 30;
const LOG_FILE: &str = "ssdp-packets.jsonl";
const API_LOG_FILE: &str = "ssdp-api-request.json";

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

/// Decode M-SEARCH specific fields into human-readable format
#[derive(Debug, Clone, Serialize)]
struct MSearchDetails {
    search_target: String,
    search_target_description: String,
    max_wait_seconds: Option<u32>,
    discovery_type: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    msearch_details: Option<MSearchDetails>,
}

#[derive(Debug, Clone, Serialize)]
struct DeviceFingerprint {
    device_type: String,
    name: Option<String>,
}

#[derive(Debug, Serialize)]
struct ApiSsdpEntry {
    packet_type: String,
    headers: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    msearch_details: Option<MSearchDetails>,
}

#[derive(Debug, Serialize)]
struct ApiDevice {
    ip: String,
    ssdp: Vec<ApiSsdpEntry>,
}

#[derive(Debug, Serialize)]
struct ApiRequest {
    devices: Vec<ApiDevice>,
}

#[derive(Clone)]
struct SsdpPacket {
    packet_type: String,
    status_line: String,
    headers: HashMap<String, String>,
}

#[derive(Debug, Clone)]
enum PacketClass {
    DeviceAnnouncement,
    ClientSearch,
}

#[allow(dead_code)]
struct BufferedPacket {
    packet: SsdpPacket,
    class: PacketClass,
    source_ip: String,
    source_port: u16,
    dedup_key: String,
    fingerprint: DeviceFingerprint,
    msearch_details: Option<MSearchDetails>,
    received_at: Instant,
}

struct PacketBuffer {
    packets: Vec<BufferedPacket>,
    window_start: Instant,
}

fn classify_packet(packet: &SsdpPacket) -> Option<PacketClass> {
    let man = packet.headers.get("MAN").map(|s| s.to_lowercase());
    if let Some(ref man_val) = man {
        if man_val.contains("ssdp:discover") {
            return Some(PacketClass::ClientSearch);
        }
    }

    if packet.headers.contains_key("USN") || packet.headers.contains_key("NTS") {
        return Some(PacketClass::DeviceAnnouncement);
    }

    None
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

fn extract_uuid_from_usn(usn: &str) -> Option<String> {
    if let Some(start) = usn.find("uuid:") {
        let rest = &usn[start + 5..];
        if let Some(end) = rest.find("::") {
            return Some(rest[..end].to_string());
        }
        return Some(rest.to_string());
    }
    None
}

fn compute_dedup_key(class: &PacketClass, packet: &SsdpPacket, source_ip: &str) -> String {
    match class {
        PacketClass::DeviceAnnouncement => {
            packet
                .headers
                .get("USN")
                .and_then(|usn| extract_uuid_from_usn(usn))
                .unwrap_or_else(|| source_ip.to_string())
        }
        PacketClass::ClientSearch => {
            let st = packet.headers.get("ST").cloned().unwrap_or_default();
            format!("{}:{}", source_ip, st)
        }
    }
}

fn fingerprint_msearch_sender(headers: &HashMap<String, String>) -> DeviceFingerprint {
    let user_agent = headers.get("USER-AGENT").cloned();
    let st = headers.get("ST").cloned();

    let ua_lower = user_agent.as_ref().map(|s| s.to_lowercase()).unwrap_or_default();
    let st_lower = st.as_ref().map(|s| s.to_lowercase()).unwrap_or_default();

    let device_type = if ua_lower.contains("chromecast") || ua_lower.contains("castdevice") {
        "Chromecast"
    } else if ua_lower.contains("roku") {
        "Roku"
    } else if ua_lower.contains("samsung") || ua_lower.contains("tizen") {
        "Samsung TV"
    } else if ua_lower.contains("lg") || ua_lower.contains("webos") {
        "LG TV"
    } else if ua_lower.contains("sonos") {
        "Sonos"
    } else if ua_lower.contains("hue") || ua_lower.contains("philips") {
        "Philips Hue"
    } else if ua_lower.contains("darwin") || ua_lower.contains("apple") || ua_lower.contains("ios") {
        "Apple Device"
    } else if ua_lower.contains("microsoft") || ua_lower.contains("windows") {
        "Windows"
    } else if ua_lower.contains("android") {
        "Android Device"
    } else if ua_lower.contains("linux") {
        "Linux Device"
    } else if ua_lower.contains("plex") {
        "Plex Client"
    } else if ua_lower.contains("kodi") || ua_lower.contains("xbmc") {
        "Kodi"
    } else if ua_lower.contains("vlc") {
        "VLC"
    } else if ua_lower.contains("nvidia") || ua_lower.contains("shield") {
        "NVIDIA Shield"
    } else if ua_lower.contains("synology") {
        "Synology NAS"
    } else if ua_lower.contains("qnap") {
        "QNAP NAS"
    } else if ua_lower.contains("fing") || ua_lower.contains("fingbox") {
        "Fing Fingbox"
    } else if ua_lower.contains("upnp") || ua_lower.contains("dlna") {
        "UPnP/DLNA Client"
    } else if st_lower.contains("dial-multiscreen") {
        "DIAL Client"
    } else if st_lower.contains("mediarenderer") {
        "Media Renderer Client"
    } else if st_lower.contains("mediaserver") {
        "Media Server Client"
    } else if st_lower == "ssdp:all" || st_lower == "upnp:rootdevice" {
        "UPnP Scanner"
    } else {
        "Unknown"
    }
    .to_string();

    // Extract name from USER-AGENT (first product/version token)
    let name = user_agent.as_ref().map(|ua| {
        ua.split_whitespace()
            .next()
            .unwrap_or("Unknown")
            .to_string()
    });

    DeviceFingerprint { device_type, name }
}

fn decode_msearch_details(headers: &HashMap<String, String>) -> MSearchDetails {
    let st = headers.get("ST").cloned().unwrap_or_else(|| "unknown".to_string());
    let mx = headers.get("MX").and_then(|s| s.parse::<u32>().ok());
    let man = headers.get("MAN").cloned().unwrap_or_default();

    let st_description = decode_search_target(&st);

    let discovery_type = if man.contains("ssdp:discover") {
        "Standard SSDP Discovery"
    } else {
        "Custom Discovery"
    }
    .to_string();

    MSearchDetails {
        search_target: st,
        search_target_description: st_description,
        max_wait_seconds: mx,
        discovery_type,
    }
}

fn decode_search_target(st: &str) -> String {
    let st_lower = st.to_lowercase();

    if st_lower == "ssdp:all" {
        "All UPnP devices and services".to_string()
    } else if st_lower == "upnp:rootdevice" {
        "All UPnP root devices".to_string()
    } else if st_lower.starts_with("uuid:") {
        format!("Specific device with UUID: {}", &st[5..])
    } else if st_lower.starts_with("urn:schemas-upnp-org:device:") {
        let device_type = st.split(':').nth(3).unwrap_or("unknown");
        format!("UPnP device type: {}", device_type)
    } else if st_lower.starts_with("urn:schemas-upnp-org:service:") {
        let service_type = st.split(':').nth(3).unwrap_or("unknown");
        format!("UPnP service type: {}", service_type)
    } else if st_lower.contains("dial-multiscreen") {
        "DIAL protocol (Chromecast/Smart TV casting)".to_string()
    } else if st_lower.contains("mediarenderer") {
        "DLNA Media Renderer".to_string()
    } else if st_lower.contains("mediaserver") {
        "DLNA Media Server".to_string()
    } else if st_lower.contains("basicdevice") {
        "UPnP Basic Device".to_string()
    } else if st_lower.contains("internetgatewaydevice") {
        "Internet Gateway Device (Router)".to_string()
    } else if st_lower.contains("wanconnection") || st_lower.contains("wanipconnection") {
        "WAN Connection Service".to_string()
    } else if st_lower.starts_with("urn:") {
        format!("Custom URN: {}", st)
    } else {
        format!("Custom search target: {}", st)
    }
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

fn deduplicate(packets: Vec<BufferedPacket>) -> Vec<BufferedPacket> {
    let mut seen = HashSet::new();
    packets
        .into_iter()
        .filter(|p| seen.insert(p.dedup_key.clone()))
        .collect()
}

fn build_api_batch(packets: &[BufferedPacket]) -> ApiRequest {
    let mut by_ip: HashMap<String, Vec<ApiSsdpEntry>> = HashMap::new();

    for p in packets {
        let ssdp_entry = ApiSsdpEntry {
            packet_type: p.packet.packet_type.clone(),
            headers: p.packet.headers.clone(),
            msearch_details: p.msearch_details.clone(),
        };
        by_ip
            .entry(p.source_ip.clone())
            .or_default()
            .push(ssdp_entry);
    }

    let devices = by_ip
        .into_iter()
        .map(|(ip, ssdp)| ApiDevice { ip, ssdp })
        .collect();

    ApiRequest { devices }
}

fn write_api_batch(request: &ApiRequest) {
    if let Ok(json) = serde_json::to_string_pretty(request) {
        if let Ok(mut file) = File::create(API_LOG_FILE) {
            let _ = file.write_all(json.as_bytes());
        }
    }
}

fn flush_buffer(buffer: &Arc<Mutex<PacketBuffer>>) {
    let packets = {
        let mut buf = buffer.lock().unwrap();
        let packets = std::mem::take(&mut buf.packets);
        buf.window_start = Instant::now();
        packets
    };

    if packets.is_empty() {
        return;
    }

    let total = packets.len();
    let deduped = deduplicate(packets);
    let unique = deduped.len();
    let batch = build_api_batch(&deduped);
    write_api_batch(&batch);

    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
    println!(
        "[{}] BATCH FLUSH: {} packets received, {} unique after dedup, {} sources",
        timestamp, total, unique, batch.devices.len()
    );
}

fn start_flush_timer(buffer: Arc<Mutex<PacketBuffer>>) {
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(BUFFER_WINDOW_SECS));
        flush_buffer(&buffer);
    });
}

fn print_packet(entry: &SsdpLogEntry) {
    println!("[{}] PACKET from {}:{}", entry.timestamp_local, entry.source_ip, entry.source_port);
    println!("  Type: {}", entry.packet_type);
    println!("  Status: {}", entry.status_line);

    if let Some(fp) = &entry.fingerprint {
        println!("  Fingerprint: {}", fp.device_type);
        if let Some(name) = &fp.name {
            if entry.packet_type == "M-SEARCH" {
                println!("  User-Agent: {}", name);
            } else {
                println!("  Device Name: {}", name);
            }
        }
    }

    // Print M-SEARCH decoded details
    if let Some(details) = &entry.msearch_details {
        println!("  M-SEARCH Details:");
        println!("    Search Target: {} ({})", details.search_target, details.search_target_description);
        if let Some(mx) = details.max_wait_seconds {
            println!("    Max Wait: {} seconds", mx);
        }
        println!("    Discovery Type: {}", details.discovery_type);
    }

    println!("  Headers:");
    let mut sorted_headers: Vec<_> = entry.headers.iter().collect();
    sorted_headers.sort_by_key(|(k, _)| k.as_str());
    for (key, value) in sorted_headers {
        println!("    {}: {}", key, value);
    }
    println!();
}

fn ingest_packet(
    data: &[u8],
    source_ip: String,
    source_port: u16,
    buffer: &Arc<Mutex<PacketBuffer>>,
    log_writer: &Arc<Mutex<BufWriter<File>>>,
) {
    let Some(packet) = parse_ssdp_packet(data) else {
        return;
    };

    let Some(class) = classify_packet(&packet) else {
        return;
    };

    let dedup_key = compute_dedup_key(&class, &packet, &source_ip);

    let (fingerprint, msearch_details) = match class {
        PacketClass::ClientSearch => {
            let fp = fingerprint_msearch_sender(&packet.headers);
            let details = decode_msearch_details(&packet.headers);
            (fp, Some(details))
        }
        PacketClass::DeviceAnnouncement => (fingerprint_device(&packet.headers), None),
    };

    let now = Utc::now();
    let entry = SsdpLogEntry {
        timestamp: now,
        timestamp_local: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        source_ip: source_ip.clone(),
        source_port,
        packet_type: packet.packet_type.clone(),
        status_line: packet.status_line.clone(),
        headers: packet.headers.clone(),
        fingerprint: Some(fingerprint.clone()),
        msearch_details: msearch_details.clone(),
    };

    write_log_entry(log_writer, &entry);
    print_packet(&entry);

    let buffered = BufferedPacket {
        packet,
        class,
        source_ip,
        source_port,
        dedup_key,
        fingerprint,
        msearch_details,
        received_at: Instant::now(),
    };

    buffer.lock().unwrap().packets.push(buffered);
}

fn start_msearch_listener(
    buffer: Arc<Mutex<PacketBuffer>>,
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
                        ingest_packet(&buf[..len], source_ip, source_port, &buffer, &log_writer);
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
    println!("Logging packets to: {}", LOG_FILE);
    println!("Logging API requests to: {}\n", API_LOG_FILE);

    let log_writer = Arc::new(Mutex::new(open_log_file()?));
    let buffer = Arc::new(Mutex::new(PacketBuffer {
        packets: Vec::new(),
        window_start: Instant::now(),
    }));

    let socket = create_multicast_socket(local_ip)?;

    // Start flush timer for batched API output
    start_flush_timer(Arc::clone(&buffer));

    // Start M-SEARCH sender/receiver thread for unicast responses
    start_msearch_listener(Arc::clone(&buffer), Arc::clone(&log_writer), local_ip);

    let mut buf = [0u8; 4096];

    println!("Waiting for packets...\n");

    // Main loop: listen for multicast NOTIFY packets
    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, addr)) => {
                let source_ip = addr.ip().to_string();
                let source_port = addr.port();
                ingest_packet(&buf[..len], source_ip, source_port, &buffer, &log_writer);
            }
            Err(e) => {
                eprintln!("Error receiving packet: {}", e);
            }
        }
    }
}
