# SSDP Device Fingerprinter

A Rust console application that sniffs SSDP (Simple Service Discovery Protocol) packets and fingerprints network devices based on their announcement headers.

## Features

- Joins SSDP multicast group `239.255.255.250:1900`
- Sends periodic M-SEARCH discovery requests (every 30 seconds)
- Handles two packet types:
  - **NOTIFY** - Multicast announcements from devices
  - **HTTP 200 OK** - Unicast responses to M-SEARCH requests
- Parses and displays all SSDP packet headers
- Fingerprints 16+ device types including:
  - Chromecast
  - Roku
  - Samsung TV
  - LG TV
  - Sonos
  - Philips Hue
  - Apple devices
  - Windows
  - Plex Media Server
  - Synology/QNAP NAS
  - Generic UPnP devices
- Logs all packets to JSON-NL file (`ssdp-packets.jsonl`)
- Deduplicates devices by USN (Unique Service Name)

## Building

```bash
cargo build --release
```

## Running

Binding to port 1900 typically requires root privileges:

```bash
sudo ./target/release/ssdp-fingerprint
```

## Output

### Console

**NOTIFY packet (multicast announcement):**
```
[2024-01-15 10:30:15] NEW DEVICE from 192.168.1.50:1900
  Type: NOTIFY
  Status: NOTIFY * HTTP/1.1
  Fingerprint: Chromecast
  Device Name: abc123-def456
  Headers:
    CACHE-CONTROL: max-age=1800
    HOST: 239.255.255.250:1900
    LOCATION: http://192.168.1.50:8008/ssdp/device-desc.xml
    NT: urn:dial-multiscreen-org:service:dial:1
    NTS: ssdp:alive
    SERVER: Linux/3.8 UPnP/1.0 CastDevice/1.0
    USN: uuid:abc123-def456::urn:dial-multiscreen-org:service:dial:1
```

**HTTP 200 OK packet (unicast M-SEARCH response):**
```
[2024-01-15 10:30:18] NEW DEVICE from 192.168.1.100:1900
  Type: HTTP 200 OK
  Status: HTTP/1.1 200 OK
  Fingerprint: Samsung TV
  Device Name: uuid-samsung-tv-123
  Headers:
    CACHE-CONTROL: max-age=1800
    EXT:
    LOCATION: http://192.168.1.100:9197/dmr
    SERVER: SHP, UPnP/1.0, Samsung UPnP SDK/1.0
    ST: urn:schemas-upnp-org:device:MediaRenderer:1
    USN: uuid:uuid-samsung-tv-123::urn:schemas-upnp-org:device:MediaRenderer:1
```

### JSON-NL Log

All packets are logged to `ssdp-packets.jsonl` with full metadata:

```json
{
  "timestamp": "2024-01-15T09:30:15.123Z",
  "timestamp_local": "2024-01-15 10:30:15",
  "source_ip": "192.168.1.50",
  "source_port": 1900,
  "packet_type": "NOTIFY",
  "status_line": "NOTIFY * HTTP/1.1",
  "headers": {
    "NT": "urn:dial-multiscreen-org:service:dial:1",
    "SERVER": "Linux/3.8 UPnP/1.0 CastDevice/1.0"
  },
  "fingerprint": {
    "device_type": "Chromecast",
    "name": "abc123-def456"
  },
  "is_new_device": true
}
```

```json
{
  "timestamp": "2024-01-15T09:30:18.456Z",
  "timestamp_local": "2024-01-15 10:30:18",
  "source_ip": "192.168.1.100",
  "source_port": 1900,
  "packet_type": "HTTP 200 OK",
  "status_line": "HTTP/1.1 200 OK",
  "headers": {
    "ST": "urn:schemas-upnp-org:device:MediaRenderer:1",
    "SERVER": "SHP, UPnP/1.0, Samsung UPnP SDK/1.0"
  },
  "fingerprint": {
    "device_type": "Samsung TV",
    "name": "uuid-samsung-tv-123"
  },
  "is_new_device": true
}
```

## How It Works

1. **Multicast listener** - Binds to port 1900 and joins the SSDP multicast group to receive NOTIFY announcements that devices broadcast periodically.

2. **M-SEARCH sender** - Sends discovery requests to the multicast group every 30 seconds. Devices respond with unicast HTTP 200 OK packets directly to the sender.

3. **Unicast listener** - A separate socket on an ephemeral port receives the HTTP 200 OK responses from devices.

4. **Fingerprinting** - Uses the `SERVER` header and service type (`NT` for NOTIFY, `ST` for responses) to identify device types.

## Dependencies

- `socket2` - Multicast socket configuration
- `chrono` - Timestamp handling
- `serde` / `serde_json` - JSON serialization

## License

MIT
