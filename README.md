# SSDP Device Fingerprinter

A Rust console application that passively sniffs SSDP (Simple Service Discovery Protocol) multicast packets and fingerprints network devices based on their announcement headers.

## Features

- Joins SSDP multicast group `239.255.255.250:1900`
- Sends periodic M-SEARCH discovery requests (every 30 seconds)
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

```
[2024-01-15 10:30:15] NEW DEVICE from 192.168.1.50:1900
  Method: NOTIFY
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

### JSON-NL Log

All packets are logged to `ssdp-packets.jsonl` with full metadata:

```json
{
  "timestamp": "2024-01-15T09:30:15.123Z",
  "timestamp_local": "2024-01-15 10:30:15",
  "source_ip": "192.168.1.50",
  "source_port": 1900,
  "method": "NOTIFY",
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

## Dependencies

- `socket2` - Multicast socket configuration
- `chrono` - Timestamp handling
- `serde` / `serde_json` - JSON serialization

## License

MIT
