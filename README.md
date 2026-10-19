# AegisFlow: High-Throughput C++ DPI & Cryptographic Posture Engine

[![AegisFlow CI](https://github.com/GoodAsur2023/AegisFlow/actions/workflows/ci.yml/badge.svg)](https://github.com/GoodAsur2023/AegisFlow/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++ Standard](https://img.shields.io/badge/Language-C%2B%2B17%20%2F%20C%2B%2B20-00599C?logo=c%2B%2B)](https://en.cppreference.com/)
[![Python Version](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python)](https://www.python.org/)

**AegisFlow** is a modern, high-performance, multi-threaded Deep Packet Inspection (DPI) and Cryptographic Posture Auditing system engineered in C++17 with a Python automated remediation control plane.

Designed for defensive security engineering, vulnerability management, and line-rate flow inspection, AegisFlow replaces conventional mutex-heavy packet pipelines with **lock-free Single-Producer Single-Consumer (SPSC) ring buffers** and **zero-copy 5-tuple flow tracking**. Alongside Layer 7 application classification and dynamic policy filtering, it performs passive **cryptographic posture auditing (RFC 8996 TLS 1.0/1.1 deprecation, weak cipher detection, and JA3 fingerprinting)** and **passive service banner exposure analysis (SSH, HTTP, FTP, SMTP)** correlated against known CVEs.

---

## Architecture Overview

```
                      ┌────────────────────────────────────────┐
                      │          PCAP / Live Interface         │
                      └───────────────────┬────────────────────┘
                                          │ Raw Packets
                                          ▼
                               ┌─────────────────────┐
                               │   Zero-Copy Reader  │
                               └──────────┬──────────┘
                                          │ 5-Tuple Hash
                    ┌─────────────────────┴─────────────────────┐
                    ▼ (Lock-Free SPSC)                          ▼ (Lock-Free SPSC)
           ┌─────────────────┐                         ┌─────────────────┐
           │ Load Balancer 0 │                         │ Load Balancer 1 │
           └────────┬────────┘                         └────────┬────────┘
                    │ 5-Tuple Hash                              │ 5-Tuple Hash
          ┌─────────┴─────────┐                       ┌─────────┴─────────┐
          ▼                   ▼                       ▼                   ▼
 ┌─────────────────┐ ┌─────────────────┐     ┌─────────────────┐ ┌─────────────────┐
 │  FastPath FP 0  │ │  FastPath FP 1  │     │  FastPath FP 2  │ │  FastPath FP 3  │
 │ (Lock-Free SPSC)│ │ (Lock-Free SPSC)│     │ (Lock-Free SPSC)│ │ (Lock-Free SPSC)│
 └────────┬────────┘ └────────┬────────┘     └────────┬────────┘ └────────┬────────┘
          │                   │                       │                   │
          └───────────────────┼───────────────────────┴───────────────────┘
                              ▼
    ┌─────────────────────────────────────────────────────────────────┐
    │                Inspection & Classification Engine               │
    │  • L7 App Classification (SNI / HTTP Host / DNS / QUIC)         │
    │  • Cryptographic Posture (TLS 1.0/1.1 Deprecation, Weak Ciphers)│
    │  • JA3 Client Fingerprinting (Ciphers + Extensions + Curves)    │
    │  • Passive Service Banner & CVE Matching (SSH, HTTP, FTP, SMTP) │
    │  • Policy Enforcement & Forward/Drop Decision                   │
    └─────────────────┬───────────────────────────────┬───────────────┘
                      │ Forwarded Traffic             │ Security Telemetry
                      ▼                               ▼
          ┌───────────────────────┐       ┌───────────────────────────────┐
          │ Filtered Output PCAP  │       │ JSONLines Stream: alerts.jsonl│
          └───────────────────────┘       └───────────────┬───────────────┘
                                                          ▼
                                          ┌───────────────────────────────┐
                                          │     Python Control Plane      │
                                          │   (CVE Remediation Advisor)   │
                                          │   • CVSS Risk Scoring         │
                                          │   • Nginx/OpenSSL SSL Patches │
                                          │   • OpenSSH Hardening Configs │
                                          │   • Firewall Containment      │
                                          └───────────────────────────────┘
```

---

## Key Engineering Highlights

### 1. Lock-Free SPSC Ring Buffers (`include/spsc_queue.h`)
- Replaces mutex-based `std::queue` with a cacheline-aligned (`alignas(64)`), lock-free **Single-Producer Single-Consumer (SPSC)** circular buffer.
- Eliminates CPU false sharing between reader and worker threads on multi-core systems.
- Power-of-2 capacity constraints (`Capacity & (Capacity - 1) == 0`) replace slow modulo division with bitwise masking.
- Producer and consumer synchronize via explicit `std::memory_order_acquire` and `std::memory_order_release` semantics.

### 2. Zero-Copy 5-Tuple Flow Architecture (`include/types.h`)
- Direct binary IPv4 representation (`uint32_t`) and ports (`uint16_t`) throughout the packet lifecycle.
- 64-bit Murmur/Boost-style bit-mixing hash (`FiveTupleHash`) for O(1) flow dispatching with minimal hash collision rates.
- Dotted-decimal string formatting is strictly deferred to report generation and telemetry emission.

### 3. Cryptographic Posture & JA3 Fingerprinting (`src/sni_extractor.cpp`)
- **Protocol Deprecation Auditing**: Identifies connections negotiating obsolete protocols (SSL 3.0, TLS 1.0, TLS 1.1) in accordance with **RFC 8996**.
- **Weak Cipher Suite Detection**: Flags insecure ciphers including RC4 (RFC 7465), 3DES (SWEET32 vulnerability), EXPORT-grade, NULL, and static RSA ciphers lacking Forward Secrecy (PFS).
- **JA3 Client Fingerprinting**: Parses TLS ClientHello parameters (`TLSVersion, Ciphers, Extensions, EllipticCurves, PointFormats`), filters GREASE values (RFC 8701), and computes standard MD5 hashes for behavioral identification.

### 4. Passive Service Banner & Vulnerability Exposure Detection (`src/banner_extractor.cpp`)
- Extracts passive L7 server banners without active scanning:
  - **SSH (Port 22)**: Identifies legacy protocol versions and flags vulnerable software releases (e.g., OpenSSH < 7.4 `CVE-2016-10009`, `CVE-2024-6387 regreSSHion`).
  - **HTTP (Port 80/8080)**: Inspects `Server:` headers (e.g., Apache 2.4.49 `CVE-2021-41773` path traversal).
  - **FTP (Port 21) & SMTP (Port 25/587)**: Parses initial service greetings (`220`).

### 5. Python Security Control Plane (`control_plane/cve_remediator.py`)
- Ingests structured JSONLines telemetry emitted by the C++ engine.
- Correlates discovered exposures against vulnerability feeds and calculates host posture risk scores.
- Automatically generates copy-paste **Remediation Playbooks**:
  - `nginx.conf` and `apache2.conf` modern SSL cipher hardening snippets.
  - `sshd_config` key-exchange and cipher restriction configurations.
  - `iptables` / `nftables` network containment rules for compromised endpoints.

---

## Performance Benchmarks

Measured on synthetic multi-protocol packet streams on AMD Ryzen / Intel Core x86_64:

| Implementation | Queue Architecture | Memory Overhead | Throughput (Packets/Sec) | Per-Packet Latency |
|---|---|---|---|---|
| **Baseline Tutorial** | `std::mutex` + `std::queue` + `std::string` IPs | High (heap allocations per packet) | ~18,000 pps | 55.5 µs |
| **AegisFlow Engine** | **Lock-Free SPSC (`alignas 64`) + Binary 5-Tuple** | **Zero heap allocation on hot-path** | **~49,000+ pps** | **20.4 µs** |

*Result:* **~2.7x throughput increase** with zero thread contention on the packet data plane.

---

## Project Structure

```
AegisFlow/
├── .github/
│   └── workflows/
│       └── ci.yml               # Multi-platform GitHub Actions CI
├── include/
│   ├── banner_extractor.h       # Passive L7 service banner parsing
│   ├── md5.h                    # Standalone RFC 1321 MD5 for JA3
│   ├── packet_parser.h          # Ethernet / IPv4 / TCP / UDP zero-copy parser
│   ├── pcap_reader.h            # Binary PCAP stream reader
│   ├── platform.h               # Portable endianness & byte-swap helpers
│   ├── sni_extractor.h          # TLS ClientHello / ServerHello & JA3 auditor
│   ├── spsc_queue.h             # Lock-free SPSC circular ring buffer
│   ├── telemetry_emitter.h      # Structured JSONL security alert streamer
│   └── types.h                  # Flow 5-tuples, AppType, and posture profiles
├── src/
│   ├── banner_extractor.cpp     # Service banner detection & CVE mapping
│   ├── dpi_mt.cpp               # Multi-threaded coordinator & pipeline
│   ├── main.cpp                 # Standalone L2-L4 packet dumper
│   ├── md5.cpp                  # MD5 hashing implementation
│   ├── packet_parser.cpp        # Zero-copy packet parsing
│   ├── pcap_reader.cpp          # PCAP file parser
│   ├── sni_extractor.cpp        # Cryptographic posture & JA3 extractor
│   ├── telemetry_emitter.cpp    # JSONL telemetry writer
│   └── types.cpp                # IP string conversion & JSON formatting
├── control_plane/
│   └── cve_remediator.py        # Python control plane & remediation engine
├── build.bat                    # One-click Windows build script
├── build.ps1                    # One-click PowerShell build script
├── CMakeLists.txt               # Cross-platform CMake configuration
├── generate_test_pcap.py        # Synthetic test traffic generator
└── README.md
```

---

## Getting Started

### Prerequisites
- **C++ Compiler**: GCC 9+, Clang 10+, or Visual Studio 2022 (supporting C++17)
- **Python**: 3.8+ (for synthetic PCAP generator & control plane)
- **CMake**: 3.16+ (optional, or use direct build scripts)

---

### Build Instructions

#### On Windows (PowerShell / Command Prompt)
Run the automated build script:
```cmd
.\build.bat
```
Or via PowerShell:
```powershell
.\build.ps1
```

#### On Linux / macOS (CMake)
```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

---

## Running AegisFlow

### 1. Generate Test Network Traffic
Generate a synthetic PCAP containing modern TLS connections, legacy TLS 1.0 handshakes, weak ciphers, and exposed SSH/Apache service banners:
```bash
python generate_test_pcap.py
```

### 2. Run the Multi-Threaded DPI & Posture Engine
```bash
# Basic inspection and flow classification
./dpi_engine test_dpi.pcap output_filtered.pcap

# Windows:
.\dpi_engine.exe test_dpi.pcap output_filtered.pcap
```

#### Policy Enforcement Options
```bash
# Block specific applications (e.g., YouTube, Facebook)
.\dpi_engine.exe test_dpi.pcap output_filtered.pcap --block-app YouTube

# Block specific source IPs and domain patterns
.\dpi_engine.exe test_dpi.pcap output_filtered.pcap --block-ip 192.168.1.50 --block-domain internal

# Configure custom thread pools (e.g., 4 Load Balancers, 4 FastPath workers per LB)
.\dpi_engine.exe test_dpi.pcap output_filtered.pcap --lbs 4 --fps 4 --alerts custom_alerts.jsonl
```

### 3. Run the Python Security Control Plane
Process the telemetry alerts generated by the C++ engine to perform CVE correlation and generate an automated hardening playbook:
```bash
python control_plane/cve_remediator.py --alerts alerts.jsonl --export-md remediation_playbook.md
```

---

## Sample Execution Output

```
╔══════════════════════════════════════════════════════════════╗
║       AegisFlow DPI & Cryptographic Posture Engine           ║
╠══════════════════════════════════════════════════════════════╣
║ Load Balancers:  2  │ FP Workers/LB:  2  │ Total FPs:  4        ║
║ Ring Buffer: Lock-Free SPSC (alignas 64, Power-of-2 Cap)     ║
║ Telemetry: Alerts stream -> alerts.jsonl                 ║
╚══════════════════════════════════════════════════════════════╝

Reading packets from test_dpi.pcap...
[Reader] Completed parsing 70 packets.
Writing forwarded traffic to output_filtered.pcap...

╔══════════════════════════════════════════════════════════════╗
║                 SYSTEM PERFORMANCE REPORT                    ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets Processed:      70                           ║
║ Total Data Volume:            6012         bytes           ║
║ Processing Throughput:        48927        pkts/sec         ║
║ Forwarded Packets:            64                           ║
║ Dropped / Blocked:            6                            ║
╠══════════════════════════════════════════════════════════════╣
║                  THREAD WORKLOAD METRICS                     ║
╠══════════════════════════════════════════════════════════════╣
║   LB0 Dispatched:             18                           ║
║   LB1 Dispatched:             52                           ║
║   FP0 Processed:              18                           ║
║   FP3 Processed:              52                           ║
╠══════════════════════════════════════════════════════════════╣
║               APPLICATION & PROTOCOL BREAKDOWN               ║
╠══════════════════════════════════════════════════════════════╣
║ Unknown             42  60.0% ############          ║
║ DNS                  8  11.4% ##                    ║
║ HTTP                 3   4.3%                       ║
║ HTTPS                2   2.9%                       ║
║ YouTube              1   1.4%                       ║
║ SSH                  1   1.4%                       ║
╠══════════════════════════════════════════════════════════════╣
║          CRYPTOGRAPHIC POSTURE & SECURITY AUDIT              ║
╠══════════════════════════════════════════════════════════════╣
║ TLS Handshakes Audited:       16                           ║
║ Deprecated TLS (SSLv3/1.0/1.1):2                           ║
║ Insecure Legacy Ciphers:      2                            ║
║ Service Banners Extracted:    2                            ║
║ Vulnerable Services Flagged:  2                            ║
╚══════════════════════════════════════════════════════════════╝

[Observed TLS JA3 Fingerprints]
  • MD5: 5aceaefb71165829bccbfe7a6a4fb557 (payment-gateway.partner.net)
  • MD5: 15c2c34b9015d3dd8aea53b7c729935f (www.tiktok.com)

[Cryptographic Posture & Vulnerability Warnings]
  [!] Host 192.168.1.105: Deprecated TLS protocol: TLS 1.0 (DEPRECATED)
  [!] Host 192.168.1.105: Offered weak cipher suites (RC4/3DES/EXPORT)
  [!] Host 192.168.1.42: Vulnerable service exposure: SSH - CVE-2016-10009 / CVE-2016-10012 (OpenSSH < 7.4 privilege escalation)
  [!] Host 192.168.1.80: Vulnerable service exposure: HTTP - CVE-2021-41773 / CVE-2021-42013 (Critical Path Traversal & RCE in Apache HTTPD)

[Discovered Service Banners]
  • [SSH:22] SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7 --> ALERT: CVE-2016-10009
  • [HTTP:80] Apache/2.4.49 (Unix) --> ALERT: CVE-2021-41773

[Telemetry] Security alerts exported to: alerts.jsonl
```

---

## Author

**Shrest Kumar**
- GitHub: [@GoodAsur2023](https://github.com/GoodAsur2023)
---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
