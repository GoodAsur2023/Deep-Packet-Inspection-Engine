#!/usr/bin/env python3
"""
AegisFlow Synthetic PCAP Test Generator
Generates realistic multi-protocol PCAP captures for DPI and security posture testing:
- Modern TLS 1.2 / 1.3 ClientHello with SNI and JA3 parameters
- Deprecated TLS 1.0 / 1.1 handshakes with weak ciphers (RC4, 3DES)
- Passive Service Banners (SSH with vulnerable OpenSSH, HTTP Apache 2.4.49 CVE-2021-41773)
- HTTP requests and DNS queries
- Policy enforcement target IPs
"""

import struct
import random
import time

class PCAPWriter:
    def __init__(self, filename):
        self.file = open(filename, 'wb')
        self.write_global_header()
        self.timestamp = int(time.time()) - 3600
        
    def write_global_header(self):
        # Magic 0xa1b2c3d4, version 2.4, tz 0, sigfigs 0, snaplen 65535, linktype Ethernet (1)
        header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        self.file.write(header)
        
    def write_packet(self, data):
        ts_sec = self.timestamp
        ts_usec = random.randint(0, 999999)
        self.timestamp += 1
        
        pkt_header = struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data))
        self.file.write(pkt_header)
        self.file.write(data)
        
    def close(self):
        self.file.close()


def create_ethernet_header(src_mac, dst_mac, ethertype=0x0800):
    return bytes.fromhex(dst_mac.replace(':', '')) + \
           bytes.fromhex(src_mac.replace(':', '')) + \
           struct.pack('>H', ethertype)


def create_ip_header(src_ip, dst_ip, protocol, payload_len):
    version_ihl = 0x45
    tos = 0
    total_len = 20 + payload_len
    ident = random.randint(1, 65535)
    flags_frag = 0x4000  # Don't fragment
    ttl = 64
    checksum = 0
    
    header = struct.pack('>BBHHHBBH',
                         version_ihl, tos, total_len,
                         ident, flags_frag, ttl,
                         protocol, checksum)
    
    src_bytes = bytes([int(x) for x in src_ip.split('.')])
    dst_bytes = bytes([int(x) for x in dst_ip.split('.')])
    
    return header + src_bytes + dst_bytes


def create_tcp_header(src_port, dst_port, seq=1000, ack=0, flags=0x18, payload_len=0):
    data_offset = 5 << 4  # 20 bytes
    window = 65535
    checksum = 0
    urgent = 0
    
    return struct.pack('>HHIIBBHHH',
                       src_port, dst_port,
                       seq, ack,
                       data_offset, flags,
                       window, checksum, urgent)


def create_udp_header(src_port, dst_port, payload_len):
    total_len = 8 + payload_len
    checksum = 0
    return struct.pack('>HHHH', src_port, dst_port, total_len, checksum)


def create_tls_client_hello(sni, client_ver=0x0303, ciphers=None):
    """Create a TLS Client Hello with SNI, Supported Groups, and Ciphers for JA3."""
    if ciphers is None:
        ciphers = [0xC02F, 0xC030, 0x1301, 0x1302]  # Modern ECDHE + TLS 1.3
    
    # SNI extension (0x0000)
    sni_bytes = sni.encode('ascii')
    sni_entry = struct.pack('>BH', 0, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack('>H', len(sni_entry)) + sni_entry
    sni_ext = struct.pack('>HH', 0x0000, len(sni_list)) + sni_list
    
    # Supported groups extension (0x000a) - X25519, secp256r1
    curves_data = struct.pack('>HH', 0x001d, 0x0017)
    groups_ext = struct.pack('>HHH', 0x000a, len(curves_data) + 2, len(curves_data)) + curves_data

    # EC point formats extension (0x000b) - uncompressed (0)
    points_ext = struct.pack('>HHBB', 0x000b, 2, 1, 0)
    
    # Supported versions extension (0x002b)
    supported_versions = struct.pack('>HHB', 0x002b, 3, 2) + struct.pack('>H', 0x0304)
    
    extensions = sni_ext + groups_ext + points_ext + supported_versions
    extensions_data = struct.pack('>H', len(extensions)) + extensions
    
    # Body
    client_version = struct.pack('>H', client_ver)
    random_bytes = bytes([random.randint(0, 255) for _ in range(32)])
    session_id = struct.pack('B', 0)
    
    cipher_bytes = b''
    for c in ciphers:
        cipher_bytes += struct.pack('>H', c)
    cipher_suites = struct.pack('>H', len(cipher_bytes)) + cipher_bytes
    compression = struct.pack('BB', 1, 0)
    
    client_hello_body = client_version + random_bytes + session_id + cipher_suites + compression + extensions_data
    
    handshake = struct.pack('B', 0x01)  # Client Hello
    handshake += struct.pack('>I', len(client_hello_body))[1:]  # 3-byte length
    handshake += client_hello_body
    
    record = struct.pack('B', 0x16)  # Handshake
    record += struct.pack('>H', 0x0301)  # Record layer TLS 1.0 compatibility
    record += struct.pack('>H', len(handshake))
    record += handshake
    
    return record


def create_deprecated_tls_client_hello(sni):
    """Create a deprecated TLS 1.0 ClientHello with weak 3DES & RC4 ciphers."""
    return create_tls_client_hello(sni, client_ver=0x0301, ciphers=[0x000A, 0x0005, 0x0004])


def create_ssh_banner(banner="SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7"):
    return (banner + "\r\n").encode('ascii')


def create_http_response(server="Apache/2.4.49 (Unix)"):
    body = "<html><body><h1>Internal Portal</h1></body></html>"
    resp = f"HTTP/1.1 200 OK\r\nDate: Mon, 20 Oct 2026 00:00:00 GMT\r\nServer: {server}\r\nContent-Type: text/html\r\nContent-Length: {len(body)}\r\n\r\n{body}"
    return resp.encode('ascii')


def create_http_request(host, path='/'):
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept: */*\r\n\r\n".encode()


def create_dns_query(domain):
    txid = struct.pack('>H', random.randint(1, 65535))
    flags = struct.pack('>H', 0x0100)
    counts = struct.pack('>HHHH', 1, 0, 0, 0)
    
    question = b''
    for label in domain.split('.'):
        question += struct.pack('B', len(label)) + label.encode()
    question += struct.pack('B', 0)
    question += struct.pack('>HH', 1, 1)  # Type A, Class IN
    
    return txid + flags + counts + question


def main():
    writer = PCAPWriter('test_dpi.pcap')
    
    client_mac = "00:11:22:33:44:55"
    gateway_mac = "aa:bb:cc:dd:ee:ff"
    
    print("[+] Generating synthetic traffic in test_dpi.pcap...")

    # 1. Modern TLS Connections with SNI
    modern_snis = [
        ("www.youtube.com", "142.250.185.206"),
        ("www.google.com", "142.250.185.200"),
        ("www.facebook.com", "157.240.22.35"),
        ("www.instagram.com", "157.240.22.174"),
        ("github.com", "140.82.121.4"),
        ("discord.com", "162.159.135.232"),
        ("open.spotify.com", "35.186.224.25"),
        ("www.amazon.com", "205.251.242.103"),
        ("www.apple.com", "17.253.144.10"),
        ("www.cloudflare.com", "104.16.132.229"),
        ("zoom.us", "170.114.52.2"),
        ("twitter.com", "104.244.42.1"),
        ("web.telegram.org", "149.154.167.99"),
        ("www.tiktok.com", "162.159.152.4"),
    ]
    
    for sni, server_ip in modern_snis:
        client_ip = "192.168.1.100"
        client_port = random.randint(40000, 60000)
        
        # SYN, SYN-ACK, ACK
        eth = create_ethernet_header(client_mac, gateway_mac)
        ip = create_ip_header(client_ip, server_ip, 6, 20)
        tcp = create_tcp_header(client_port, 443, seq=1000, ack=0, flags=0x02)
        writer.write_packet(eth + ip + tcp)
        
        eth = create_ethernet_header(gateway_mac, client_mac)
        ip = create_ip_header(server_ip, client_ip, 6, 20)
        tcp = create_tcp_header(443, client_port, seq=2000, ack=1001, flags=0x12)
        writer.write_packet(eth + ip + tcp)
        
        eth = create_ethernet_header(client_mac, gateway_mac)
        ip = create_ip_header(client_ip, server_ip, 6, 20)
        tcp = create_tcp_header(client_port, 443, seq=1001, ack=2001, flags=0x10)
        writer.write_packet(eth + ip + tcp)
        
        # TLS Client Hello
        tls_payload = create_tls_client_hello(sni)
        eth = create_ethernet_header(client_mac, gateway_mac)
        ip = create_ip_header(client_ip, server_ip, 6, 20 + len(tls_payload))
        tcp = create_tcp_header(client_port, 443, seq=1001, ack=2001, flags=0x18, payload_len=len(tls_payload))
        writer.write_packet(eth + ip + tcp + tls_payload)

    # 2. Cryptographic Posture Test: Deprecated TLS 1.0 + Weak Ciphers (RC4, 3DES)
    legacy_snis = [
        ("legacy-banking.internal", "10.0.1.20"),
        ("payment-gateway.partner.net", "10.0.1.25"),
    ]
    for sni, server_ip in legacy_snis:
        client_ip = "192.168.1.105"
        client_port = random.randint(40000, 60000)
        tls_payload = create_deprecated_tls_client_hello(sni)
        
        eth = create_ethernet_header(client_mac, gateway_mac)
        ip = create_ip_header(client_ip, server_ip, 6, 20 + len(tls_payload))
        tcp = create_tcp_header(client_port, 443, seq=1001, ack=2001, flags=0x18, payload_len=len(tls_payload))
        writer.write_packet(eth + ip + tcp + tls_payload)

    # 3. Passive Service Banner: Vulnerable OpenSSH 7.4p1 (CVE-2016-10009)
    ssh_ip = "192.168.1.42"
    ssh_client = "192.168.1.100"
    ssh_port = random.randint(40000, 60000)
    ssh_banner = create_ssh_banner("SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7")
    
    eth = create_ethernet_header(gateway_mac, client_mac)
    ip = create_ip_header(ssh_ip, ssh_client, 6, 20 + len(ssh_banner))
    tcp = create_tcp_header(22, ssh_port, seq=1, ack=1, flags=0x18, payload_len=len(ssh_banner))
    writer.write_packet(eth + ip + tcp + ssh_banner)

    # 4. Passive Service Banner: Vulnerable Apache 2.4.49 (CVE-2021-41773 Path Traversal / RCE)
    http_srv_ip = "192.168.1.80"
    http_resp = create_http_response("Apache/2.4.49 (Unix)")
    
    eth = create_ethernet_header(gateway_mac, client_mac)
    ip = create_ip_header(http_srv_ip, ssh_client, 6, 20 + len(http_resp))
    tcp = create_tcp_header(80, random.randint(40000, 60000), seq=1, ack=1, flags=0x18, payload_len=len(http_resp))
    writer.write_packet(eth + ip + tcp + http_resp)

    # 5. HTTP Plaintext Requests
    http_hosts = [("insecure.org", "45.33.49.119"), ("example.com", "93.184.216.34")]
    for host, server_ip in http_hosts:
        client_ip = "192.168.1.100"
        client_port = random.randint(40000, 60000)
        http_payload = create_http_request(host)
        
        eth = create_ethernet_header(client_mac, gateway_mac)
        ip = create_ip_header(client_ip, server_ip, 6, 20 + len(http_payload))
        tcp = create_tcp_header(client_port, 80, flags=0x18, payload_len=len(http_payload))
        writer.write_packet(eth + ip + tcp + http_payload)

    # 6. DNS Queries
    dns_domains = ["api.github.com", "update.microsoft.com", "internal-portal.corp"]
    for dom in dns_domains:
        dns_payload = create_dns_query(dom)
        eth = create_ethernet_header(client_mac, gateway_mac)
        ip = create_ip_header("192.168.1.100", "8.8.8.8", 17, 8 + len(dns_payload))
        udp = create_udp_header(random.randint(40000, 60000), 53, len(dns_payload))
        writer.write_packet(eth + ip + udp + dns_payload)

    # 7. Traffic from Blocked Policy IP (192.168.1.50)
    for _ in range(5):
        payload = b'BLOCKED_TELEMETRY_TEST'
        eth = create_ethernet_header(client_mac, gateway_mac)
        ip = create_ip_header("192.168.1.50", "1.1.1.1", 17, 8 + len(payload))
        udp = create_udp_header(55555, 53, len(payload))
        writer.write_packet(eth + ip + udp + payload)

    writer.close()
    print("[+] Successfully generated test_dpi.pcap with rich multi-protocol security scenarios.")

if __name__ == '__main__':
    main()
