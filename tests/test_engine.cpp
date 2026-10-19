// AegisFlow Unit Test Suite
// Tests TLS parsing, JA3 fingerprinting, banner extraction, SPSC queue,
// packet parser zero-copy, and flow hashing.

#include <gtest/gtest.h>
#include <thread>
#include <atomic>
#include <algorithm>
#include <cstring>

#include "sni_extractor.h"
#include "banner_extractor.h"
#include "spsc_queue.h"
#include "md5.h"
#include "types.h"
#include "packet_parser.h"
#include "pcap_reader.h"
#include <unordered_set>

using namespace DPI;
using namespace PacketAnalyzer;

// =============================================================================
// Helper: Build a synthetic TLS ClientHello
// =============================================================================
static std::vector<uint8_t> buildClientHello(
    uint16_t client_ver, 
    const std::string& sni,
    std::vector<uint16_t> ciphers = {0xC02F, 0xC030, 0x1301},
    std::vector<uint16_t> curves = {0x001d, 0x0017},
    std::vector<uint8_t> point_fmts = {0x00}
) {
    std::vector<uint8_t> pkt;

    // --- Build extensions ---
    std::vector<uint8_t> extensions;

    // SNI extension (type 0x0000)
    if (!sni.empty()) {
        std::vector<uint8_t> sni_ext;
        uint16_t sni_len = static_cast<uint16_t>(sni.size());
        uint16_t entry_len = 3 + sni_len; // type(1) + len(2) + data
        uint16_t list_len = entry_len;
        sni_ext.push_back(0x00); sni_ext.push_back(0x00); // ext type
        uint16_t ext_data_len = 2 + list_len;
        sni_ext.push_back(ext_data_len >> 8); sni_ext.push_back(ext_data_len & 0xFF);
        sni_ext.push_back(list_len >> 8); sni_ext.push_back(list_len & 0xFF);
        sni_ext.push_back(0x00); // host name type
        sni_ext.push_back(sni_len >> 8); sni_ext.push_back(sni_len & 0xFF);
        sni_ext.insert(sni_ext.end(), sni.begin(), sni.end());
        extensions.insert(extensions.end(), sni_ext.begin(), sni_ext.end());
    }

    // Supported Groups extension (0x000a)
    if (!curves.empty()) {
        uint16_t curves_bytes = curves.size() * 2;
        extensions.push_back(0x00); extensions.push_back(0x0a);
        uint16_t ext_len = 2 + curves_bytes;
        extensions.push_back(ext_len >> 8); extensions.push_back(ext_len & 0xFF);
        extensions.push_back(curves_bytes >> 8); extensions.push_back(curves_bytes & 0xFF);
        for (uint16_t c : curves) {
            extensions.push_back(c >> 8); extensions.push_back(c & 0xFF);
        }
    }

    // EC Point Formats extension (0x000b)
    if (!point_fmts.empty()) {
        uint8_t pf_len = static_cast<uint8_t>(point_fmts.size());
        extensions.push_back(0x00); extensions.push_back(0x0b);
        uint16_t ext_len = 1 + pf_len;
        extensions.push_back(ext_len >> 8); extensions.push_back(ext_len & 0xFF);
        extensions.push_back(pf_len);
        extensions.insert(extensions.end(), point_fmts.begin(), point_fmts.end());
    }

    // --- Build ClientHello body ---
    std::vector<uint8_t> body;
    body.push_back(client_ver >> 8); body.push_back(client_ver & 0xFF);
    for (int i = 0; i < 32; i++) body.push_back(0x42); // random
    body.push_back(0); // session id length

    uint16_t cipher_bytes_len = ciphers.size() * 2;
    body.push_back(cipher_bytes_len >> 8); body.push_back(cipher_bytes_len & 0xFF);
    for (uint16_t c : ciphers) {
        body.push_back(c >> 8); body.push_back(c & 0xFF);
    }
    body.push_back(1); body.push_back(0); // compression: null

    uint16_t ext_total = static_cast<uint16_t>(extensions.size());
    body.push_back(ext_total >> 8); body.push_back(ext_total & 0xFF);
    body.insert(body.end(), extensions.begin(), extensions.end());

    // --- Handshake header ---
    std::vector<uint8_t> handshake;
    handshake.push_back(0x01); // ClientHello
    uint32_t hs_len = body.size();
    handshake.push_back((hs_len >> 16) & 0xFF);
    handshake.push_back((hs_len >> 8) & 0xFF);
    handshake.push_back(hs_len & 0xFF);
    handshake.insert(handshake.end(), body.begin(), body.end());

    // --- TLS record header ---
    pkt.push_back(0x16); // Content type: Handshake
    pkt.push_back(0x03); pkt.push_back(0x01); // Record version TLS 1.0
    uint16_t rec_len = static_cast<uint16_t>(handshake.size());
    pkt.push_back(rec_len >> 8); pkt.push_back(rec_len & 0xFF);
    pkt.insert(pkt.end(), handshake.begin(), handshake.end());

    return pkt;
}

// =============================================================================
// TLS ClientHello Detection & SNI Extraction
// =============================================================================
TEST(TLSParser, DetectsClientHello) {
    auto pkt = buildClientHello(0x0303, "example.com");
    EXPECT_TRUE(SNIExtractor::isTLSClientHello(pkt.data(), pkt.size()));
}

TEST(TLSParser, RejectsNonTLS) {
    uint8_t garbage[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
    EXPECT_FALSE(SNIExtractor::isTLSClientHello(garbage, sizeof(garbage)));
}

TEST(TLSParser, RejectsTooShort) {
    uint8_t tiny[] = {0x16, 0x03, 0x01};
    EXPECT_FALSE(SNIExtractor::isTLSClientHello(tiny, sizeof(tiny)));
}

TEST(TLSParser, ExtractsSNI) {
    auto pkt = buildClientHello(0x0303, "www.example.com");
    auto sni = SNIExtractor::extract(pkt.data(), pkt.size());
    ASSERT_TRUE(sni.has_value());
    EXPECT_EQ(*sni, "www.example.com");
}

TEST(TLSParser, EmptySNI) {
    auto pkt = buildClientHello(0x0303, "");
    auto sni = SNIExtractor::extract(pkt.data(), pkt.size());
    EXPECT_FALSE(sni.has_value());
}

// =============================================================================
// JA3 Fingerprinting
// =============================================================================
TEST(JA3, ComputesFingerprint) {
    auto pkt = buildClientHello(0x0303, "test.example.com", {0xC02F, 0xC030, 0x1301});
    auto profile = SNIExtractor::auditClientHello(pkt.data(), pkt.size());
    ASSERT_TRUE(profile.has_value());
    EXPECT_FALSE(profile->ja3_hash.empty());
    EXPECT_EQ(profile->ja3_hash.size(), 32u); // MD5 hex = 32 chars
    EXPECT_FALSE(profile->ja3_raw.empty());
}

TEST(JA3, DeterministicHash) {
    auto pkt1 = buildClientHello(0x0303, "a.com", {0xC02F, 0x1301});
    auto pkt2 = buildClientHello(0x0303, "b.com", {0xC02F, 0x1301}); // same ciphers
    auto p1 = SNIExtractor::auditClientHello(pkt1.data(), pkt1.size());
    auto p2 = SNIExtractor::auditClientHello(pkt2.data(), pkt2.size());
    ASSERT_TRUE(p1.has_value() && p2.has_value());
    // JA3 raw string should match (SNI is not part of JA3)
    EXPECT_EQ(p1->ja3_raw, p2->ja3_raw);
    EXPECT_EQ(p1->ja3_hash, p2->ja3_hash);
}

// =============================================================================
// Deprecated TLS & Weak Cipher Detection
// =============================================================================
TEST(PostureAudit, FlagsDeprecatedTLS10) {
    auto pkt = buildClientHello(0x0301, "legacy.internal"); // TLS 1.0
    auto profile = SNIExtractor::auditClientHello(pkt.data(), pkt.size());
    ASSERT_TRUE(profile.has_value());
    EXPECT_TRUE(profile->is_deprecated_tls);
    EXPECT_FALSE(profile->posture_anomalies.empty());
}

TEST(PostureAudit, FlagsDeprecatedTLS11) {
    auto pkt = buildClientHello(0x0302, "old-bank.net"); // TLS 1.1
    auto profile = SNIExtractor::auditClientHello(pkt.data(), pkt.size());
    ASSERT_TRUE(profile.has_value());
    EXPECT_TRUE(profile->is_deprecated_tls);
}

TEST(PostureAudit, TLS12NotDeprecated) {
    auto pkt = buildClientHello(0x0303, "modern.site");
    auto profile = SNIExtractor::auditClientHello(pkt.data(), pkt.size());
    ASSERT_TRUE(profile.has_value());
    EXPECT_FALSE(profile->is_deprecated_tls);
}

TEST(PostureAudit, FlagsWeakRC4Cipher) {
    auto pkt = buildClientHello(0x0303, "weak.site", {0x0004, 0x0005}); // RC4
    auto profile = SNIExtractor::auditClientHello(pkt.data(), pkt.size());
    ASSERT_TRUE(profile.has_value());
    EXPECT_TRUE(profile->has_weak_ciphers);
}

TEST(PostureAudit, FlagsWeak3DESCipher) {
    auto pkt = buildClientHello(0x0303, "old.site", {0x000A}); // 3DES
    auto profile = SNIExtractor::auditClientHello(pkt.data(), pkt.size());
    ASSERT_TRUE(profile.has_value());
    EXPECT_TRUE(profile->has_weak_ciphers);
}

TEST(PostureAudit, ModernCiphersNotFlagged) {
    auto pkt = buildClientHello(0x0303, "secure.com", {0xC02F, 0xC030, 0x1301, 0x1302});
    auto profile = SNIExtractor::auditClientHello(pkt.data(), pkt.size());
    ASSERT_TRUE(profile.has_value());
    EXPECT_FALSE(profile->has_weak_ciphers);
}

TEST(PostureAudit, CipherUtilities) {
    EXPECT_TRUE(SNIExtractor::isWeakCipherSuite(0x0004));  // RC4
    EXPECT_TRUE(SNIExtractor::isWeakCipherSuite(0x000A));  // 3DES
    EXPECT_FALSE(SNIExtractor::isWeakCipherSuite(0xC02F)); // ECDHE_RSA_AES128_GCM
    EXPECT_TRUE(SNIExtractor::lacksForwardSecrecy(0x002F)); // RSA_AES128_CBC
    EXPECT_FALSE(SNIExtractor::lacksForwardSecrecy(0xC02F));
    EXPECT_TRUE(SNIExtractor::isDeprecatedVersion(0x0301)); // TLS 1.0
    EXPECT_FALSE(SNIExtractor::isDeprecatedVersion(0x0303)); // TLS 1.2
}

// =============================================================================
// Passive Service Banner Extraction
// =============================================================================
TEST(BannerExtractor, DetectsSSHBanner) {
    const char* ssh = "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n";
    auto info = BannerExtractor::inspect(
        reinterpret_cast<const uint8_t*>(ssh), strlen(ssh), 22, 50000);
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->service, "SSH");
    EXPECT_TRUE(info->is_vulnerable);
    EXPECT_FALSE(info->cve_hint.empty());
}

TEST(BannerExtractor, DetectsSSHv1Deprecation) {
    const char* ssh = "SSH-1.99-OpenSSH_3.9p1\r\n";
    auto info = BannerExtractor::inspect(
        reinterpret_cast<const uint8_t*>(ssh), strlen(ssh), 22, 50000);
    ASSERT_TRUE(info.has_value());
    EXPECT_TRUE(info->is_vulnerable);
}

TEST(BannerExtractor, DetectsApacheCVE) {
    const char* http = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n\r\n";
    auto info = BannerExtractor::inspect(
        reinterpret_cast<const uint8_t*>(http), strlen(http), 80, 50000);
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->service, "HTTP");
    EXPECT_TRUE(info->is_vulnerable);
    EXPECT_NE(info->cve_hint.find("CVE-2021-41773"), std::string::npos);
}

TEST(BannerExtractor, DetectsNginxCVE) {
    const char* http = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n";
    auto info = BannerExtractor::inspect(
        reinterpret_cast<const uint8_t*>(http), strlen(http), 80, 50000);
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->service, "HTTP");
    EXPECT_TRUE(info->is_vulnerable);
}

TEST(BannerExtractor, DetectsFTPBanner) {
    const char* ftp = "220 vsftpd 2.3.4 ready\r\n";
    auto info = BannerExtractor::inspect(
        reinterpret_cast<const uint8_t*>(ftp), strlen(ftp), 21, 50000);
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->service, "FTP");
    EXPECT_TRUE(info->is_vulnerable);
}

TEST(BannerExtractor, DetectsSMTPBanner) {
    const char* smtp = "220 mail.example.com Exim 4.80 Ready\r\n";
    auto info = BannerExtractor::inspect(
        reinterpret_cast<const uint8_t*>(smtp), strlen(smtp), 25, 50000);
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->service, "SMTP");
}

TEST(BannerExtractor, RejectsEmptyPayload) {
    auto info = BannerExtractor::inspect(nullptr, 0, 80, 50000);
    EXPECT_FALSE(info.has_value());
}

// =============================================================================
// SPSC Queue - Correctness & Thread Safety
// =============================================================================
TEST(SPSCQueue, PushPop) {
    SPSCQueue<int, 16> q;
    EXPECT_TRUE(q.empty());
    EXPECT_EQ(q.size(), 0u);

    int val;
    EXPECT_FALSE(q.pop(val));

    EXPECT_TRUE(q.push(42));
    EXPECT_FALSE(q.empty());
    EXPECT_EQ(q.size(), 1u);

    EXPECT_TRUE(q.pop(val));
    EXPECT_EQ(val, 42);
    EXPECT_TRUE(q.empty());
}

TEST(SPSCQueue, FullQueueRejectsPush) {
    SPSCQueue<int, 4> q; // Capacity 4, but max fill = 3 (one slot sentinel)
    EXPECT_TRUE(q.push(1));
    EXPECT_TRUE(q.push(2));
    EXPECT_TRUE(q.push(3));
    EXPECT_FALSE(q.push(4)); // Full
}

TEST(SPSCQueue, FIFO_Order) {
    SPSCQueue<int, 64> q;
    for (int i = 0; i < 50; i++) {
        EXPECT_TRUE(q.push(std::move(i)));
    }
    for (int i = 0; i < 50; i++) {
        int val;
        EXPECT_TRUE(q.pop(val));
        EXPECT_EQ(val, i);
    }
}

TEST(SPSCQueue, ConcurrentPushPop) {
    constexpr size_t N = 100000;
    SPSCQueue<uint64_t, 1024> q;
    std::atomic<bool> done{false};
    std::atomic<uint64_t> sum_produced{0};
    std::atomic<uint64_t> sum_consumed{0};

    // Producer thread
    std::thread producer([&] {
        for (uint64_t i = 1; i <= N; i++) {
            while (!q.push(std::move(i))) {
                std::this_thread::yield();
            }
            sum_produced += i;
        }
        done = true;
    });

    // Consumer thread
    std::thread consumer([&] {
        uint64_t val;
        while (!done || !q.empty()) {
            if (q.pop(val)) {
                sum_consumed += val;
            } else {
                std::this_thread::yield();
            }
        }
    });

    producer.join();
    consumer.join();
    EXPECT_EQ(sum_produced.load(), sum_consumed.load());
}

// =============================================================================
// FiveTuple Hashing & Equality
// =============================================================================
TEST(FiveTuple, Equality) {
    FiveTuple a{0x0100A8C0, 0x0200A8C0, 80, 50000, 6};
    FiveTuple b{0x0100A8C0, 0x0200A8C0, 80, 50000, 6};
    FiveTuple c{0x0100A8C0, 0x0200A8C0, 81, 50000, 6};
    EXPECT_EQ(a, b);
    EXPECT_FALSE(a == c);
}

TEST(FiveTuple, ReverseSymmetry) {
    FiveTuple t{0x01020304, 0x05060708, 80, 443, 6};
    FiveTuple r = t.reverse();
    EXPECT_EQ(r.src_ip, t.dst_ip);
    EXPECT_EQ(r.dst_ip, t.src_ip);
    EXPECT_EQ(r.src_port, t.dst_port);
    EXPECT_EQ(r.dst_port, t.src_port);
    EXPECT_EQ(r.protocol, t.protocol);
}

TEST(FiveTuple, HashDistribution) {
    FiveTupleHash hasher;
    std::unordered_set<size_t> hashes;
    for (uint32_t i = 0; i < 1000; i++) {
        FiveTuple t{i, i + 1000, static_cast<uint16_t>(i % 65535), 443, 6};
        hashes.insert(hasher(t));
    }
    // Expect at least 95% unique hashes (good distribution)
    EXPECT_GT(hashes.size(), 950u);
}

// =============================================================================
// MD5 Hashing
// =============================================================================
TEST(MD5, KnownVector_Empty) {
    EXPECT_EQ(MD5::hash(""), "d41d8cd98f00b204e9800998ecf8427e");
}

TEST(MD5, KnownVector_ABC) {
    EXPECT_EQ(MD5::hash("abc"), "900150983cd24fb0d6963f7d28e17f72");
}

TEST(MD5, KnownVector_HelloWorld) {
    EXPECT_EQ(MD5::hash("Hello, World!"), "65a8e27d8879283831b664bd8b7f0ad4");
}

TEST(MD5, Deterministic) {
    EXPECT_EQ(MD5::hash("test_input"), MD5::hash("test_input"));
}

// =============================================================================
// PacketParser - Zero-Copy Verification
// =============================================================================
TEST(PacketParser, ZeroCopyNoStringFields) {
    // Build a minimal valid Ethernet + IPv4 + TCP packet
    std::vector<uint8_t> raw_data;
    
    // Ethernet header (14 bytes)
    uint8_t eth[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,  // dst MAC
                     0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // src MAC
                     0x08, 0x00};                           // IPv4
    raw_data.insert(raw_data.end(), eth, eth + 14);
    
    // IPv4 header (20 bytes)
    uint8_t ip[] = {0x45, 0x00, 0x00, 0x28, // ver+ihl, tos, total_len=40
                    0x00, 0x01, 0x40, 0x00, // id, flags+frag
                    0x40, 0x06, 0x00, 0x00, // ttl=64, proto=TCP, checksum
                    0xC0, 0xA8, 0x01, 0x64, // src: 192.168.1.100
                    0x8E, 0xFA, 0xB9, 0xCE};// dst: 142.250.185.206
    raw_data.insert(raw_data.end(), ip, ip + 20);
    
    // TCP header (20 bytes)
    uint8_t tcp[] = {0xC3, 0x50, 0x01, 0xBB, // src port 50000, dst port 443
                     0x00, 0x00, 0x03, 0xE8, // seq
                     0x00, 0x00, 0x00, 0x00, // ack
                     0x50, 0x18, 0xFF, 0xFF, // data offset=5, flags=PSH+ACK, window
                     0x00, 0x00, 0x00, 0x00};// checksum, urgent
    raw_data.insert(raw_data.end(), tcp, tcp + 20);
    
    RawPacket raw;
    raw.header.ts_sec = 1000;
    raw.header.ts_usec = 500;
    raw.header.incl_len = raw_data.size();
    raw.header.orig_len = raw_data.size();
    raw.data = raw_data;
    
    ParsedPacket parsed;
    ASSERT_TRUE(PacketParser::parse(raw, parsed));
    
    // Verify binary data is stored directly (no heap allocation during parse)
    EXPECT_EQ(parsed.src_mac_raw[0], 0x00);
    EXPECT_EQ(parsed.src_mac_raw[5], 0x55);
    EXPECT_EQ(parsed.dest_mac_raw[0], 0xaa);
    EXPECT_EQ(parsed.dest_mac_raw[5], 0xff);
    
    // IP integers stored directly
    EXPECT_EQ(parsed.src_ip_int, 0x6401A8C0u);  // 192.168.1.100 in LE
    EXPECT_EQ(parsed.dest_ip_int, 0xCEB9FA8Eu);  // 142.250.185.206 in LE
    
    // TCP fields
    EXPECT_TRUE(parsed.has_tcp);
    EXPECT_EQ(parsed.src_port, 50000u);
    EXPECT_EQ(parsed.dest_port, 443u);
    EXPECT_EQ(parsed.protocol, 6u);
    EXPECT_EQ(parsed.ttl, 64u);
    
    // Lazy string accessors still work
    EXPECT_EQ(parsed.srcIPString(), "192.168.1.100");
    EXPECT_EQ(parsed.destIPString(), "142.250.185.206");
    EXPECT_EQ(parsed.srcMacString(), "00:11:22:33:44:55");
    EXPECT_EQ(parsed.destMacString(), "aa:bb:cc:dd:ee:ff");
}

// =============================================================================
// Application Classification (SNI → AppType)
// =============================================================================
TEST(AppClassification, DetectsYouTube) {
    EXPECT_EQ(sniToAppType("www.youtube.com"), AppType::YOUTUBE);
    EXPECT_EQ(sniToAppType("ytimg.l.google.com"), AppType::YOUTUBE);
}

TEST(AppClassification, DetectsGoogle) {
    EXPECT_EQ(sniToAppType("www.google.com"), AppType::GOOGLE);
    EXPECT_EQ(sniToAppType("fonts.googleapis.com"), AppType::GOOGLE);
}

TEST(AppClassification, DetectsFacebook) {
    EXPECT_EQ(sniToAppType("www.facebook.com"), AppType::FACEBOOK);
    EXPECT_EQ(sniToAppType("static.fbcdn.net"), AppType::FACEBOOK);
}

TEST(AppClassification, UnknownDomain) {
    EXPECT_EQ(sniToAppType("random-custom-site.xyz"), AppType::HTTPS);
}

TEST(AppClassification, EmptySNI) {
    EXPECT_EQ(sniToAppType(""), AppType::UNKNOWN);
}

// =============================================================================
// HTTP Host Extraction
// =============================================================================
TEST(HTTP, ExtractsHost) {
    const char* req = "GET / HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: test\r\n\r\n";
    auto host = HTTPHostExtractor::extract(
        reinterpret_cast<const uint8_t*>(req), strlen(req));
    ASSERT_TRUE(host.has_value());
    EXPECT_EQ(*host, "www.example.com");
}

TEST(HTTP, RejectsNonHTTP) {
    const char* data = "SSH-2.0-OpenSSH_8.4\r\n";
    EXPECT_FALSE(HTTPHostExtractor::isHTTPRequest(
        reinterpret_cast<const uint8_t*>(data), strlen(data)));
}

// =============================================================================
// DNS Query Extraction
// =============================================================================
TEST(DNS, ExtractsQuery) {
    // Build a minimal DNS query for "example.com"
    std::vector<uint8_t> dns;
    // Header: 12 bytes
    uint8_t header[] = {0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    dns.insert(dns.end(), header, header + 12);
    // Question: "example" label
    dns.push_back(7); dns.insert(dns.end(), {'e','x','a','m','p','l','e'});
    // "com" label
    dns.push_back(3); dns.insert(dns.end(), {'c','o','m'});
    dns.push_back(0); // terminator
    dns.push_back(0x00); dns.push_back(0x01); // Type A
    dns.push_back(0x00); dns.push_back(0x01); // Class IN

    auto domain = DNSExtractor::extractQuery(dns.data(), dns.size());
    ASSERT_TRUE(domain.has_value());
    EXPECT_EQ(*domain, "example.com");
}

// =============================================================================
// Utility String Functions
// =============================================================================
TEST(Utils, TLSVersionString) {
    EXPECT_EQ(tlsVersionToString(0x0301), "TLS 1.0 (DEPRECATED)");
    EXPECT_EQ(tlsVersionToString(0x0303), "TLS 1.2");
    EXPECT_EQ(tlsVersionToString(0x0304), "TLS 1.3");
}

TEST(Utils, CipherSuiteString) {
    EXPECT_NE(cipherSuiteToString(0x0004).find("WEAK"), std::string::npos);
    EXPECT_NE(cipherSuiteToString(0x1301).find("TLS1.3"), std::string::npos);
}

TEST(Utils, AppTypeRoundTrip) {
    for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
        std::string name = appTypeToString(static_cast<AppType>(i));
        EXPECT_FALSE(name.empty());
    }
}

// =============================================================================
// Live Capture & Interface Discovery
// =============================================================================
TEST(PcapReaderLive, ListInterfacesRunsWithoutCrash) {
    auto ifaces = PcapReader::listInterfaces();
    // Device enumeration completes cleanly and populates interface metadata
    for (const auto& iface : ifaces) {
        EXPECT_FALSE(iface.name.empty());
    }
}

TEST(PcapReaderLive, HandlesNonExistentInterfaceGracefully) {
    PcapReader reader;
    EXPECT_FALSE(reader.openLive("non_existent_device_xyz_999"));
    EXPECT_FALSE(reader.isOpen());
    EXPECT_FALSE(reader.isLive());
}

// =============================================================================
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
