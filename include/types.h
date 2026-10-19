#ifndef DPI_TYPES_H
#define DPI_TYPES_H

#include <cstdint>
#include <string>
#include <functional>
#include <chrono>
#include <vector>
#include <atomic>
#include <optional>
#include <sstream>

namespace DPI {

// ============================================================================
// Five-Tuple: Uniquely identifies a connection/flow with integer IPs (Zero-Copy)
// ============================================================================
struct FiveTuple {
    uint32_t src_ip{0};
    uint32_t dst_ip{0};
    uint16_t src_port{0};
    uint16_t dst_port{0};
    uint8_t  protocol{0};  // TCP=6, UDP=17
    
    constexpr bool operator==(const FiveTuple& other) const noexcept {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }
    
    // Create reverse tuple (for bidirectional flow matching)
    constexpr FiveTuple reverse() const noexcept {
        return {dst_ip, src_ip, dst_port, src_port, protocol};
    }
    
    std::string toString() const;
    std::string srcIPString() const;
    std::string dstIPString() const;
};

// Fast 64-bit bit-mixing hash for FiveTuple
struct FiveTupleHash {
    std::size_t operator()(const FiveTuple& t) const noexcept {
        uint64_t k1 = (static_cast<uint64_t>(t.src_ip) << 32) | t.dst_ip;
        uint64_t k2 = (static_cast<uint64_t>(t.src_port) << 32) |
                      (static_cast<uint64_t>(t.dst_port) << 16) | t.protocol;
        k1 ^= k2 + 0x9e3779b97f4a7c15ULL + (k1 << 6) + (k1 >> 2);
        return static_cast<std::size_t>(k1);
    }
};

// ============================================================================
// Application Classification
// ============================================================================
enum class AppType {
    UNKNOWN = 0,
    HTTP,
    HTTPS,
    DNS,
    TLS,
    QUIC,
    SSH,
    FTP,
    SMTP,
    // Specific applications (detected via SNI/Host)
    GOOGLE,
    FACEBOOK,
    YOUTUBE,
    TWITTER,
    INSTAGRAM,
    NETFLIX,
    AMAZON,
    MICROSOFT,
    APPLE,
    WHATSAPP,
    TELEGRAM,
    TIKTOK,
    SPOTIFY,
    ZOOM,
    DISCORD,
    GITHUB,
    CLOUDFLARE,
    APP_COUNT
};

std::string appTypeToString(AppType type);
AppType sniToAppType(const std::string& sni);
std::string tlsVersionToString(uint16_t version);
std::string cipherSuiteToString(uint16_t cipher);

// ============================================================================
// Cryptographic Posture & Telemetry Types
// ============================================================================
struct TLSSecurityProfile {
    uint16_t record_version{0};
    uint16_t client_version{0};
    uint16_t server_version{0};
    uint16_t negotiated_cipher{0};
    std::string sni;
    std::vector<uint16_t> offered_ciphers;
    std::vector<uint16_t> extensions;
    std::vector<uint16_t> elliptic_curves;
    std::vector<uint8_t>  ec_point_formats;

    std::string ja3_raw;
    std::string ja3_hash;

    bool is_deprecated_tls{false};   // SSL 3.0, TLS 1.0, TLS 1.1
    bool has_weak_ciphers{false};     // RC4, 3DES, EXPORT, NULL, Static RSA
    std::vector<std::string> posture_anomalies;
};

struct ServiceBannerInfo {
    std::string service;          // SSH, HTTP, FTP, SMTP
    std::string banner_raw;       // Full raw banner
    std::string product;          // Extracted product (OpenSSH, Apache, nginx)
    std::string version;          // Extracted version
    uint16_t port{0};
    bool is_vulnerable{false};
    std::string cve_hint;
};

struct SecurityAlert {
    uint32_t timestamp{0};
    FiveTuple tuple;
    std::string alert_type;       // DEPRECATED_TLS, WEAK_CIPHER, EXPOSED_SERVICE, BLOCKED_FLOW
    std::string severity;         // LOW, MEDIUM, HIGH, CRITICAL
    std::string description;
    std::string sni;
    std::string ja3_hash;
    std::string service_banner;
    std::string action;           // FORWARDED, BLOCKED

    std::string toJSON() const;
};

// ============================================================================
// Connection State & Tracking
// ============================================================================
enum class ConnectionState {
    NEW,
    ESTABLISHED,
    CLASSIFIED,
    POSTURE_AUDITED,
    BLOCKED,
    CLOSED
};

enum class PacketAction {
    FORWARD,
    DROP,
    INSPECT,
    LOG_ONLY
};

struct Connection {
    FiveTuple tuple;
    ConnectionState state{ConnectionState::NEW};
    AppType app_type{AppType::UNKNOWN};
    std::string sni;
    
    // Posture and banner security telemetry
    TLSSecurityProfile tls_profile;
    ServiceBannerInfo banner_info;
    bool posture_alert_emitted{false};

    uint64_t packets_in{0};
    uint64_t packets_out{0};
    uint64_t bytes_in{0};
    uint64_t bytes_out{0};
    
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
    
    PacketAction action{PacketAction::FORWARD};
    
    bool syn_seen{false};
    bool syn_ack_seen{false};
    bool fin_seen{false};
};

// ============================================================================
// Packet Job for Inter-Thread Passing
// ============================================================================
struct PacketJob {
    uint32_t packet_id{0};
    FiveTuple tuple;
    std::vector<uint8_t> data;
    size_t eth_offset{0};
    size_t ip_offset{0};
    size_t transport_offset{0};
    size_t payload_offset{0};
    size_t payload_length{0};
    uint8_t tcp_flags{0};
    
    uint32_t ts_sec{0};
    uint32_t ts_usec{0};
};

// ============================================================================
// Engine Statistics
// ============================================================================
struct DPIStats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> forwarded_packets{0};
    std::atomic<uint64_t> dropped_packets{0};
    std::atomic<uint64_t> tcp_packets{0};
    std::atomic<uint64_t> udp_packets{0};
    std::atomic<uint64_t> other_packets{0};
    std::atomic<uint64_t> active_connections{0};

    // Security Posture Audit Stats
    std::atomic<uint64_t> tls_client_hellos{0};
    std::atomic<uint64_t> deprecated_tls_flows{0};
    std::atomic<uint64_t> weak_cipher_flows{0};
    std::atomic<uint64_t> unique_ja3_fingerprints{0};
    std::atomic<uint64_t> exposed_service_banners{0};
    std::atomic<uint64_t> potential_cve_exposures{0};

    DPIStats() = default;
    DPIStats(const DPIStats&) = delete;
    DPIStats& operator=(const DPIStats&) = delete;
};

} // namespace DPI

#endif // DPI_TYPES_H
