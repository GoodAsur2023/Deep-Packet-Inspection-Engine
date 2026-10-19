#include "sni_extractor.h"
#include "md5.h"
#include <cstring>
#include <algorithm>
#include <sstream>

namespace DPI {

// ============================================================================
// TLS Posture & SNI Extractor Implementation
// ============================================================================

uint16_t SNIExtractor::readUint16BE(const uint8_t* data) {
    return (static_cast<uint16_t>(data[0]) << 8) | data[1];
}

uint32_t SNIExtractor::readUint24BE(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 16) |
           (static_cast<uint32_t>(data[1]) << 8) |
           data[2];
}

bool SNIExtractor::isGrease(uint16_t val) {
    // RFC 8701: GREASE values have form 0x?a?a where both ? nibbles are identical
    return (val & 0x0F0F) == 0x0A0A && ((val >> 8) == (val & 0xFF));
}

bool SNIExtractor::isDeprecatedVersion(uint16_t version) {
    // SSL 2.0 (0x0200), SSL 3.0 (0x0300), TLS 1.0 (0x0301), TLS 1.1 (0x0302) are deprecated
    return version <= 0x0302 && version >= 0x0200;
}

bool SNIExtractor::isWeakCipherSuite(uint16_t cipher) {
    switch (cipher) {
        // RC4 ciphers (RFC 7465 prohibited)
        case 0x0004: // TLS_RSA_WITH_RC4_128_MD5
        case 0x0005: // TLS_RSA_WITH_RC4_128_SHA
        case 0x0018: // TLS_DH_anon_WITH_RC4_128_MD5
        case 0xC007: // TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
        case 0xC011: // TLS_ECDHE_RSA_WITH_RC4_128_SHA
        // 3DES ciphers (SWEET32 vulnerability, deprecated by NIST)
        case 0x000A: // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        case 0x0013: // TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
        case 0x0016: // TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
        case 0xC008: // TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
        case 0xC012: // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
        // NULL encryption / Export grade ciphers
        case 0x0000: // TLS_NULL_WITH_NULL_NULL
        case 0x0001: // TLS_RSA_WITH_NULL_MD5
        case 0x0002: // TLS_RSA_WITH_NULL_SHA
        case 0x0003: // TLS_RSA_EXPORT_WITH_RC4_40_MD5
        case 0x0006: // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
        case 0x0008: // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
        case 0x0009: // TLS_RSA_WITH_DES_CBC_SHA
            return true;
        default:
            return false;
    }
}

bool SNIExtractor::lacksForwardSecrecy(uint16_t cipher) {
    // Static RSA key exchanges without (EC)DHE
    switch (cipher) {
        case 0x002F: // TLS_RSA_WITH_AES_128_CBC_SHA
        case 0x0035: // TLS_RSA_WITH_AES_256_CBC_SHA
        case 0x009C: // TLS_RSA_WITH_AES_128_GCM_SHA256
        case 0x009D: // TLS_RSA_WITH_AES_256_GCM_SHA384
            return true;
        default:
            return false;
    }
}

bool SNIExtractor::isTLSClientHello(const uint8_t* payload, size_t length) {
    if (length < 9) return false;
    if (payload[0] != CONTENT_TYPE_HANDSHAKE) return false;
    
    uint16_t version = readUint16BE(payload + 1);
    if (version < 0x0300 || version > 0x0304) return false;
    
    uint16_t record_length = readUint16BE(payload + 3);
    if (record_length > length - 5) return false;
    
    return payload[5] == HANDSHAKE_CLIENT_HELLO;
}

bool SNIExtractor::isTLSServerHello(const uint8_t* payload, size_t length) {
    if (length < 9) return false;
    if (payload[0] != CONTENT_TYPE_HANDSHAKE) return false;
    
    uint16_t version = readUint16BE(payload + 1);
    if (version < 0x0300 || version > 0x0304) return false;
    
    return payload[5] == HANDSHAKE_SERVER_HELLO;
}

std::optional<TLSSecurityProfile> SNIExtractor::auditClientHello(const uint8_t* payload, size_t length) {
    if (!isTLSClientHello(payload, length)) {
        return std::nullopt;
    }

    TLSSecurityProfile profile;
    profile.record_version = readUint16BE(payload + 1);

    size_t offset = 5; // Skip TLS record header
    if (offset + 4 > length) return std::nullopt;

    uint32_t handshake_length = readUint24BE(payload + offset + 1);
    offset += 4; // Skip handshake type + length

    if (offset + 34 > length) return std::nullopt;
    profile.client_version = readUint16BE(payload + offset);
    offset += 2;  // Skip client version
    offset += 32; // Skip random bytes

    // Session ID
    if (offset >= length) return std::nullopt;
    uint8_t session_id_len = payload[offset];
    offset += 1 + session_id_len;

    // Cipher Suites
    if (offset + 2 > length) return std::nullopt;
    uint16_t cipher_suites_len = readUint16BE(payload + offset);
    offset += 2;

    if (offset + cipher_suites_len > length) return std::nullopt;

    std::vector<uint16_t> ja3_ciphers;
    for (size_t i = 0; i + 1 < cipher_suites_len; i += 2) {
        uint16_t cipher = readUint16BE(payload + offset + i);
        profile.offered_ciphers.push_back(cipher);
        if (isWeakCipherSuite(cipher)) {
            profile.has_weak_ciphers = true;
        }
        if (!isGrease(cipher)) {
            ja3_ciphers.push_back(cipher);
        }
    }
    offset += cipher_suites_len;

    // Compression Methods
    if (offset >= length) return std::nullopt;
    uint8_t comp_len = payload[offset];
    offset += 1 + comp_len;

    // Extensions
    std::vector<uint16_t> ja3_extensions;
    std::vector<uint16_t> ja3_curves;
    std::vector<uint8_t>  ja3_points;

    if (offset + 2 <= length) {
        uint16_t extensions_len = readUint16BE(payload + offset);
        offset += 2;
        size_t ext_end = std::min(offset + extensions_len, length);

        while (offset + 4 <= ext_end) {
            uint16_t ext_type = readUint16BE(payload + offset);
            uint16_t ext_len = readUint16BE(payload + offset + 2);
            offset += 4;

            if (offset + ext_len > ext_end) break;

            profile.extensions.push_back(ext_type);
            if (!isGrease(ext_type)) {
                ja3_extensions.push_back(ext_type);
            }

            // SNI Extension (0x0000)
            if (ext_type == EXTENSION_SNI && ext_len >= 5) {
                size_t sni_offset = offset + 2; // skip list length
                if (sni_offset < offset + ext_len && payload[sni_offset] == 0x00) { // hostname
                    sni_offset += 1;
                    if (sni_offset + 2 <= offset + ext_len) {
                        uint16_t hostname_len = readUint16BE(payload + sni_offset);
                        sni_offset += 2;
                        if (sni_offset + hostname_len <= offset + ext_len) {
                            profile.sni = std::string(
                                reinterpret_cast<const char*>(payload + sni_offset),
                                hostname_len
                            );
                        }
                    }
                }
            }
            // Supported Groups / Elliptic Curves Extension (0x000a)
            else if (ext_type == EXTENSION_SUPPORTED_GROUPS && ext_len >= 2) {
                uint16_t groups_len = readUint16BE(payload + offset);
                size_t g_offset = offset + 2;
                size_t g_end = std::min(g_offset + groups_len, offset + ext_len);
                while (g_offset + 2 <= g_end) {
                    uint16_t curve = readUint16BE(payload + g_offset);
                    profile.elliptic_curves.push_back(curve);
                    if (!isGrease(curve)) {
                        ja3_curves.push_back(curve);
                    }
                    g_offset += 2;
                }
            }
            // EC Point Formats Extension (0x000b)
            else if (ext_type == EXTENSION_EC_POINT_FORMATS && ext_len >= 1) {
                uint8_t points_len = payload[offset];
                size_t p_offset = offset + 1;
                size_t p_end = std::min(p_offset + points_len, offset + ext_len);
                while (p_offset < p_end) {
                    uint8_t fmt = payload[p_offset++];
                    profile.ec_point_formats.push_back(fmt);
                    ja3_points.push_back(fmt);
                }
            }

            offset += ext_len;
        }
    }

    // Build JA3 String: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    std::ostringstream ja3_ss;
    ja3_ss << profile.client_version << ",";

    for (size_t i = 0; i < ja3_ciphers.size(); ++i) {
        ja3_ss << (i > 0 ? "-" : "") << ja3_ciphers[i];
    }
    ja3_ss << ",";

    for (size_t i = 0; i < ja3_extensions.size(); ++i) {
        ja3_ss << (i > 0 ? "-" : "") << ja3_extensions[i];
    }
    ja3_ss << ",";

    for (size_t i = 0; i < ja3_curves.size(); ++i) {
        ja3_ss << (i > 0 ? "-" : "") << ja3_curves[i];
    }
    ja3_ss << ",";

    for (size_t i = 0; i < ja3_points.size(); ++i) {
        ja3_ss << (i > 0 ? "-" : "") << static_cast<int>(ja3_points[i]);
    }

    profile.ja3_raw = ja3_ss.str();
    profile.ja3_hash = MD5::hash(profile.ja3_raw);

    // Cryptographic Posture Evaluation
    // Note: Record layer version is often 0x0301 (TLS 1.0) for backwards compatibility even in TLS 1.2/1.3.
    // ClientHandshake version (profile.client_version) represents the client's actual proposed TLS version.
    if (isDeprecatedVersion(profile.client_version)) {
        profile.is_deprecated_tls = true;
        profile.posture_anomalies.push_back("DEPRECATED_TLS_VERSION (" + tlsVersionToString(profile.client_version) + ")");
    }

    if (profile.has_weak_ciphers) {
        profile.posture_anomalies.push_back("OFFERS_WEAK_CIPHERS (RC4/3DES/EXPORT)");
    }

    return profile;
}

bool SNIExtractor::auditServerHello(const uint8_t* payload, size_t length, TLSSecurityProfile& profile) {
    if (!isTLSServerHello(payload, length)) return false;

    size_t offset = 5; // Skip record header
    if (offset + 4 > length) return false;
    offset += 4; // Skip handshake header

    if (offset + 34 > length) return false;
    profile.server_version = readUint16BE(payload + offset);
    offset += 2;  // Skip version
    offset += 32; // Skip random

    if (offset >= length) return false;
    uint8_t session_id_len = payload[offset];
    offset += 1 + session_id_len;

    // Server selected cipher suite (single 2 bytes)
    if (offset + 2 <= length) {
        profile.negotiated_cipher = readUint16BE(payload + offset);
        if (isWeakCipherSuite(profile.negotiated_cipher)) {
            profile.has_weak_ciphers = true;
            profile.posture_anomalies.push_back("NEGOTIATED_WEAK_CIPHER: " + cipherSuiteToString(profile.negotiated_cipher));
        }
    }

    if (isDeprecatedVersion(profile.server_version)) {
        profile.is_deprecated_tls = true;
        profile.posture_anomalies.push_back("SERVER_NEGOTIATED_DEPRECATED_TLS (" + tlsVersionToString(profile.server_version) + ")");
    }

    return true;
}

std::optional<std::string> SNIExtractor::extract(const uint8_t* payload, size_t length) {
    auto profile = auditClientHello(payload, length);
    if (profile && !profile->sni.empty()) {
        return profile->sni;
    }
    return std::nullopt;
}

std::vector<std::pair<uint16_t, std::string>> SNIExtractor::extractExtensions(
    const uint8_t* payload, size_t length) {
    std::vector<std::pair<uint16_t, std::string>> result;
    auto profile = auditClientHello(payload, length);
    if (!profile) return result;

    for (uint16_t ext : profile->extensions) {
        result.push_back({ext, ""});
    }
    return result;
}

// ============================================================================
// HTTP Host Header Extractor
// ============================================================================
bool HTTPHostExtractor::isHTTPRequest(const uint8_t* payload, size_t length) {
    if (length < 10) return false;
    const char* methods[] = {"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "CONNECT ", "OPTIONS "};
    for (const char* method : methods) {
        size_t mlen = std::strlen(method);
        if (length >= mlen && std::memcmp(payload, method, mlen) == 0) {
            return true;
        }
    }
    return false;
}

std::optional<std::string> HTTPHostExtractor::extract(const uint8_t* payload, size_t length) {
    if (!isHTTPRequest(payload, length)) return std::nullopt;

    const char* str = reinterpret_cast<const char*>(payload);
    const char* end = str + length;

    // Search for "Host:" case-insensitively
    const char* host_hdr = nullptr;
    for (const char* p = str; p + 6 <= end; ++p) {
        if ((p[0] == '\r' || p[0] == '\n') && 
            (p[1] == 'H' || p[1] == 'h') &&
            (p[2] == 'o' || p[2] == 'o') &&
            (p[3] == 's' || p[3] == 's') &&
            (p[4] == 't' || p[4] == 't') &&
            p[5] == ':') {
            host_hdr = p + 6;
            break;
        }
    }

    if (!host_hdr) return std::nullopt;

    while (host_hdr < end && (*host_hdr == ' ' || *host_hdr == '\t')) {
        host_hdr++;
    }

    const char* line_end = host_hdr;
    while (line_end < end && *line_end != '\r' && *line_end != '\n') {
        line_end++;
    }

    if (line_end <= host_hdr) return std::nullopt;

    std::string host(host_hdr, line_end - host_hdr);
    size_t colon = host.find(':');
    if (colon != std::string::npos) {
        host = host.substr(0, colon);
    }
    return host;
}

// ============================================================================
// DNS Query Extractor
// ============================================================================
bool DNSExtractor::isDNSQuery(const uint8_t* payload, size_t length) {
    if (length < 12) return false;
    uint16_t flags = (static_cast<uint16_t>(payload[2]) << 8) | payload[3];
    return (flags & 0x8000) == 0; // QR bit == 0 (Query)
}

std::optional<std::string> DNSExtractor::extractQuery(const uint8_t* payload, size_t length) {
    if (!isDNSQuery(payload, length)) return std::nullopt;

    size_t offset = 12; // Skip 12-byte DNS header
    std::string domain;

    while (offset < length) {
        uint8_t label_len = payload[offset++];
        if (label_len == 0) break; // Terminating null
        if (label_len > 63 || offset + label_len > length) return std::nullopt;

        if (!domain.empty()) domain += ".";
        domain.append(reinterpret_cast<const char*>(payload + offset), label_len);
        offset += label_len;
    }

    return domain.empty() ? std::nullopt : std::make_optional(domain);
}

} // namespace DPI
