#ifndef DPI_SNI_EXTRACTOR_H
#define DPI_SNI_EXTRACTOR_H

#include <string>
#include <cstdint>
#include <optional>
#include <vector>
#include "types.h"

namespace DPI {

// ============================================================================
// TLS Cryptographic Posture Inspector & SNI Extractor
//
// Inspects TLS ClientHello and ServerHello handshakes:
// - Extracts Server Name Indication (SNI)
// - Computes JA3 cryptographic fingerprints (ClientHello MD5 hash)
// - Audits deprecated TLS protocols (SSL 3.0, TLS 1.0, TLS 1.1)
// - Audits insecure cipher suites (RC4, 3DES, EXPORT, NULL, Non-PFS RSA)
// - Audits negotiated parameters in ServerHello
// ============================================================================
class SNIExtractor {
public:
    // Extract SNI string (backward compatible)
    static std::optional<std::string> extract(const uint8_t* payload, size_t length);
    
    // Perform full cryptographic posture audit on ClientHello
    static std::optional<TLSSecurityProfile> auditClientHello(const uint8_t* payload, size_t length);

    // Audit ServerHello response (negotiated version and cipher)
    static bool auditServerHello(const uint8_t* payload, size_t length, TLSSecurityProfile& profile);

    // Protocol check helpers
    static bool isTLSClientHello(const uint8_t* payload, size_t length);
    static bool isTLSServerHello(const uint8_t* payload, size_t length);

    // Utility: Check if a cipher suite is considered weak/insecure
    static bool isWeakCipherSuite(uint16_t cipher);

    // Utility: Check if cipher lacks Forward Secrecy (PFS)
    static bool lacksForwardSecrecy(uint16_t cipher);

    // Utility: Check if TLS version is deprecated (RFC 8996)
    static bool isDeprecatedVersion(uint16_t version);

    // Extract all raw extensions for debugging
    static std::vector<std::pair<uint16_t, std::string>> extractExtensions(
        const uint8_t* payload, size_t length);

private:
    static constexpr uint8_t CONTENT_TYPE_HANDSHAKE = 0x16;
    static constexpr uint8_t HANDSHAKE_CLIENT_HELLO = 0x01;
    static constexpr uint8_t HANDSHAKE_SERVER_HELLO = 0x02;

    static constexpr uint16_t EXTENSION_SNI = 0x0000;
    static constexpr uint16_t EXTENSION_SUPPORTED_GROUPS = 0x000a;
    static constexpr uint16_t EXTENSION_EC_POINT_FORMATS = 0x000b;

    static bool isGrease(uint16_t val);

    static uint16_t readUint16BE(const uint8_t* data);
    static uint32_t readUint24BE(const uint8_t* data);
};

// ============================================================================
// HTTP Host Header Extractor (for unencrypted HTTP)
// ============================================================================
class HTTPHostExtractor {
public:
    static std::optional<std::string> extract(const uint8_t* payload, size_t length);
    static bool isHTTPRequest(const uint8_t* payload, size_t length);
};

// ============================================================================
// DNS Query Extractor
// ============================================================================
class DNSExtractor {
public:
    static std::optional<std::string> extractQuery(const uint8_t* payload, size_t length);
    static bool isDNSQuery(const uint8_t* payload, size_t length);
};

} // namespace DPI

#endif // DPI_SNI_EXTRACTOR_H
