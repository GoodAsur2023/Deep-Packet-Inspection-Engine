#ifndef DPI_BANNER_EXTRACTOR_H
#define DPI_BANNER_EXTRACTOR_H

#include <string>
#include <cstdint>
#include <optional>
#include "types.h"

namespace DPI {

// ============================================================================
// Passive Service Banner & Exposure Extractor
//
// Extracts L7 banners from unencrypted / initial service handshakes:
// - SSH (Port 22): SSH-2.0-OpenSSH_... (identifies legacy OpenSSH, CVE exposure)
// - HTTP (Port 80/8080): Server: Apache/nginx headers
// - FTP (Port 21): 220 banner greetings
// - SMTP (Port 25/587): 220 mail server greetings
// ============================================================================
class BannerExtractor {
public:
    static std::optional<ServiceBannerInfo> inspect(
        const uint8_t* payload, 
        size_t length, 
        uint16_t src_port, 
        uint16_t dst_port
    );

private:
    static std::optional<ServiceBannerInfo> extractSSH(const uint8_t* payload, size_t length, uint16_t port);
    static std::optional<ServiceBannerInfo> extractHTTP(const uint8_t* payload, size_t length, uint16_t port);
    static std::optional<ServiceBannerInfo> extractFTP(const uint8_t* payload, size_t length, uint16_t port);
    static std::optional<ServiceBannerInfo> extractSMTP(const uint8_t* payload, size_t length, uint16_t port);
};

} // namespace DPI

#endif // DPI_BANNER_EXTRACTOR_H
