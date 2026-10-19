#include "banner_extractor.h"
#include <cstring>
#include <algorithm>

namespace DPI {

std::optional<ServiceBannerInfo> BannerExtractor::inspect(
    const uint8_t* payload, 
    size_t length, 
    uint16_t src_port, 
    uint16_t dst_port
) {
    if (!payload || length == 0) return std::nullopt;

    // Check SSH (typically port 22)
    if (src_port == 22 || dst_port == 22 || (length >= 4 && std::memcmp(payload, "SSH-", 4) == 0)) {
        auto res = extractSSH(payload, length, (src_port == 22 ? src_port : dst_port));
        if (res) return res;
    }

    // Check HTTP (typically port 80, 8080, 8000, 8888)
    if (src_port == 80 || src_port == 8080 || src_port == 8000 || src_port == 8888 ||
        dst_port == 80 || dst_port == 8080 || dst_port == 8000 || dst_port == 8888) {
        auto res = extractHTTP(payload, length, src_port);
        if (res) return res;
    }

    // Check FTP (port 21)
    if (src_port == 21 || dst_port == 21) {
        auto res = extractFTP(payload, length, src_port);
        if (res) return res;
    }

    // Check SMTP (port 25, 587)
    if (src_port == 25 || src_port == 587 || dst_port == 25 || dst_port == 587) {
        auto res = extractSMTP(payload, length, src_port);
        if (res) return res;
    }

    return std::nullopt;
}

std::optional<ServiceBannerInfo> BannerExtractor::extractSSH(
    const uint8_t* payload, 
    size_t length, 
    uint16_t port
) {
    if (length < 7 || std::memcmp(payload, "SSH-", 4) != 0) {
        return std::nullopt;
    }

    const char* str = reinterpret_cast<const char*>(payload);
    size_t line_len = 0;
    while (line_len < length && str[line_len] != '\r' && str[line_len] != '\n') {
        line_len++;
    }

    if (line_len < 7) return std::nullopt;

    std::string banner(str, line_len);
    ServiceBannerInfo info;
    info.service = "SSH";
    info.banner_raw = banner;
    info.port = port;

    // Check protocol version
    if (banner.rfind("SSH-1.", 0) == 0) {
        info.is_vulnerable = true;
        info.cve_hint = "DEPRECATED_SSHv1_PROTOCOL (RFC 4253, vulnerable to plaintext injection)";
    }

    // Parse software token: SSH-<proto>-<software>
    size_t second_dash = banner.find('-', 4);
    if (second_dash != std::string::npos && second_dash + 1 < banner.size()) {
        std::string soft_part = banner.substr(second_dash + 1);
        size_t space = soft_part.find(' ');
        std::string software = (space != std::string::npos) ? soft_part.substr(0, space) : soft_part;
        info.product = software;

        // Check OpenSSH versions
        if (software.find("OpenSSH_") != std::string::npos) {
            std::string ver = software.substr(8);
            info.version = ver;
            if (ver.rfind("7.4", 0) == 0 || ver.rfind("7.2", 0) == 0 || ver.rfind("6.", 0) == 0) {
                info.is_vulnerable = true;
                info.cve_hint = "CVE-2016-10009 / CVE-2016-10012 (OpenSSH < 7.4 privilege escalation)";
            } else if (ver.rfind("9.6p1", 0) == 0) {
                info.is_vulnerable = true;
                info.cve_hint = "CVE-2024-6387 regreSSHion (Unauthenticated RCE in OpenSSH server)";
            }
        }
    }

    return info;
}

std::optional<ServiceBannerInfo> BannerExtractor::extractHTTP(
    const uint8_t* payload, 
    size_t length, 
    uint16_t port
) {
    if (length < 15) return std::nullopt;
    const char* str = reinterpret_cast<const char*>(payload);
    const char* end = str + length;

    // Look for HTTP response header "Server: "
    const char* server_hdr = nullptr;
    for (const char* p = str; p + 8 <= end; ++p) {
        if ((p[0] == '\r' || p[0] == '\n') &&
            (p[1] == 'S' || p[1] == 's') &&
            (p[2] == 'e' || p[2] == 'e') &&
            (p[3] == 'r' || p[3] == 'r') &&
            (p[4] == 'v' || p[4] == 'v') &&
            (p[5] == 'e' || p[5] == 'e') &&
            (p[6] == 'r' || p[6] == 'r') &&
            p[7] == ':') {
            server_hdr = p + 8;
            break;
        }
    }

    if (!server_hdr) return std::nullopt;

    while (server_hdr < end && (*server_hdr == ' ' || *server_hdr == '\t')) {
        server_hdr++;
    }

    const char* line_end = server_hdr;
    while (line_end < end && *line_end != '\r' && *line_end != '\n') {
        line_end++;
    }

    if (line_end <= server_hdr) return std::nullopt;

    std::string banner(server_hdr, line_end - server_hdr);
    ServiceBannerInfo info;
    info.service = "HTTP";
    info.banner_raw = banner;
    info.port = port;

    // Check known vulnerable server versions
    if (banner.find("Apache/2.4.49") != std::string::npos || banner.find("Apache/2.4.50") != std::string::npos) {
        info.is_vulnerable = true;
        info.cve_hint = "CVE-2021-41773 / CVE-2021-42013 (Critical Path Traversal & RCE in Apache HTTPD)";
        info.product = "Apache HTTPD";
        info.version = "2.4.49";
    } else if (banner.find("nginx/1.18.0") != std::string::npos) {
        info.is_vulnerable = true;
        info.cve_hint = "CVE-2021-23017 / CVE-2023-44487 (HTTP/2 Rapid Reset & DNS Resolver overflow)";
        info.product = "nginx";
        info.version = "1.18.0";
    } else {
        info.product = banner;
    }

    return info;
}

std::optional<ServiceBannerInfo> BannerExtractor::extractFTP(
    const uint8_t* payload, 
    size_t length, 
    uint16_t port
) {
    if (length < 5 || std::memcmp(payload, "220 ", 4) != 0) return std::nullopt;

    const char* str = reinterpret_cast<const char*>(payload);
    size_t line_len = 0;
    while (line_len < length && str[line_len] != '\r' && str[line_len] != '\n') {
        line_len++;
    }

    ServiceBannerInfo info;
    info.service = "FTP";
    info.banner_raw = std::string(str, line_len);
    info.port = port;
    info.product = info.banner_raw.substr(4);

    if (info.product.find("vsftpd 2.3.4") != std::string::npos) {
        info.is_vulnerable = true;
        info.cve_hint = "CVE-2011-2523 (vsftpd 2.3.4 Backdoor Command Execution)";
    }

    return info;
}

std::optional<ServiceBannerInfo> BannerExtractor::extractSMTP(
    const uint8_t* payload, 
    size_t length, 
    uint16_t port
) {
    if (length < 5 || std::memcmp(payload, "220 ", 4) != 0) return std::nullopt;

    const char* str = reinterpret_cast<const char*>(payload);
    size_t line_len = 0;
    while (line_len < length && str[line_len] != '\r' && str[line_len] != '\n') {
        line_len++;
    }

    ServiceBannerInfo info;
    info.service = "SMTP";
    info.banner_raw = std::string(str, line_len);
    info.port = port;
    info.product = info.banner_raw.substr(4);

    if (info.product.find("Exim 4.8") != std::string::npos || info.product.find("Exim 4.90") != std::string::npos) {
        info.is_vulnerable = true;
        info.cve_hint = "CVE-2019-10149 Return of the WIZard (Exim Remote Command Execution)";
    }

    return info;
}

} // namespace DPI
