#include "types.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace DPI {

namespace {

std::string formatIPv4(uint32_t ip) {
    std::ostringstream s;
    s << ((ip >> 0) & 0xFF) << "."
      << ((ip >> 8) & 0xFF) << "."
      << ((ip >> 16) & 0xFF) << "."
      << ((ip >> 24) & 0xFF);
    return s.str();
}

} // namespace

std::string FiveTuple::srcIPString() const {
    return formatIPv4(src_ip);
}

std::string FiveTuple::dstIPString() const {
    return formatIPv4(dst_ip);
}

std::string FiveTuple::toString() const {
    std::ostringstream ss;
    ss << srcIPString() << ":" << src_port
       << " -> "
       << dstIPString() << ":" << dst_port
       << " (" << (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") << ")";
    return ss.str();
}

std::string tlsVersionToString(uint16_t version) {
    switch (version) {
        case 0x0300: return "SSL 3.0 (DEPRECATED)";
        case 0x0301: return "TLS 1.0 (DEPRECATED)";
        case 0x0302: return "TLS 1.1 (DEPRECATED)";
        case 0x0303: return "TLS 1.2";
        case 0x0304: return "TLS 1.3";
        default: {
            std::ostringstream ss;
            ss << "0x" << std::hex << std::setw(4) << std::setfill('0') << version;
            return ss.str();
        }
    }
}

std::string cipherSuiteToString(uint16_t cipher) {
    switch (cipher) {
        // Deprecated / Weak Ciphers
        case 0x0004: return "TLS_RSA_WITH_RC4_128_MD5 [WEAK]";
        case 0x0005: return "TLS_RSA_WITH_RC4_128_SHA [WEAK]";
        case 0x000A: return "TLS_RSA_WITH_3DES_EDE_CBC_SHA [WEAK]";
        case 0x0013: return "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA [WEAK]";
        case 0x0016: return "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA [WEAK]";
        case 0x002F: return "TLS_RSA_WITH_AES_128_CBC_SHA [NO_PFS]";
        case 0x0035: return "TLS_RSA_WITH_AES_256_CBC_SHA [NO_PFS]";
        // Modern TLS 1.2 Ciphers
        case 0xC02F: return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        case 0xC030: return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
        case 0xC02B: return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
        case 0xC02C: return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
        case 0xCCA8: return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
        case 0xCCA9: return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";
        // Modern TLS 1.3 Ciphers
        case 0x1301: return "TLS_AES_128_GCM_SHA256 (TLS1.3)";
        case 0x1302: return "TLS_AES_256_GCM_SHA384 (TLS1.3)";
        case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256 (TLS1.3)";
        default: {
            std::ostringstream ss;
            ss << "0x" << std::hex << std::setw(4) << std::setfill('0') << cipher;
            return ss.str();
        }
    }
}

std::string SecurityAlert::toJSON() const {
    std::ostringstream ss;
    ss << "{"
       << "\"timestamp\":" << timestamp << ","
       << "\"alert_type\":\"" << alert_type << "\","
       << "\"severity\":\"" << severity << "\","
       << "\"src_ip\":\"" << tuple.srcIPString() << "\","
       << "\"dst_ip\":\"" << tuple.dstIPString() << "\","
       << "\"src_port\":" << tuple.src_port << ","
       << "\"dst_port\":" << tuple.dst_port << ","
       << "\"protocol\":\"" << (tuple.protocol == 6 ? "TCP" : "UDP") << "\","
       << "\"sni\":\"" << sni << "\","
       << "\"ja3_hash\":\"" << ja3_hash << "\","
       << "\"service_banner\":\"" << service_banner << "\","
       << "\"description\":\"" << description << "\","
       << "\"action\":\"" << action << "\""
       << "}";
    return ss.str();
}

std::string appTypeToString(AppType type) {
    switch (type) {
        case AppType::UNKNOWN:    return "Unknown";
        case AppType::HTTP:       return "HTTP";
        case AppType::HTTPS:      return "HTTPS";
        case AppType::DNS:        return "DNS";
        case AppType::TLS:        return "TLS";
        case AppType::QUIC:       return "QUIC";
        case AppType::SSH:        return "SSH";
        case AppType::FTP:        return "FTP";
        case AppType::SMTP:       return "SMTP";
        case AppType::GOOGLE:     return "Google";
        case AppType::FACEBOOK:   return "Facebook";
        case AppType::YOUTUBE:    return "YouTube";
        case AppType::TWITTER:    return "Twitter/X";
        case AppType::INSTAGRAM:  return "Instagram";
        case AppType::NETFLIX:    return "Netflix";
        case AppType::AMAZON:     return "Amazon";
        case AppType::MICROSOFT:  return "Microsoft";
        case AppType::APPLE:      return "Apple";
        case AppType::WHATSAPP:   return "WhatsApp";
        case AppType::TELEGRAM:   return "Telegram";
        case AppType::TIKTOK:     return "TikTok";
        case AppType::SPOTIFY:    return "Spotify";
        case AppType::ZOOM:       return "Zoom";
        case AppType::DISCORD:    return "Discord";
        case AppType::GITHUB:     return "GitHub";
        case AppType::CLOUDFLARE: return "Cloudflare";
        default:                  return "Unknown";
    }
}

AppType sniToAppType(const std::string& sni) {
    if (sni.empty()) return AppType::UNKNOWN;
    
    std::string lower_sni = sni;
    std::transform(lower_sni.begin(), lower_sni.end(), lower_sni.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    
    if (lower_sni.find("youtube") != std::string::npos ||
        lower_sni.find("ytimg") != std::string::npos ||
        lower_sni.find("youtu.be") != std::string::npos ||
        lower_sni.find("yt3.ggpht") != std::string::npos) {
        return AppType::YOUTUBE;
    }
    
    if (lower_sni.find("google") != std::string::npos ||
        lower_sni.find("gstatic") != std::string::npos ||
        lower_sni.find("googleapis") != std::string::npos ||
        lower_sni.find("ggpht") != std::string::npos ||
        lower_sni.find("gvt1") != std::string::npos) {
        return AppType::GOOGLE;
    }
    
    if (lower_sni.find("facebook") != std::string::npos ||
        lower_sni.find("fbcdn") != std::string::npos ||
        lower_sni.find("fb.com") != std::string::npos ||
        lower_sni.find("fbsbx") != std::string::npos ||
        lower_sni.find("meta.com") != std::string::npos) {
        return AppType::FACEBOOK;
    }
    
    if (lower_sni.find("instagram") != std::string::npos ||
        lower_sni.find("cdninstagram") != std::string::npos) {
        return AppType::INSTAGRAM;
    }
    
    if (lower_sni.find("twitter") != std::string::npos ||
        lower_sni.find("twimg") != std::string::npos ||
        lower_sni.find("t.co") != std::string::npos ||
        lower_sni.find("x.com") != std::string::npos) {
        return AppType::TWITTER;
    }
    
    if (lower_sni.find("netflix") != std::string::npos ||
        lower_sni.find("nflxvideo") != std::string::npos ||
        lower_sni.find("nflxext") != std::string::npos) {
        return AppType::NETFLIX;
    }
    
    if (lower_sni.find("amazon") != std::string::npos ||
        lower_sni.find("aws") != std::string::npos ||
        lower_sni.find("media-amazon") != std::string::npos) {
        return AppType::AMAZON;
    }
    
    if (lower_sni.find("microsoft") != std::string::npos ||
        lower_sni.find("live.com") != std::string::npos ||
        lower_sni.find("office.com") != std::string::npos ||
        lower_sni.find("azure") != std::string::npos ||
        lower_sni.find("msn.com") != std::string::npos) {
        return AppType::MICROSOFT;
    }
    
    if (lower_sni.find("apple") != std::string::npos ||
        lower_sni.find("icloud") != std::string::npos ||
        lower_sni.find("aaplimg") != std::string::npos) {
        return AppType::APPLE;
    }
    
    if (lower_sni.find("whatsapp") != std::string::npos) {
        return AppType::WHATSAPP;
    }
    
    if (lower_sni.find("telegram") != std::string::npos ||
        lower_sni.find("t.me") != std::string::npos) {
        return AppType::TELEGRAM;
    }
    
    if (lower_sni.find("tiktok") != std::string::npos ||
        lower_sni.find("byteoversea") != std::string::npos ||
        lower_sni.find("ibytedtos") != std::string::npos) {
        return AppType::TIKTOK;
    }
    
    if (lower_sni.find("spotify") != std::string::npos ||
        lower_sni.find("scdn.co") != std::string::npos) {
        return AppType::SPOTIFY;
    }
    
    if (lower_sni.find("zoom") != std::string::npos) {
        return AppType::ZOOM;
    }
    
    if (lower_sni.find("discord") != std::string::npos ||
        lower_sni.find("discordapp") != std::string::npos) {
        return AppType::DISCORD;
    }
    
    if (lower_sni.find("github") != std::string::npos ||
        lower_sni.find("githubusercontent") != std::string::npos) {
        return AppType::GITHUB;
    }
    
    if (lower_sni.find("cloudflare") != std::string::npos) {
        return AppType::CLOUDFLARE;
    }
    
    return AppType::HTTPS;
}

} // namespace DPI
