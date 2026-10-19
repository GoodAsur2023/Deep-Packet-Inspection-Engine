#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <cstdint>
#include <string>
#include <array>
#include <sstream>
#include <iomanip>
#include "pcap_reader.h"

namespace PacketAnalyzer {

// Ethernet Header (14 bytes)
// This is the first layer - the "envelope" for the packet
struct EthernetHeader {
    std::array<uint8_t, 6> dest_mac;    // Destination MAC address
    std::array<uint8_t, 6> src_mac;     // Source MAC address
    uint16_t ether_type;                 // Type of payload (0x0800 = IPv4)
};

// IPv4 Header (20-60 bytes, usually 20)
struct IPv4Header {
    uint8_t  version_ihl;      // Version (4 bits) + Header Length (4 bits)
    uint8_t  tos;              // Type of Service
    uint16_t total_length;     // Total packet length
    uint16_t identification;   // Fragment identification
    uint16_t flags_fragment;   // Flags (3 bits) + Fragment Offset (13 bits)
    uint8_t  ttl;              // Time To Live
    uint8_t  protocol;         // Protocol (6=TCP, 17=UDP, 1=ICMP)
    uint16_t checksum;         // Header checksum
    uint32_t src_ip;           // Source IP address
    uint32_t dest_ip;          // Destination IP address
    // Options may follow if header length > 5
};

// TCP Header (20-60 bytes, usually 20)
struct TCPHeader {
    uint16_t src_port;         // Source port
    uint16_t dest_port;        // Destination port
    uint32_t seq_number;       // Sequence number
    uint32_t ack_number;       // Acknowledgment number
    uint8_t  data_offset;      // Data offset (4 bits) + Reserved (4 bits)
    uint8_t  flags;            // TCP flags (SYN, ACK, FIN, etc.)
    uint16_t window;           // Window size
    uint16_t checksum;         // Checksum
    uint16_t urgent_pointer;   // Urgent pointer
};

// UDP Header (8 bytes - always fixed size)
struct UDPHeader {
    uint16_t src_port;         // Source port
    uint16_t dest_port;        // Destination port
    uint16_t length;           // Length of UDP header + data
    uint16_t checksum;         // Checksum
};

// Parsed packet information - zero-copy hot-path representation
// String formatting is deferred to display-time via accessor methods
// to eliminate per-packet heap allocations on the inspection pipeline.
struct ParsedPacket {
    // Timestamps
    uint32_t timestamp_sec;
    uint32_t timestamp_usec;
    
    // Ethernet layer (raw binary - no heap allocation)
    std::array<uint8_t, 6> src_mac_raw{};
    std::array<uint8_t, 6> dest_mac_raw{};
    uint16_t ether_type;
    
    // IP layer (binary uint32_t - no string conversion on hot path)
    bool has_ip = false;
    uint8_t ip_version = 0;
    uint32_t src_ip_int = 0;
    uint32_t dest_ip_int = 0;
    uint8_t protocol = 0;          // TCP=6, UDP=17, ICMP=1
    uint8_t ttl = 0;
    
    // Transport layer (if present)
    bool has_tcp = false;
    bool has_udp = false;
    uint16_t src_port = 0;
    uint16_t dest_port = 0;
    
    // TCP-specific
    uint8_t tcp_flags = 0;
    uint32_t seq_number = 0;
    uint32_t ack_number = 0;
    
    // Payload
    size_t payload_offset = 0;
    size_t payload_length = 0;
    const uint8_t* payload_data = nullptr;  // Points into original packet

    // Lazy string accessors (only called for display/reporting, not on hot path)
    std::string srcMacString() const { return formatMAC(src_mac_raw.data()); }
    std::string destMacString() const { return formatMAC(dest_mac_raw.data()); }
    std::string srcIPString() const { return formatIPv4(src_ip_int); }
    std::string destIPString() const { return formatIPv4(dest_ip_int); }

private:
    static std::string formatMAC(const uint8_t* mac) {
        std::ostringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < 6; i++) {
            if (i > 0) ss << ":";
            ss << std::setw(2) << static_cast<int>(mac[i]);
        }
        return ss.str();
    }
    static std::string formatIPv4(uint32_t ip) {
        std::ostringstream ss;
        ss << ((ip >> 0) & 0xFF) << "."
           << ((ip >> 8) & 0xFF) << "."
           << ((ip >> 16) & 0xFF) << "."
           << ((ip >> 24) & 0xFF);
        return ss.str();
    }
};

// Class to parse raw packets
class PacketParser {
public:
    // Parse a raw packet and fill in the ParsedPacket structure
    static bool parse(const RawPacket& raw, ParsedPacket& parsed);
    
    // Helper functions to convert to human-readable strings
    static std::string macToString(const uint8_t* mac);
    static std::string ipToString(uint32_t ip);
    static std::string protocolToString(uint8_t protocol);
    static std::string tcpFlagsToString(uint8_t flags);
    
private:
    static bool parseEthernet(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset);
    static bool parseIPv4(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset);
    static bool parseTCP(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset);
    static bool parseUDP(const uint8_t* data, size_t len, ParsedPacket& parsed, size_t& offset);
};

// TCP Flag constants
namespace TCPFlags {
    constexpr uint8_t FIN = 0x01;
    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t RST = 0x04;
    constexpr uint8_t PSH = 0x08;
    constexpr uint8_t ACK = 0x10;
    constexpr uint8_t URG = 0x20;
}

// Protocol numbers
namespace Protocol {
    constexpr uint8_t ICMP = 1;
    constexpr uint8_t TCP = 6;
    constexpr uint8_t UDP = 17;
}

// EtherType values
namespace EtherType {
    constexpr uint16_t IPv4 = 0x0800;
    constexpr uint16_t IPv6 = 0x86DD;
    constexpr uint16_t ARP  = 0x0806;
}

} // namespace PacketAnalyzer

#endif // PACKET_PARSER_H
