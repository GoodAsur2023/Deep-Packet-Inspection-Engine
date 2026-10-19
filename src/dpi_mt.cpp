// AegisFlow - High-Speed Multi-Threaded DPI & Cryptographic Posture Engine
// Architecture: Reader -> [Lock-Free SPSC] -> LB Threads -> [Lock-Free SPSC] -> FP Workers -> Output Writer

#include <iostream>
#include <fstream>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <optional>
#include <csignal>

#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "banner_extractor.h"
#include "telemetry_emitter.h"
#include "spsc_queue.h"
#include "types.h"

using namespace PacketAnalyzer;
using namespace DPI;

static std::atomic<bool> g_stop_signal{false};

static void signalHandler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        g_stop_signal.store(true);
    }
}

// =============================================================================
// Packet Job representation
// =============================================================================
struct Packet {
    uint32_t id{0};
    uint32_t ts_sec{0};
    uint32_t ts_usec{0};
    FiveTuple tuple;
    std::vector<uint8_t> data;
    uint8_t tcp_flags{0};
    size_t payload_offset{0};
    size_t payload_length{0};
};

// =============================================================================
// Flow Entry with Security Posture & Telemetry
// =============================================================================
struct FlowEntry {
    FiveTuple tuple;
    AppType app_type = AppType::UNKNOWN;
    std::string sni;
    TLSSecurityProfile tls_profile;
    ServiceBannerInfo banner_info;
    uint64_t packets = 0;
    uint64_t bytes = 0;
    bool blocked = false;
    bool classified = false;
    bool posture_alert_sent = false;
};

// =============================================================================
// Blocking & Filtering Policy Manager
// =============================================================================
class Rules {
public:
    void blockIP(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_ips_.insert(parseIP(ip));
        std::cout << "[Policy] Added block rule for IP: " << ip << "\n";
    }
    
    void blockApp(const std::string& app) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
            if (appTypeToString(static_cast<AppType>(i)) == app) {
                blocked_apps_.insert(static_cast<AppType>(i));
                std::cout << "[Policy] Added block rule for Application: " << app << "\n";
                return;
            }
        }
        std::cerr << "[Policy] Unknown application name: " << app << "\n";
    }
    
    void blockDomain(const std::string& domain) {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_domains_.push_back(domain);
        std::cout << "[Policy] Added block rule for Domain pattern: " << domain << "\n";
    }
    
    bool isBlocked(uint32_t src_ip, AppType app, const std::string& sni) const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (blocked_ips_.count(src_ip)) return true;
        if (blocked_apps_.count(app)) return true;
        for (const auto& dom : blocked_domains_) {
            if (sni.find(dom) != std::string::npos) return true;
        }
        return false;
    }

private:
    static uint32_t parseIP(const std::string& ip) {
        uint32_t result = 0;
        int octet = 0, shift = 0;
        for (char c : ip) {
            if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
            else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
        }
        return result | (octet << shift);
    }
    
    mutable std::mutex mutex_;
    std::unordered_set<uint32_t> blocked_ips_;
    std::unordered_set<AppType> blocked_apps_;
    std::vector<std::string> blocked_domains_;
};

// =============================================================================
// Security Engine Statistics
// =============================================================================
struct EngineStats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> forwarded{0};
    std::atomic<uint64_t> dropped{0};
    std::atomic<uint64_t> tcp_packets{0};
    std::atomic<uint64_t> udp_packets{0};

    // Posture Audit
    std::atomic<uint64_t> tls_handshakes{0};
    std::atomic<uint64_t> deprecated_tls_flows{0};
    std::atomic<uint64_t> weak_cipher_flows{0};
    std::atomic<uint64_t> service_banners_detected{0};
    std::atomic<uint64_t> vulnerable_services_flagged{0};
    
    // Aggregated distributions
    std::mutex data_mutex;
    std::unordered_map<AppType, uint64_t> app_counts;
    std::unordered_map<std::string, AppType> detected_snis;
    std::unordered_map<std::string, std::pair<std::string, std::string>> ja3_fingerprints; // hash -> (sni, raw)
    std::vector<std::pair<std::string, std::string>> posture_warnings; // (host, warning)
    std::vector<ServiceBannerInfo> exposed_banners;
    
    void recordApp(AppType app, const std::string& sni) {
        std::lock_guard<std::mutex> lock(data_mutex);
        app_counts[app]++;
        if (!sni.empty()) {
            detected_snis[sni] = app;
        }
    }

    void recordJA3(const std::string& hash, const std::string& sni, const std::string& raw) {
        if (hash.empty()) return;
        std::lock_guard<std::mutex> lock(data_mutex);
        ja3_fingerprints[hash] = {sni, raw};
    }

    void recordPostureWarning(const std::string& host, const std::string& warning) {
        std::lock_guard<std::mutex> lock(data_mutex);
        posture_warnings.push_back({host, warning});
    }

    void recordBanner(const ServiceBannerInfo& banner) {
        std::lock_guard<std::mutex> lock(data_mutex);
        exposed_banners.push_back(banner);
    }
};

// =============================================================================
// Fast Path Worker (One per FP Thread, Consuming from Lock-Free SPSC Ring Buffer)
// =============================================================================
class FastPath {
public:
    FastPath(int id, Rules* rules, EngineStats* stats, TelemetryEmitter* telemetry, std::vector<Packet>* output_sink, std::mutex* sink_mutex)
        : id_(id), rules_(rules), stats_(stats), telemetry_(telemetry), output_sink_(output_sink), sink_mutex_(sink_mutex) {}
    
    void start() {
        running_ = true;
        thread_ = std::thread(&FastPath::run, this);
    }
    
    void stop() {
        running_ = false;
        if (thread_.joinable()) thread_.join();
    }
    
    SPSCQueue<Packet, 16384>& queue() { return input_queue_; }
    void markInputDone() { input_done_ = true; }
    
    uint64_t processed() const { return processed_; }

private:
    int id_;
    Rules* rules_;
    EngineStats* stats_;
    TelemetryEmitter* telemetry_;
    std::vector<Packet>* output_sink_;
    std::mutex* sink_mutex_;
    
    alignas(64) SPSCQueue<Packet, 16384> input_queue_;
    std::unordered_map<FiveTuple, FlowEntry, FiveTupleHash> flows_;
    
    std::atomic<bool> running_{false};
    std::atomic<bool> input_done_{false};
    std::thread thread_;
    std::atomic<uint64_t> processed_{0};
    
    void run() {
        Packet pkt;
        while (running_) {
            if (input_queue_.pop(pkt)) {
                processPacket(pkt);
            } else {
                if (input_done_ && input_queue_.empty()) {
                    break;
                }
                std::this_thread::yield();
            }
        }
        // Drain any remaining packets after signal
        while (input_queue_.pop(pkt)) {
            processPacket(pkt);
        }
    }

    void processPacket(Packet& pkt) {
        processed_++;
        
        FlowEntry& flow = flows_[pkt.tuple];
        if (flow.packets == 0) {
            flow.tuple = pkt.tuple;
        }
        flow.packets++;
        flow.bytes += pkt.data.size();
        
        if (!flow.classified) {
            classifyAndAudit(pkt, flow);
        }
        
        if (!flow.blocked) {
            flow.blocked = rules_->isBlocked(pkt.tuple.src_ip, flow.app_type, flow.sni);
            if (flow.blocked && !flow.posture_alert_sent) {
                SecurityAlert alert;
                alert.timestamp = pkt.ts_sec;
                alert.tuple = pkt.tuple;
                alert.alert_type = "POLICY_VIOLATION";
                alert.severity = "MEDIUM";
                alert.description = "Traffic blocked by security policy rule";
                alert.sni = flow.sni;
                alert.ja3_hash = flow.tls_profile.ja3_hash;
                alert.action = "BLOCKED";
                telemetry_->emit(alert);
                flow.posture_alert_sent = true;
            }
        }
        
        stats_->recordApp(flow.app_type, flow.sni);
        
        if (flow.blocked) {
            stats_->dropped++;
        } else {
            stats_->forwarded++;
            if (output_sink_ && sink_mutex_) {
                std::lock_guard<std::mutex> lock(*sink_mutex_);
                output_sink_->push_back(std::move(pkt));
            }
        }
    }
    
    void classifyAndAudit(Packet& pkt, FlowEntry& flow) {
        if (pkt.payload_length == 0) return;
        
        const uint8_t* payload = pkt.data.data() + pkt.payload_offset;
        size_t len = pkt.payload_length;

        // 1. Audit TLS ClientHello (SNI, JA3, Posture)
        if (SNIExtractor::isTLSClientHello(payload, len)) {
            stats_->tls_handshakes++;
            auto profile = SNIExtractor::auditClientHello(payload, len);
            if (profile) {
                flow.tls_profile = *profile;
                if (!profile->sni.empty()) {
                    flow.sni = profile->sni;
                    flow.app_type = sniToAppType(profile->sni);
                } else {
                    flow.app_type = AppType::HTTPS;
                }

                stats_->recordJA3(profile->ja3_hash, flow.sni, profile->ja3_raw);

                // Cryptographic posture anomaly checks
                if (profile->is_deprecated_tls) {
                    stats_->deprecated_tls_flows++;
                    stats_->recordPostureWarning(pkt.tuple.srcIPString(), "Deprecated TLS protocol: " + tlsVersionToString(profile->client_version));
                    
                    SecurityAlert alert;
                    alert.timestamp = pkt.ts_sec;
                    alert.tuple = pkt.tuple;
                    alert.alert_type = "DEPRECATED_TLS";
                    alert.severity = "HIGH";
                    alert.description = "Connection offered deprecated TLS version (" + tlsVersionToString(profile->client_version) + ")";
                    alert.sni = flow.sni;
                    alert.ja3_hash = profile->ja3_hash;
                    alert.action = "FORWARDED";
                    telemetry_->emit(alert);
                }

                if (profile->has_weak_ciphers) {
                    stats_->weak_cipher_flows++;
                    stats_->recordPostureWarning(pkt.tuple.srcIPString(), "Offered weak cipher suites (RC4/3DES/EXPORT)");

                    SecurityAlert alert;
                    alert.timestamp = pkt.ts_sec;
                    alert.tuple = pkt.tuple;
                    alert.alert_type = "WEAK_CIPHERS";
                    alert.severity = "MEDIUM";
                    alert.description = "Connection offered insecure legacy ciphers (RC4/3DES/EXPORT)";
                    alert.sni = flow.sni;
                    alert.ja3_hash = profile->ja3_hash;
                    alert.action = "FORWARDED";
                    telemetry_->emit(alert);
                }

                flow.classified = true;
                return;
            }
        }

        // 2. Audit TLS ServerHello (Negotiated Version and Cipher)
        if (SNIExtractor::isTLSServerHello(payload, len)) {
            SNIExtractor::auditServerHello(payload, len, flow.tls_profile);
            if (flow.tls_profile.has_weak_ciphers) {
                stats_->weak_cipher_flows++;
                stats_->recordPostureWarning(pkt.tuple.srcIPString(), "Server negotiated weak cipher: " + cipherSuiteToString(flow.tls_profile.negotiated_cipher));
            }
            return;
        }

        // 3. Passive Service Banner & Exposure Detection
        auto banner = BannerExtractor::inspect(payload, len, pkt.tuple.src_port, pkt.tuple.dst_port);
        if (banner) {
            stats_->service_banners_detected++;
            flow.banner_info = *banner;
            if (banner->service == "SSH") flow.app_type = AppType::SSH;
            else if (banner->service == "HTTP") flow.app_type = AppType::HTTP;
            else if (banner->service == "FTP") flow.app_type = AppType::FTP;
            else if (banner->service == "SMTP") flow.app_type = AppType::SMTP;

            stats_->recordBanner(*banner);

            if (banner->is_vulnerable) {
                stats_->vulnerable_services_flagged++;
                stats_->recordPostureWarning(pkt.tuple.srcIPString(), "Vulnerable service exposure: " + banner->service + " - " + banner->cve_hint);

                SecurityAlert alert;
                alert.timestamp = pkt.ts_sec;
                alert.tuple = pkt.tuple;
                alert.alert_type = "EXPOSED_VULNERABLE_SERVICE";
                alert.severity = "CRITICAL";
                alert.description = banner->cve_hint;
                alert.service_banner = banner->banner_raw;
                alert.action = "FORWARDED";
                telemetry_->emit(alert);
            }

            flow.classified = true;
            return;
        }
        
        // 4. HTTP Host Header
        if (HTTPHostExtractor::isHTTPRequest(payload, len)) {
            auto host = HTTPHostExtractor::extract(payload, len);
            if (host) {
                flow.sni = *host;
                flow.app_type = AppType::HTTP;
                flow.classified = true;
                return;
            }
        }
        
        // 5. DNS Query
        if (pkt.tuple.protocol == 17 && (pkt.tuple.dst_port == 53 || pkt.tuple.src_port == 53)) {
            auto query = DNSExtractor::extractQuery(payload, len);
            if (query) {
                flow.sni = *query;
                flow.app_type = AppType::DNS;
                flow.classified = true;
                return;
            }
        }
        
        // Default classification by port
        if (pkt.tuple.dst_port == 80 || pkt.tuple.src_port == 80) flow.app_type = AppType::HTTP;
        else if (pkt.tuple.dst_port == 443 || pkt.tuple.src_port == 443) flow.app_type = AppType::HTTPS;
        else if (pkt.tuple.dst_port == 53 || pkt.tuple.src_port == 53) flow.app_type = AppType::DNS;
        else if (pkt.tuple.dst_port == 22 || pkt.tuple.src_port == 22) flow.app_type = AppType::SSH;
    }
};

// =============================================================================
// Load Balancer (Distributes Packets to FP Workers using 5-Tuple Hashing)
// =============================================================================
class LoadBalancer {
public:
    LoadBalancer(int id, int fps_per_lb, std::vector<std::unique_ptr<FastPath>>& fps)
        : id_(id), fps_per_lb_(fps_per_lb), fps_(fps) {}
    
    void start() {
        running_ = true;
        thread_ = std::thread(&LoadBalancer::run, this);
    }
    
    void stop() {
        running_ = false;
        if (thread_.joinable()) thread_.join();
    }
    
    SPSCQueue<Packet, 16384>& queue() { return input_queue_; }
    void markInputDone() { input_done_ = true; }
    
    uint64_t dispatched() const { return dispatched_; }

private:
    int id_;
    int fps_per_lb_;
    std::vector<std::unique_ptr<FastPath>>& fps_;
    
    alignas(64) SPSCQueue<Packet, 16384> input_queue_;
    std::atomic<bool> running_{false};
    std::atomic<bool> input_done_{false};
    std::thread thread_;
    std::atomic<uint64_t> dispatched_{0};
    
    void run() {
        FiveTupleHash hasher;
        Packet pkt;
        while (running_) {
            if (input_queue_.pop(pkt)) {
                dispatchPacket(pkt, hasher);
            } else {
                if (input_done_ && input_queue_.empty()) {
                    break;
                }
                std::this_thread::yield();
            }
        }
        while (input_queue_.pop(pkt)) {
            dispatchPacket(pkt, hasher);
        }
        // Signal child FPs
        for (int i = 0; i < fps_per_lb_; i++) {
            fps_[id_ * fps_per_lb_ + i]->markInputDone();
        }
    }

    void dispatchPacket(Packet& pkt, const FiveTupleHash& hasher) {
        dispatched_++;
        size_t fp_idx = id_ * fps_per_lb_ + (hasher(pkt.tuple) % fps_per_lb_);
        while (!fps_[fp_idx]->queue().push(std::move(pkt))) {
            std::this_thread::yield();
        }
    }
};

// =============================================================================
// Engine Configuration
// =============================================================================
struct EngineConfig {
    int num_lbs = 2;
    int fps_per_lb = 2;
    std::string alerts_file = "alerts.jsonl";
};

// =============================================================================
// DPI Engine Coordinator
// =============================================================================
class DPIEngine {
public:
    using Config = EngineConfig;

    DPIEngine(Config cfg = Config())
        : cfg_(cfg), telemetry_(cfg_.alerts_file) {
        
        int total_fps = cfg_.num_lbs * cfg_.fps_per_lb;
        for (int i = 0; i < total_fps; i++) {
            fps_.push_back(std::make_unique<FastPath>(
                i, &rules_, &stats_, &telemetry_, &output_sink_, &sink_mutex_));
        }
        
        for (int i = 0; i < cfg_.num_lbs; i++) {
            lbs_.push_back(std::make_unique<LoadBalancer>(i, cfg_.fps_per_lb, fps_));
        }
    }
    
    void blockIP(const std::string& ip) { rules_.blockIP(ip); }
    void blockApp(const std::string& app) { rules_.blockApp(app); }
    void blockDomain(const std::string& dom) { rules_.blockDomain(dom); }
    
    bool process(const std::string& input_source, const std::string& output_pcap, bool is_live = false, uint32_t packet_limit = 0) {
        PcapReader reader;
        if (is_live) {
            if (!reader.openLive(input_source)) {
                std::cerr << "Failed to open live interface: " << input_source << "\n";
                return false;
            }
        } else {
            if (!reader.open(input_source)) {
                std::cerr << "Failed to open PCAP file: " << input_source << "\n";
                return false;
            }
        }
        
        std::ofstream output(output_pcap, std::ios::binary);
        if (!output.is_open()) {
            std::cerr << "Failed to open output PCAP file: " << output_pcap << "\n";
            return false;
        }

        // Write global PCAP header
        auto gh = reader.getGlobalHeader();
        output.write(reinterpret_cast<const char*>(&gh), sizeof(gh));

        std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║       AegisFlow DPI & Cryptographic Posture Engine           ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Mode: " << (is_live ? "LIVE NETWORK CAPTURE (Daemon Mode)  " : "OFFLINE PCAP TRACE ANALYSIS   ") << "    ║\n";
        std::cout << "║ Load Balancers: " << std::setw(2) << cfg_.num_lbs 
                  << "  │ FP Workers/LB: " << std::setw(2) << cfg_.fps_per_lb
                  << "  │ Total FPs: " << std::setw(2) << (cfg_.num_lbs * cfg_.fps_per_lb) << "        ║\n";
        std::cout << "║ Ring Buffer: Lock-Free SPSC (alignas 64, Power-of-2 Cap)     ║\n";
        std::cout << "║ Telemetry: Alerts stream -> " << std::setw(27) << std::left << cfg_.alerts_file << "  ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";
        
        for (auto& fp : fps_) fp->start();
        for (auto& lb : lbs_) lb->start();
        
        if (is_live) {
            std::cout << "Capturing live packets from interface: " << input_source << "\n";
            if (packet_limit > 0) {
                std::cout << "Capture limit: " << packet_limit << " packets (or Ctrl+C to terminate early)\n";
            } else {
                std::cout << "Continuous daemon mode running. Press Ctrl+C to terminate.\n";
            }
        } else {
            std::cout << "Reading packets from " << input_source << "...\n";
        }

        FiveTupleHash hasher;
        RawPacket raw;
        uint32_t pkt_id = 0;
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        while (!g_stop_signal.load()) {
            if (!reader.readNextPacket(raw)) {
                if (is_live) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                    continue;
                } else {
                    break;
                }
            }

            pkt_id++;
            stats_.total_packets++;
            stats_.total_bytes += raw.header.incl_len;
            
            ParsedPacket parsed;
            PacketParser::parse(raw, parsed);
            
            if (parsed.has_tcp) stats_.tcp_packets++;
            else if (parsed.has_udp) stats_.udp_packets++;
            
            Packet pkt;
            pkt.id = pkt_id;
            pkt.ts_sec = raw.header.ts_sec;
            pkt.ts_usec = raw.header.ts_usec;
            pkt.tuple.src_ip = parsed.src_ip_int;
            pkt.tuple.dst_ip = parsed.dest_ip_int;
            pkt.tuple.src_port = parsed.src_port;
            pkt.tuple.dst_port = parsed.dest_port;
            pkt.tuple.protocol = parsed.protocol;
            pkt.data = std::move(raw.data);
            pkt.tcp_flags = parsed.tcp_flags;
            pkt.payload_offset = parsed.payload_offset;
            pkt.payload_length = parsed.payload_length;
            
            size_t lb_idx = hasher(pkt.tuple) % cfg_.num_lbs;
            while (!lbs_[lb_idx]->queue().push(std::move(pkt))) {
                std::this_thread::yield();
            }

            if (is_live && packet_limit > 0 && pkt_id >= packet_limit) {
                std::cout << "\n[Live Capture] Reached packet count limit (" << packet_limit << ").\n";
                break;
            }
        }
        
        if (g_stop_signal.load()) {
            std::cout << "\n[Shutdown] Termination signal received. Flushing pipelines...\n";
        } else {
            std::cout << "[Reader] Completed parsing " << pkt_id << " packets.\n";
        }
        
        for (auto& lb : lbs_) lb->markInputDone();
        for (auto& lb : lbs_) lb->stop();
        for (auto& fp : fps_) fp->stop();
        
        auto end_time = std::chrono::high_resolution_clock::now();
        double total_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();
        double pps = (pkt_id > 0 && total_ms > 0) ? (pkt_id / (total_ms / 1000.0)) : 0;
        
        // Write forwarded packets to output PCAP
        std::cout << "Writing forwarded traffic to " << output_pcap << "...\n";
        for (const auto& pkt : output_sink_) {
            PcapPacketHeader ph;
            ph.ts_sec = pkt.ts_sec;
            ph.ts_usec = pkt.ts_usec;
            ph.incl_len = static_cast<uint32_t>(pkt.data.size());
            ph.orig_len = static_cast<uint32_t>(pkt.data.size());
            output.write(reinterpret_cast<const char*>(&ph), sizeof(ph));
            output.write(reinterpret_cast<const char*>(pkt.data.data()), pkt.data.size());
        }
        output.close();
        reader.close();
        
        telemetry_.close();
        printReport(pps);
        return true;
    }

private:
    Config cfg_;
    Rules rules_;
    EngineStats stats_;
    TelemetryEmitter telemetry_;
    std::vector<std::unique_ptr<FastPath>> fps_;
    std::vector<std::unique_ptr<LoadBalancer>> lbs_;
    
    std::vector<Packet> output_sink_;
    std::mutex sink_mutex_;
    
    void printReport(double pps) {
        std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                 SYSTEM PERFORMANCE REPORT                    ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Total Packets Processed:      " << std::setw(12) << stats_.total_packets.load() << "                 ║\n";
        std::cout << "║ Total Data Volume:            " << std::setw(12) << stats_.total_bytes.load() << " bytes           ║\n";
        std::cout << "║ Processing Throughput:        " << std::setw(12) << static_cast<uint64_t>(pps) << " pkts/sec         ║\n";
        std::cout << "║ Forwarded Packets:            " << std::setw(12) << stats_.forwarded.load() << "                 ║\n";
        std::cout << "║ Dropped / Blocked:            " << std::setw(12) << stats_.dropped.load() << "                 ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║                  THREAD WORKLOAD METRICS                     ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        for (size_t i = 0; i < lbs_.size(); i++) {
            std::cout << "║   LB" << i << " Dispatched:             " 
                      << std::setw(12) << lbs_[i]->dispatched() << "                 ║\n";
        }
        for (size_t i = 0; i < fps_.size(); i++) {
            std::cout << "║   FP" << i << " Processed:              " 
                      << std::setw(12) << fps_[i]->processed() << "                 ║\n";
        }
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║               APPLICATION & PROTOCOL BREAKDOWN               ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        
        {
            std::lock_guard<std::mutex> lock(stats_.data_mutex);
            std::vector<std::pair<AppType, uint64_t>> sorted_apps(
                stats_.app_counts.begin(), stats_.app_counts.end());
            std::sort(sorted_apps.begin(), sorted_apps.end(),
                      [](const auto& a, const auto& b) { return a.second > b.second; });
            
            uint64_t total = stats_.total_packets.load();
            for (const auto& [app, count] : sorted_apps) {
                double pct = total > 0 ? (100.0 * count / total) : 0;
                int bar_len = static_cast<int>(pct / 5);
                std::string bar(bar_len, '#');
                
                std::cout << "║ " << std::setw(14) << std::left << appTypeToString(app)
                          << std::setw(8) << std::right << count
                          << " " << std::setw(5) << std::fixed << std::setprecision(1) << pct << "% "
                          << std::setw(21) << std::left << bar << " ║\n";
            }
        }
        
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║          CRYPTOGRAPHIC POSTURE & SECURITY AUDIT              ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ TLS Handshakes Audited:       " << std::setw(12) << stats_.tls_handshakes.load() << "                 ║\n";
        std::cout << "║ Deprecated TLS (SSLv3/1.0/1.1):" << std::setw(11) << stats_.deprecated_tls_flows.load() << "                 ║\n";
        std::cout << "║ Insecure Legacy Ciphers:      " << std::setw(12) << stats_.weak_cipher_flows.load() << "                 ║\n";
        std::cout << "║ Service Banners Extracted:    " << std::setw(12) << stats_.service_banners_detected.load() << "                 ║\n";
        std::cout << "║ Vulnerable Services Flagged:  " << std::setw(12) << stats_.vulnerable_services_flagged.load() << "                 ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
        
        // Show JA3 Client Fingerprints
        {
            std::lock_guard<std::mutex> lock(stats_.data_mutex);
            if (!stats_.ja3_fingerprints.empty()) {
                std::cout << "\n[Observed TLS JA3 Fingerprints]\n";
                for (const auto& [hash, pair] : stats_.ja3_fingerprints) {
                    std::cout << "  • MD5: " << hash 
                              << " (" << (pair.first.empty() ? "No SNI" : pair.first) << ")\n";
                }
            }
            
            // Show Security Posture Warnings
            if (!stats_.posture_warnings.empty()) {
                std::cout << "\n[Cryptographic Posture & Vulnerability Warnings]\n";
                for (const auto& [host, warning] : stats_.posture_warnings) {
                    std::cout << "  [!] Host " << host << ": " << warning << "\n";
                }
            }

            // Show Detected Service Banners
            if (!stats_.exposed_banners.empty()) {
                std::cout << "\n[Discovered Service Banners]\n";
                for (const auto& b : stats_.exposed_banners) {
                    std::cout << "  • [" << b.service << ":" << b.port << "] " << b.banner_raw;
                    if (b.is_vulnerable) {
                        std::cout << " --> ALERT: " << b.cve_hint;
                    }
                    std::cout << "\n";
                }
            }
        }
        
        std::cout << "\n[Telemetry] Security alerts exported to: " << cfg_.alerts_file << "\n";
    }
};

// =============================================================================
// CLI Entry Point
// =============================================================================
void printUsage(const char* prog) {
    std::cout << R"(
AegisFlow v3.0 - High-Speed DPI & Cryptographic Posture Engine
Author: Shrest Kumar
==============================================================

Usage: 
  Offline PCAP Analysis:
    )" << prog << R"( <input.pcap> <output.pcap> [options]

  Live Interface Sniffing (Daemon Mode):
    )" << prog << R"( --live <interface> <output.pcap> [options]

  List Available Network Interfaces:
    )" << prog << R"( --list-interfaces

Core Options:
  --live <interface>     Live packet sniffing on specified interface
  --list-interfaces      List discovered capture interfaces and exit
  --count <n>            Maximum packets to capture (default: 0 = unlimited)
  --block-ip <ip>        Block source IP (e.g., 192.168.1.50)
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain substring match
  --lbs <n>              Number of load balancer threads (default: 2)
  --fps <n>              FP worker threads per LB (default: 2)
  --alerts <path>        Path to export JSONL alerts (default: alerts.jsonl)

Examples:
  )" << prog << R"( capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
  )" << prog << R"( --live eth0 live_audit.pcap --count 1000
)";
}

int main(int argc, char* argv[]) {
    // Check for --list-interfaces flag
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "--list-interfaces") {
            std::cout << "\n[AegisFlow] Discovering local network interfaces for live capture...\n";
            auto ifaces = PcapReader::listInterfaces();
            if (ifaces.empty()) {
                std::cout << "  No interfaces available or missing capture permissions.\n"
                          << "  (Ensure Npcap is installed on Windows or run as Administrator/root)\n\n";
            } else {
                for (size_t idx = 0; idx < ifaces.size(); idx++) {
                    std::cout << "  [" << idx << "] " << ifaces[idx].name;
                    if (!ifaces[idx].description.empty()) {
                        std::cout << " - " << ifaces[idx].description;
                    }
                    if (ifaces[idx].is_loopback) {
                        std::cout << " [Loopback]";
                    }
                    std::cout << "\n";
                }
                std::cout << "\n";
            }
            return 0;
        }
    }

    if (argc < 3) {
        printUsage(argv[0]);
        return 1;
    }

    // Register clean signal handling
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    std::string input;
    std::string output;
    bool is_live = false;
    uint32_t packet_limit = 0;

    int arg_idx = 1;
    if (std::string(argv[1]) == "--live") {
        if (argc < 4) {
            printUsage(argv[0]);
            return 1;
        }
        is_live = true;
        input = argv[2];
        output = argv[3];
        arg_idx = 4;
    } else {
        input = argv[1];
        output = argv[2];
        arg_idx = 3;
    }

    DPIEngine::Config cfg;
    std::vector<std::string> block_ips, block_apps, block_domains;

    for (int i = arg_idx; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--block-ip" && i + 1 < argc) block_ips.push_back(argv[++i]);
        else if (arg == "--block-app" && i + 1 < argc) block_apps.push_back(argv[++i]);
        else if (arg == "--block-domain" && i + 1 < argc) block_domains.push_back(argv[++i]);
        else if (arg == "--lbs" && i + 1 < argc) cfg.num_lbs = std::stoi(argv[++i]);
        else if (arg == "--fps" && i + 1 < argc) cfg.fps_per_lb = std::stoi(argv[++i]);
        else if (arg == "--alerts" && i + 1 < argc) cfg.alerts_file = argv[++i];
        else if (arg == "--count" && i + 1 < argc) packet_limit = static_cast<uint32_t>(std::stoul(argv[++i]));
    }

    DPIEngine engine(cfg);
    for (const auto& ip : block_ips) engine.blockIP(ip);
    for (const auto& app : block_apps) engine.blockApp(app);
    for (const auto& dom : block_domains) engine.blockDomain(dom);

    if (!engine.process(input, output, is_live, packet_limit)) {
        return 1;
    }

    std::cout << "\nProcessing completed successfully.\n";
    return 0;
}
