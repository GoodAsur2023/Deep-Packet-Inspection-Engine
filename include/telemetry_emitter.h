#ifndef DPI_TELEMETRY_EMITTER_H
#define DPI_TELEMETRY_EMITTER_H

#include <string>
#include <vector>
#include <mutex>
#include <fstream>
#include "types.h"

namespace DPI {

// ============================================================================
// Security Telemetry Emitter
//
// Streams structured JSONLines security telemetry to disk / IPC channel:
// - Cryptographic posture anomalies (weak ciphers, deprecated TLS)
// - Passive service exposure events and banner CVE correlations
// - Policy enforcement drops
// ============================================================================
class TelemetryEmitter {
public:
    explicit TelemetryEmitter(const std::string& alerts_path = "");
    ~TelemetryEmitter();

    void emit(const SecurityAlert& alert);
    void close();

    std::vector<SecurityAlert> getRecentAlerts(size_t limit = 50) const;
    size_t getTotalAlertsCount() const;

private:
    std::string alerts_path_;
    std::ofstream out_file_;
    mutable std::mutex mutex_;
    std::vector<SecurityAlert> alert_history_;
    size_t total_emitted_{0};
};

} // namespace DPI

#endif // DPI_TELEMETRY_EMITTER_H
