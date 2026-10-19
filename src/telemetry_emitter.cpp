#include "telemetry_emitter.h"
#include <iostream>

namespace DPI {

TelemetryEmitter::TelemetryEmitter(const std::string& alerts_path)
    : alerts_path_(alerts_path) {
    if (!alerts_path_.empty()) {
        out_file_.open(alerts_path_, std::ios::out | std::ios::app);
    }
}

TelemetryEmitter::~TelemetryEmitter() {
    close();
}

void TelemetryEmitter::close() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (out_file_.is_open()) {
        out_file_.flush();
        out_file_.close();
    }
}

void TelemetryEmitter::emit(const SecurityAlert& alert) {
    std::lock_guard<std::mutex> lock(mutex_);
    total_emitted_++;
    alert_history_.push_back(alert);
    if (alert_history_.size() > 500) {
        alert_history_.erase(alert_history_.begin());
    }

    if (out_file_.is_open()) {
        out_file_ << alert.toJSON() << "\n";
        out_file_.flush();
    }
}

std::vector<SecurityAlert> TelemetryEmitter::getRecentAlerts(size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (alert_history_.size() <= limit) {
        return alert_history_;
    }
    return std::vector<SecurityAlert>(alert_history_.end() - limit, alert_history_.end());
}

size_t TelemetryEmitter::getTotalAlertsCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return total_emitted_;
}

} // namespace DPI
