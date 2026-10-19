#ifndef DPI_MD5_H
#define DPI_MD5_H

#include <string>
#include <cstdint>
#include <array>

namespace DPI {

// ============================================================================
// Portable MD5 Implementation (RFC 1321)
// Used for JA3 / JA4 cryptographic fingerprint hashing without external deps
// ============================================================================
class MD5 {
public:
    MD5();
    void update(const uint8_t* data, size_t length);
    void update(const std::string& str);
    std::string finalize();

    static std::string hash(const std::string& input);

private:
    void transform(const uint8_t block[64]);

    std::array<uint32_t, 4> state_;
    std::array<uint64_t, 1> count_;
    std::array<uint8_t, 64> buffer_;
    bool finalized_{false};
};

} // namespace DPI

#endif // DPI_MD5_H
