#ifndef DPI_SPSC_QUEUE_H
#define DPI_SPSC_QUEUE_H

#include <atomic>
#include <vector>
#include <optional>
#include <cstddef>
#include <new>

namespace DPI {

// ============================================================================
// Lock-Free Single-Producer Single-Consumer (SPSC) Ring Buffer
// 
// Optimized for zero-contention inter-thread communication:
// - alignas(64) on indices prevents CPU cache-line bouncing (false sharing)
// - Capacity enforced as power of 2 enables fast bitwise masking instead of modulo
// - Explicit memory orders (acquire/release) guarantee sequential consistency
// ============================================================================
template <typename T, size_t Capacity = 65536>
class SPSCQueue {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be a power of 2");

private:
    // Prevent false sharing across CPU cores by aligning atomic pointers to L1/L2 cache lines (64 bytes)
    alignas(64) std::atomic<size_t> head_{0}; // Consumer reads & updates head
    alignas(64) std::atomic<size_t> tail_{0}; // Producer writes & updates tail
    std::vector<T> buffer_;

public:
    SPSCQueue() : buffer_(Capacity) {}

    // Pushes item into queue. Returns true if successful, false if full.
    bool push(T&& item) noexcept {
        const size_t current_tail = tail_.load(std::memory_order_relaxed);
        const size_t next_tail = (current_tail + 1) & (Capacity - 1);
        
        // Check if queue is full against consumer's head
        if (next_tail == head_.load(std::memory_order_acquire)) {
            return false; // Queue full
        }

        buffer_[current_tail] = std::move(item);
        tail_.store(next_tail, std::memory_order_release);
        return true;
    }

    bool push(const T& item) noexcept {
        T copy = item;
        return push(std::move(copy));
    }

    // Pops item from queue. Returns true if successful, false if empty.
    bool pop(T& item) noexcept {
        const size_t current_head = head_.load(std::memory_order_relaxed);
        
        // Check if queue is empty against producer's tail
        if (current_head == tail_.load(std::memory_order_acquire)) {
            return false; // Queue empty
        }

        item = std::move(buffer_[current_head]);
        head_.store((current_head + 1) & (Capacity - 1), std::memory_order_release);
        return true;
    }

    std::optional<T> pop() noexcept {
        T item;
        if (pop(item)) {
            return item;
        }
        return std::nullopt;
    }

    [[nodiscard]] bool empty() const noexcept {
        return head_.load(std::memory_order_relaxed) == tail_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] size_t size() const noexcept {
        size_t head = head_.load(std::memory_order_relaxed);
        size_t tail = tail_.load(std::memory_order_relaxed);
        if (tail >= head) {
            return tail - head;
        }
        return Capacity - (head - tail);
    }

    [[nodiscard]] constexpr size_t capacity() const noexcept {
        return Capacity;
    }
};

} // namespace DPI

#endif // DPI_SPSC_QUEUE_H
