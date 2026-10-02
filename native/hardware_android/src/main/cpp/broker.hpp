#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <vector>

inline void kp_wipe(void *data, size_t length) {
  auto p = static_cast<volatile uint8_t *>(data);
  while (length--) *p++ = 0;
}
struct HardwareFrame {
  std::vector<uint8_t> bytes;
  bool terminal;
  HardwareFrame(uint32_t status, const uint8_t *json, size_t n,
                const uint8_t *secret = nullptr, size_t s = 0)
      : bytes(12 + n + s), terminal(status != 2) {
    uint32_t words[] = {status, static_cast<uint32_t>(n), static_cast<uint32_t>(s)};
    for (size_t i = 0; i < 3; ++i)
      for (size_t j = 0; j < 4; ++j) bytes[4*i+j] = static_cast<uint8_t>(words[i] >> (8*j));
    if (n) memcpy(bytes.data()+12, json, n);
    if (s) memcpy(bytes.data()+12+n, secret, s);
  }
  ~HardwareFrame() { kp_wipe(bytes.data(), bytes.size()); }
};
class HardwareBroker {
  std::mutex mutex;
  uint64_t sequence = 0, active = 0;
  bool done = false, cancelled = false;
  std::deque<std::unique_ptr<HardwareFrame>> frames;
  static std::unique_ptr<HardwareFrame> error(const char *json) {
    return std::make_unique<HardwareFrame>(1, reinterpret_cast<const uint8_t *>(json), strlen(json));
  }
public:
  uint64_t reserve() {
    std::lock_guard<std::mutex> guard(mutex);
    if (active || sequence == UINT64_MAX) return 0;
    active = ++sequence; done = cancelled = false; return active;
  }
  bool pending(uint64_t id) {
    std::lock_guard<std::mutex> guard(mutex);
    return id && id == active && !done && !cancelled;
  }
  bool event(uint64_t id, const uint8_t *json, size_t size) {
    std::lock_guard<std::mutex> guard(mutex);
    if (!id || active != id || done || cancelled || !json || size > 65536 || frames.size() >= 4) return false;
    frames.push_back(std::make_unique<HardwareFrame>(2, json, size)); return true;
  }
  void finish(uint64_t id, const uint8_t *json, size_t size,
              uint8_t *secret, size_t secretSize, bool failed) {
    std::lock_guard<std::mutex> guard(mutex);
    // JNI passes its exclusively owned stack copy. Wipe it before the terminal
    // frame becomes visible to poll(), including cancellation/rejected results.
    struct ClearSecret {
      uint8_t *data; size_t size;
      ~ClearSecret() { if (data) kp_wipe(data, size); }
    } clear{secret, secretSize};
    if (!id || active != id || done) return;
    frames.clear();
    if (cancelled) frames.push_back(error("{\"error\":\"cancelled\"}"));
    else if (!json || size > 65536 || (secretSize && (!secret || secretSize != 32 || failed)))
      frames.push_back(error("{\"error\":\"backendFailure\"}"));
    else frames.push_back(std::make_unique<HardwareFrame>(failed ? 1 : 0, json, size, secret, secretSize));
    done = true;
  }
  void fail(uint64_t id, const char *json) {
    finish(id, reinterpret_cast<const uint8_t *>(json), strlen(json), nullptr, 0, true);
  }
  bool cancel(uint64_t id) {
    std::lock_guard<std::mutex> guard(mutex);
    if (!id || active != id) return false;
    cancelled = true;
    frames.clear();
    // Only a completed worker permits a terminal frame and slot reuse.
    if (done) frames.push_back(error("{\"error\":\"cancelled\"}"));
    return true;
  }
  uint8_t *poll(uint64_t id, uint32_t *size) {
    std::lock_guard<std::mutex> guard(mutex);
    if (!size) return nullptr;
    *size = 0;
    if (!id || active != id || frames.empty()) return nullptr;
    const auto &frame = frames.front();
    auto output = static_cast<uint8_t *>(malloc(frame->bytes.size()));
    if (!output) return nullptr;
    memcpy(output, frame->bytes.data(), frame->bytes.size());
    *size = static_cast<uint32_t>(frame->bytes.size());
    bool terminal = frame->terminal;
    frames.pop_front();
    if (terminal) { active = 0; done = cancelled = false; }
    return output;
  }
};
