#include "../src/main/cpp/broker.hpp"
#include <cassert>
#include <string>
int main() {
  HardwareBroker broker;
  uint8_t secret[32]; memset(secret, 7, sizeof secret);
  const auto json = reinterpret_cast<const uint8_t *>("{}");
  auto id = broker.reserve();
  assert(id && !broker.reserve());
  assert(broker.event(id, json, 2));
  uint32_t length = 0;
  auto frame = broker.poll(id, &length);
  assert(frame && frame[0] == 2 && frame[8] == 0);
  kp_wipe(frame, length); free(frame);
  broker.cancel(id);
  assert(!broker.pending(id) && !broker.reserve());
  assert(!broker.poll(id, &length)); // No reuse while Java/device work is running.
  memset(secret, 7, sizeof secret);
  broker.finish(id, json, 2, secret, 32, false);
  for (auto value : secret) assert(value == 0);
  assert(!broker.reserve());
  frame = broker.poll(id, &length);
  assert(frame && frame[0] == 1 && frame[8] == 0);
  assert(std::string(reinterpret_cast<char *>(frame + 12), length - 12) == "{\"error\":\"cancelled\"}");
  kp_wipe(frame, length); free(frame);
  id = broker.reserve();
  assert(id);
  memset(secret, 7, sizeof secret);
  broker.finish(id, json, 2, secret, 32, false);
  for (auto value : secret) assert(value == 0);
  broker.cancel(id); // Cancellation after completion must erase queued output.
  frame = broker.poll(id, &length);
  assert(frame && frame[0] == 1 && frame[8] == 0);
  kp_wipe(frame, length); free(frame);
  id = broker.reserve();
  memset(secret, 7, sizeof secret);
  broker.finish(id, json, 2, secret, 31, false);
  for (size_t i = 0; i < 31; ++i) assert(secret[i] == 0);
  frame = broker.poll(id, &length);
  assert(frame && frame[0] == 1 && frame[8] == 0);
  kp_wipe(frame, length); free(frame);
  id = broker.reserve();
  memset(secret, 7, sizeof secret);
  broker.finish(id, json, 2, secret, 32, false);
  for (auto value : secret) assert(value == 0);
  frame = broker.poll(id, &length);
  assert(frame && frame[0] == 0 && frame[8] == 32 && frame[14] == 7);
  memset(secret, 0, sizeof secret);
  assert(frame[14] == 7); // Independent result allocation.
  kp_wipe(frame, length); free(frame);
}
