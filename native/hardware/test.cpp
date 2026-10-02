#include "json.hpp"
#include "keypass_hardware.h"
#include <cassert>
#include <chrono>
#include <cstring>
#include <string>
#include <thread>
using Json = nlohmann::json;
Json result(uint64_t id) {
  for (int i = 0; i < 300; ++i) {
    uint32_t size = 0;
    auto p = keypass_hardware_poll(id, &size);
    if (p) {
      assert(size >= 12);
      uint32_t count = 0;
      for (int j = 0; j < 4; ++j)
        count |= uint32_t(p[4 + j]) << (8 * j);
      assert(size == 12 + count && p[0] == 1 && p[8] == 0);
      auto json = Json::parse(p + 12, p + size);
      keypass_hardware_free(p, size);
      return json;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  assert(false && "worker did not settle");
  return {};
}
uint64_t start(const std::string &s) {
  return keypass_hardware_start(reinterpret_cast<const uint8_t *>(s.data()),
                                s.size());
}
int main() {
  assert(keypass_hardware_abi_version() == 1);
  assert(keypass_hardware_start(nullptr, 0) == 0);
  const std::string s = "{\"operation\":\"invalid\"}";
  auto id = start(s);
  assert(id);
  // No new operation can steal an unconsumed result, even if worker completed.
  assert(start(s) == 0);
  auto answer = result(id);
  assert(answer["error"] == "invalidRequest");
  assert(keypass_hardware_pin(id, reinterpret_cast<const uint8_t *>("1234"),
                              4) == 0);
  // Deep/malformed input rejected without entering a credential ceremony.
  for (auto input :
       {std::string("{"), std::string("{\"operation\":\"register\"}"),
        std::string(20, '[') + std::string(20, ']')}) {
    id = start(input);
    assert(id);
    answer = result(id);
    assert(answer["error"] == "invalidRequest");
  }
  id = start(s);
  assert(id);
  keypass_hardware_cancel(id);
  answer = result(id);
  assert(answer["error"] == "cancelled" || answer["error"] == "invalidRequest");
  id = start(s);
  assert(id);
  assert(result(id)["error"] == "invalidRequest");
}
