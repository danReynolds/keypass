#include "keypass_hardware.h"
#include "json.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <fido.h>
#include <memory>
#include <mutex>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using Json = nlohmann::json;
using Bytes = std::vector<uint8_t>;
using Clock = std::chrono::steady_clock;
namespace {
struct Error {
  const char *code;
};
void wipe(Bytes &b) {
  if (!b.empty())
    OPENSSL_cleanse(b.data(), b.size());
  b.clear();
}
struct Secret {
  Bytes bytes;
  ~Secret() { wipe(bytes); }
};
struct Operation {
  uint64_t id;
  std::atomic<bool> cancelled{false};
  bool running = true, wantsPin = false, pinReady = false;
  fido_dev_t *device = nullptr; // protected against close/free by mutex
  Secret pin, result;
  std::deque<Bytes> events;
  Clock::time_point deadline = Clock::now() + std::chrono::seconds(120);
  explicit Operation(uint64_t value) : id(value) {}
};
std::mutex mutex;
std::condition_variable wake;
std::shared_ptr<Operation> active;
uint64_t sequence = 0;
void quiet(const char *) {}
void check(int result) {
  switch (result) {
  case FIDO_OK:
    return;
  case FIDO_ERR_PIN_INVALID:
    throw Error{"pinInvalid"};
  case FIDO_ERR_PIN_BLOCKED:
    throw Error{"pinBlocked"};
  case FIDO_ERR_PIN_AUTH_BLOCKED:
    throw Error{"pinTemporarilyBlocked"};
  case FIDO_ERR_PIN_NOT_SET:
  case FIDO_ERR_PIN_REQUIRED:
    throw Error{"pinRequired"};
  case FIDO_ERR_UV_BLOCKED:
  case FIDO_ERR_UV_INVALID:
    throw Error{"verificationUnavailable"};
  case FIDO_ERR_KEEPALIVE_CANCEL:
  case FIDO_ERR_OPERATION_DENIED:
    throw Error{"cancelled"};
  case FIDO_ERR_TIMEOUT:
  case FIDO_ERR_USER_ACTION_TIMEOUT:
  case FIDO_ERR_ACTION_TIMEOUT:
    throw Error{"timeout"};
  case FIDO_ERR_KEY_STORE_FULL:
    throw Error{"credentialStorageFull"};
  case FIDO_ERR_NO_CREDENTIALS:
  case FIDO_ERR_INVALID_CREDENTIAL:
    throw Error{"credentialUnavailable"};
  case FIDO_ERR_CHANNEL_BUSY:
    throw Error{"busy"};
  case FIDO_ERR_UNSUPPORTED_EXTENSION:
    throw Error{"prfUnavailable"};
  case FIDO_ERR_TX:
  case FIDO_ERR_RX:
    throw Error{"deviceUnavailable"};
  default:
    throw Error{"backendFailure"};
  }
}
std::string text(const Json &j, const char *field, size_t maximum) {
  auto s = j.at(field).get<std::string>();
  if (s.empty() || s.size() > maximum || s.find('\0') != std::string::npos)
    throw Error{"invalidRequest"};
  return s;
}
std::string encode(const uint8_t *data, size_t size) {
  if (!data || !size || size > 16384)
    throw Error{"verificationFailed"};
  std::string out(4 * ((size + 2) / 3), '\0');
  EVP_EncodeBlock(reinterpret_cast<uint8_t *>(out.data()), data,
                  static_cast<int>(size));
  std::replace(out.begin(), out.end(), '+', '-');
  std::replace(out.begin(), out.end(), '/', '_');
  while (!out.empty() && out.back() == '=')
    out.pop_back();
  return out;
}
Bytes decode(const Json &j, const char *field, size_t maximum) {
  auto s = text(j, field, 4 * ((maximum + 2) / 3));
  if (s.find_first_not_of(
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") !=
      std::string::npos)
    throw Error{"invalidRequest"};
  auto padded = s;
  std::replace(padded.begin(), padded.end(), '-', '+');
  std::replace(padded.begin(), padded.end(), '_', '/');
  while (padded.size() % 4)
    padded.push_back('=');
  Bytes out(padded.size() / 4 * 3);
  int n = EVP_DecodeBlock(out.data(),
                          reinterpret_cast<const uint8_t *>(padded.data()),
                          static_cast<int>(padded.size()));
  if (n < 0)
    throw Error{"invalidRequest"};
  if (padded.back() == '=')
    --n;
  if (padded[padded.size() - 2] == '=')
    --n;
  if (n < 1 || static_cast<size_t>(n) > maximum)
    throw Error{"invalidRequest"};
  out.resize(n);
  if (encode(out.data(), out.size()) != s)
    throw Error{"invalidRequest"};
  return out;
}
Bytes frame(uint32_t status, const Json &metadata,
            const uint8_t *secret = nullptr, size_t secretSize = 0) {
  auto json = metadata.dump();
  if (json.size() > 65536 || (secretSize != 0 && secretSize != 32))
    throw Error{"backendFailure"};
  Bytes b(12 + json.size() + secretSize);
  uint32_t words[] = {status, static_cast<uint32_t>(json.size()),
                      static_cast<uint32_t>(secretSize)};
  for (size_t i = 0; i < 3; ++i)
    for (size_t k = 0; k < 4; ++k)
      b[4 * i + k] = static_cast<uint8_t>(words[i] >> (8 * k));
  memcpy(b.data() + 12, json.data(), json.size());
  if (secretSize)
    memcpy(b.data() + 12 + json.size(), secret, secretSize);
  return b;
}
void ensure(const std::shared_ptr<Operation> &op) {
  if (op->cancelled)
    throw Error{"cancelled"};
  if (Clock::now() >= op->deadline)
    throw Error{"timeout"};
}
void event(const std::shared_ptr<Operation> &op, const Json &value) {
  std::lock_guard<std::mutex> lock(mutex);
  ensure(op);
  if (op->events.size() >= 4)
    throw Error{"backendFailure"};
  op->events.push_back(frame(2, value));
}
struct Device {
  fido_dev_t *ptr = fido_dev_new();
  bool opened = false;
  ~Device() {
    if (opened)
      fido_dev_close(ptr);
    fido_dev_free(&ptr);
  }
};
struct Info {
  fido_cbor_info_t *ptr = fido_cbor_info_new();
  ~Info() { fido_cbor_info_free(&ptr); }
};
struct Credential {
  fido_cred_t *ptr = fido_cred_new();
  ~Credential() { fido_cred_free(&ptr); }
};
struct Assertion {
  fido_assert_t *ptr = fido_assert_new();
  ~Assertion() { fido_assert_free(&ptr); }
};
struct Manifest {
  fido_dev_info_t *ptr = fido_dev_info_new(16);
  size_t count = 0;
  Manifest() {
    if (!ptr)
      throw Error{"backendFailure"};
    int result = fido_dev_info_manifest(ptr, 16, &count);
    if (result != FIDO_OK) {
      fido_dev_info_free(&ptr, 16);
      check(result);
    }
  }
  ~Manifest() { fido_dev_info_free(&ptr, 16); }
};
std::string token(const char *path) {
  if (!path || strlen(path) > 4096)
    throw Error{"deviceUnavailable"};
  uint8_t hash[32];
  SHA256(reinterpret_cast<const uint8_t *>(path), strlen(path), hash);
  const char *hex = "0123456789abcdef";
  std::string out;
  for (auto c : hash) {
    out.push_back(hex[c >> 4]);
    out.push_back(hex[c & 15]);
  }
  return out;
}
bool usbPath(const char *path) {
  if (!path)
    return false;
#ifdef __APPLE__
  return strncmp(path, "ioreg://", 8) == 0 ||
         strncmp(path, "IOService:", 10) == 0;
#else
  return strncmp(path, "/dev/hidraw", 11) == 0;
#endif
}
Json discover() {
  Manifest list;
  Json devices = Json::array();
  for (size_t i = 0; i < list.count; ++i) {
    auto d = fido_dev_info_ptr(list.ptr, i);
    auto path = fido_dev_info_path(d);
    if (!usbPath(path))
      continue; // desktop NFC is a separate qualification.
    auto product = fido_dev_info_product_string(d);
    std::string name = product ? product : "FIDO2 security key";
    name.resize(std::min(name.size(), size_t(128)));
    for (auto &c : name)
      if (static_cast<unsigned char>(c) < 32 ||
          static_cast<unsigned char>(c) > 126)
        c = '?';
    devices.push_back({{"id", token(path)}, {"name", name}});
  }
  return {{"devices", devices}};
}
bool extension(const Info &info, const char *wanted) {
  auto values = fido_cbor_info_extensions_ptr(info.ptr);
  for (size_t i = 0; i < fido_cbor_info_extensions_len(info.ptr); ++i)
    if (strcmp(values[i], wanted) == 0)
      return true;
  return false;
}
bool option(const Info &info, const char *wanted) {
  auto names = fido_cbor_info_options_name_ptr(info.ptr);
  auto values = fido_cbor_info_options_value_ptr(info.ptr);
  for (size_t i = 0; i < fido_cbor_info_options_len(info.ptr); ++i)
    if (strcmp(names[i], wanted) == 0)
      return values[i];
  return false;
}
void obtainPin(const std::shared_ptr<Operation> &op, Device &device) {
  // On-key UV is preferred when enrolled. No automatic PIN fallback/retry.
  if (fido_dev_has_uv(device.ptr))
    return;
  if (!fido_dev_has_pin(device.ptr))
    throw Error{"pinRequired"};
  int retries = 0;
  check(fido_dev_get_retry_count(device.ptr, &retries));
  if (retries <= 0)
    throw Error{"pinBlocked"};
  {
    std::lock_guard<std::mutex> lock(mutex);
    ensure(op);
    op->wantsPin = true;
  }
  event(op, {{"event", "pin"}, {"attemptsRemaining", retries}});
  std::unique_lock<std::mutex> lock(mutex);
  while (!op->pinReady) {
    ensure(op);
    wake.wait_for(lock, std::chrono::milliseconds(50));
  }
  op->wantsPin = false;
  ensure(op);
}
template <class Call>
int ceremony(const std::shared_ptr<Operation> &op, Device &device, Call call) {
  ensure(op);
  const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                             op->deadline - Clock::now())
                             .count();
  check(fido_dev_set_timeout(
      device.ptr, static_cast<int>(std::max<int64_t>(1, remaining))));
  event(op, {{"event", "touch"}});
  {
    std::lock_guard<std::mutex> lock(mutex);
    ensure(op);
    op->device = device.ptr;
  }
  // cancel() only sends CTAPHID_CANCEL; close/free always remain on this
  // worker.
  int result = call(op->pin.bytes.empty()
                        ? nullptr
                        : reinterpret_cast<const char *>(op->pin.bytes.data()));
  {
    std::lock_guard<std::mutex> lock(mutex);
    op->device = nullptr;
    wipe(op->pin.bytes);
  }
  ensure(op);
  return result;
}
Bytes execute(const std::shared_ptr<Operation> &op, const Json &request) {
  auto operation = text(request, "operation", 16);
  if (operation == "discover") {
    ensure(op);
    return frame(0, discover());
  }
  if (operation != "register" && operation != "evaluate")
    throw Error{"invalidRequest"};
  auto selected = text(request, "device", 64),
       rp = text(request, "namespace", 253);
  auto hash = decode(request, "clientDataHash", 32);
  if (hash.size() != 32)
    throw Error{"invalidRequest"};
  // Validate the whole operation before device I/O or requesting a PIN.
  Bytes user, credentialId, salt;
  std::string display, label;
  if (operation == "register") {
    user = decode(request, "userId", 64);
    display = text(request, "displayName", 1024);
    label = text(request, "label", 1024);
  } else {
    credentialId = decode(request, "credentialId", 1024);
    salt = decode(request, "hmacSalt", 32);
    if (salt.size() != 32)
      throw Error{"invalidRequest"};
  }
  Manifest list;
  std::string path;
  for (size_t i = 0; i < list.count; ++i) {
    auto p = fido_dev_info_path(fido_dev_info_ptr(list.ptr, i));
    if (usbPath(p) && token(p) == selected) {
      path = p;
      break;
    }
  }
  if (path.empty())
    throw Error{"deviceUnavailable"};
  Device device;
  Info info;
  if (!device.ptr || !info.ptr)
    throw Error{"backendFailure"};
  check(fido_dev_set_timeout(device.ptr, 3000));
  ensure(op);
  if (fido_dev_open(device.ptr, path.c_str()) != FIDO_OK)
    throw Error{"deviceUnavailable"};
  device.opened = true;
  if (!fido_dev_is_fido2(device.ptr))
    throw Error{"prfUnavailable"};
  check(fido_dev_get_cbor_info(device.ptr, info.ptr));
  if (!extension(info, "hmac-secret"))
    throw Error{"prfUnavailable"};
  if (fido_cbor_info_new_pin_required(info.ptr))
    throw Error{"pinChangeRequired"};
  if (!fido_dev_has_uv(device.ptr) && !fido_dev_has_pin(device.ptr))
    throw Error{"pinRequired"};
  if (operation == "register" &&
      (!option(info, "rk") || !extension(info, "credProtect")))
    throw Error{"verificationUnavailable"};
  obtainPin(op, device);
  if (operation == "register") {
    Credential value;
    if (!value.ptr)
      throw Error{"backendFailure"};
    check(fido_cred_set_type(value.ptr, COSE_ES256));
    check(fido_cred_set_clientdata_hash(value.ptr, hash.data(), hash.size()));
    check(fido_cred_set_rp(value.ptr, rp.c_str(), display.c_str()));
    check(fido_cred_set_user(value.ptr, user.data(), user.size(), label.c_str(),
                             label.c_str(), nullptr));
    check(fido_cred_set_rk(value.ptr, FIDO_OPT_TRUE));
    check(fido_cred_set_uv(value.ptr, FIDO_OPT_TRUE));
    check(fido_cred_set_extensions(value.ptr, FIDO_EXT_HMAC_SECRET |
                                                  FIDO_EXT_CRED_PROTECT));
    check(fido_cred_set_prot(value.ptr, FIDO_CRED_PROT_UV_REQUIRED));
    check(ceremony(op, device, [&](const char *pin) {
      return fido_dev_make_cred(device.ptr, value.ptr, pin);
    }));
    int verified = fido_cred_x5c_len(value.ptr)
                       ? fido_cred_verify(value.ptr)
                       : fido_cred_verify_self(value.ptr);
    if (verified != FIDO_OK ||
        fido_cred_prot(value.ptr) != FIDO_CRED_PROT_UV_REQUIRED ||
        (fido_cred_flags(value.ptr) & 5) != 5)
      throw Error{"verificationFailed"};
    Json transports = Json::array();
    auto ts = fido_cbor_info_transports_ptr(info.ptr);
    for (size_t i = 0; i < fido_cbor_info_transports_len(info.ptr); ++i)
      if (strcmp(ts[i], "usb") == 0 || strcmp(ts[i], "nfc") == 0)
        transports.push_back(ts[i]);
    return frame(0, {{"attestationVerified", true},
                     {"transports", transports},
                     {"credentialId", encode(fido_cred_id_ptr(value.ptr),
                                             fido_cred_id_len(value.ptr))},
                     {"authenticatorData",
                      encode(fido_cred_authdata_raw_ptr(value.ptr),
                             fido_cred_authdata_raw_len(value.ptr))}});
  }
  Assertion value;
  if (!value.ptr)
    throw Error{"backendFailure"};
  check(fido_assert_set_rp(value.ptr, rp.c_str()));
  check(fido_assert_set_clientdata_hash(value.ptr, hash.data(), hash.size()));
  check(fido_assert_allow_cred(value.ptr, credentialId.data(),
                               credentialId.size()));
  check(fido_assert_set_up(value.ptr, FIDO_OPT_TRUE));
  check(fido_assert_set_uv(value.ptr, FIDO_OPT_TRUE));
  check(fido_assert_set_extensions(value.ptr, FIDO_EXT_HMAC_SECRET));
  check(fido_assert_set_hmac_salt(value.ptr, salt.data(), salt.size()));
  check(ceremony(op, device, [&](const char *pin) {
    return fido_dev_get_assert(device.ptr, value.ptr, pin);
  }));
  if (fido_assert_count(value.ptr) != 1 ||
      (fido_assert_flags(value.ptr, 0) & 5) != 5)
    throw Error{"verificationFailed"};
  if (fido_assert_hmac_secret_len(value.ptr, 0) != 32)
    throw Error{"prfUnavailable"};
  Json metadata = {
      {"credentialId", encode(fido_assert_id_ptr(value.ptr, 0),
                              fido_assert_id_len(value.ptr, 0))},
      {"authenticatorData", encode(fido_assert_authdata_raw_ptr(value.ptr, 0),
                                   fido_assert_authdata_raw_len(value.ptr, 0))},
      {"signature", encode(fido_assert_sig_ptr(value.ptr, 0),
                           fido_assert_sig_len(value.ptr, 0))}};
  auto userSize = fido_assert_user_id_len(value.ptr, 0);
  metadata["userHandle"] =
      userSize ? Json(encode(fido_assert_user_id_ptr(value.ptr, 0), userSize))
               : Json(nullptr);
  return frame(0, metadata, fido_assert_hmac_secret_ptr(value.ptr, 0), 32);
}
void run(const std::shared_ptr<Operation> &op, Bytes input) {
  Bytes result;
  try {
    // libfido2 initialization/logging policy is thread local.
    fido_init(FIDO_DISABLE_U2F_FALLBACK);
    fido_set_log_handler(quiet);
    auto request = Json::parse(input.begin(), input.end(),
                               [](int depth, Json::parse_event_t, Json &) {
                                 if (depth > 12)
                                   throw Error{"invalidRequest"};
                                 return true;
                               });
    if (!request.is_object())
      throw Error{"invalidRequest"};
    result = execute(op, request);
  } catch (const Error &e) {
    result = frame(1, {{"error", e.code}});
  } catch (const Json::exception &) {
    result = frame(1, {{"error", "invalidRequest"}});
  } catch (...) {
    result = frame(1, {{"error", "backendFailure"}});
  }
  std::lock_guard<std::mutex> lock(mutex);
  op->device = nullptr;
  op->wantsPin = false;
  wipe(op->pin.bytes);
  if (op->cancelled) {
    wipe(result);
    result = frame(1, {{"error", "cancelled"}});
  }
  op->events.clear();
  op->result.bytes = std::move(result);
  op->running = false;
}
} // namespace
extern "C" {
uint32_t keypass_hardware_abi_version() { return 1; }
uint64_t keypass_hardware_start(const uint8_t *data, uint32_t size) {
  if (!data || size == 0 || size > 65536)
    return 0;
  try {
    std::lock_guard<std::mutex> lock(mutex);
    if (active)
      return 0;
    auto op = std::make_shared<Operation>(++sequence);
    active = op;
    try {
      std::thread(run, op, Bytes(data, data + size)).detach();
    } catch (...) {
      active.reset();
      throw;
    }
    return op->id;
  } catch (...) {
    return 0;
  }
}
uint8_t *keypass_hardware_poll(uint64_t id, uint32_t *size) {
  if (!size)
    return nullptr;
  std::lock_guard<std::mutex> lock(mutex);
  *size = 0;
  if (!active || active->id != id)
    return nullptr;
  auto op = active;
  Bytes b;
  if (!op->events.empty()) {
    b = std::move(op->events.front());
    op->events.pop_front();
  } else if (!op->running) {
    b = std::move(op->result.bytes);
    active.reset();
  } else
    return nullptr;
  auto out = static_cast<uint8_t *>(malloc(b.size()));
  if (out) {
    memcpy(out, b.data(), b.size());
    *size = static_cast<uint32_t>(b.size());
  }
  wipe(b);
  return out;
}
uint32_t keypass_hardware_pin(uint64_t id, const uint8_t *pin, uint32_t size) {
  if (!pin || size < 4 || size > 63 || memchr(pin, 0, size))
    return 0;
  std::lock_guard<std::mutex> lock(mutex);
  if (!active || active->id != id || !active->wantsPin || active->pinReady ||
      active->cancelled)
    return 0;
  try {
    // Allocate the NUL terminator up front; growing a populated vector could
    // leave an uncleared PIN in its previous allocation.
    active->pin.bytes.resize(size + 1);
    memcpy(active->pin.bytes.data(), pin, size);
    active->pin.bytes[size] = 0;
  } catch (...) {
    wipe(active->pin.bytes);
    return 0;
  }
  active->pinReady = true;
  wake.notify_all();
  return 1;
}
void keypass_hardware_cancel(uint64_t id) {
  std::lock_guard<std::mutex> lock(mutex);
  if (!active || active->id != id)
    return;
  active->cancelled = true;
  wake.notify_all();
  // The pointer is only published around a synchronous ceremony; the mutex
  // excludes close/free. Repeated cancellation handles pre-request races.
  if (active->device)
    fido_dev_cancel(active->device);
}
void keypass_hardware_free(uint8_t *data, uint32_t size) {
  if (data) {
    OPENSSL_cleanse(data, size);
    free(data);
  }
}
}
