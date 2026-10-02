#include <windows.h>
#include <wincrypt.h>
#include "webauthn.h"
#include "json.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using Json = nlohmann::json;
namespace {
struct Api {
    HMODULE library = LoadLibraryExW(L"webauthn.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    template<class T> T symbol(const char *name) { return library ? reinterpret_cast<T>(GetProcAddress(library, name)) : nullptr; }
    decltype(&WebAuthNGetApiVersionNumber) version = symbol<decltype(version)>("WebAuthNGetApiVersionNumber");
    decltype(&WebAuthNAuthenticatorMakeCredential) create = symbol<decltype(create)>("WebAuthNAuthenticatorMakeCredential");
    decltype(&WebAuthNAuthenticatorGetAssertion) get = symbol<decltype(get)>("WebAuthNAuthenticatorGetAssertion");
    decltype(&WebAuthNFreeCredentialAttestation) freeRegistration = symbol<decltype(freeRegistration)>("WebAuthNFreeCredentialAttestation");
    decltype(&WebAuthNFreeAssertion) freeAssertion = symbol<decltype(freeAssertion)>("WebAuthNFreeAssertion");
    decltype(&WebAuthNGetCancellationId) cancellation = symbol<decltype(cancellation)>("WebAuthNGetCancellationId");
    decltype(&WebAuthNCancelCurrentOperation) cancel = symbol<decltype(cancel)>("WebAuthNCancelCurrentOperation");
    bool ready() const { return version && create && get && freeRegistration && freeAssertion && cancellation && cancel && version() >= 6; }
};
Api &api() { static Api value; return value; }
struct Operation {
    uint64_t id;
    GUID cancellation{};
    std::atomic<bool> cancelled{false}, running{true}, hasCancellation{false};
    std::vector<uint8_t> response;
    explicit Operation(uint64_t value): id(value) {}
    ~Operation() { if (!response.empty()) SecureZeroMemory(response.data(), response.size()); }
};
std::mutex mutex;
uint64_t sequence = 0;
std::shared_ptr<Operation> active;
bool busy = false;
void finish(const std::shared_ptr<Operation> &op, const Json &metadata, const uint8_t *secret = nullptr, size_t secretSize = 0) {
    auto json = metadata.dump();
    if (json.size() > 65536 || (secretSize != 0 && secretSize != 32)) throw std::runtime_error("size");
    std::lock_guard<std::mutex> guard(mutex);
    if (!op->response.empty() || active != op) return;
    auto &out = op->response;
    out.resize(12 + json.size() + secretSize);
    uint32_t words[] = {metadata.contains("error") ? 1u : 0u, static_cast<uint32_t>(json.size()), static_cast<uint32_t>(secretSize)};
    for (size_t i=0; i<3; ++i) for (size_t j=0; j<4; ++j) out[4*i+j] = static_cast<uint8_t>(words[i] >> (8*j));
    memcpy(out.data()+12, json.data(), json.size());
    if (secretSize) memcpy(out.data()+12+json.size(), secret, secretSize);
}
void fail(const std::shared_ptr<Operation> &op, const char *code) { finish(op, {{"error",code}}); }
std::string encode(const uint8_t *data, size_t size) {
    if (size > 16384 || (!data && size)) throw std::runtime_error("size");
    if (!size) return "";
    DWORD count = 0;
    if (!CryptBinaryToStringA(data, static_cast<DWORD>(size), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &count)) throw std::runtime_error("base64");
    std::string out(count, '\0');
    if (!CryptBinaryToStringA(data, static_cast<DWORD>(size), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, out.data(), &count)) throw std::runtime_error("base64");
    out.resize(strlen(out.c_str()));
    std::replace(out.begin(), out.end(), '+', '-'); std::replace(out.begin(), out.end(), '/', '_');
    while (!out.empty() && out.back() == '=') out.pop_back();
    return out;
}
std::string encode(const std::string &text) { return encode(reinterpret_cast<const uint8_t *>(text.data()), text.size()); }
std::vector<uint8_t> decode(const Json &value, size_t maximum) {
    auto text = value.get<std::string>();
    if (text.empty() || text.size() > (maximum + 2)/3*4) throw std::runtime_error("size");
    auto standard = text;
    std::replace(standard.begin(), standard.end(), '-', '+'); std::replace(standard.begin(), standard.end(), '_', '/');
    while (standard.size()%4) standard.push_back('=');
    DWORD size = 0;
    if (!CryptStringToBinaryA(standard.data(), static_cast<DWORD>(standard.size()), CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr) || size > maximum) throw std::runtime_error("base64");
    std::vector<uint8_t> out(size);
    if (!CryptStringToBinaryA(standard.data(), static_cast<DWORD>(standard.size()), CRYPT_STRING_BASE64, out.data(), &size, nullptr, nullptr) || encode(out.data(), out.size()) != text) throw std::runtime_error("base64");
    return out;
}
std::wstring wide(const std::string &value) {
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (!count) throw std::runtime_error("utf8");
    std::wstring out(count, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), out.data(), count);
    return out;
}
void sdkError(const std::shared_ptr<Operation> &op, HRESULT result) {
    fail(op, op->cancelled || result == HRESULT_FROM_WIN32(ERROR_CANCELLED) || result == NTE_USER_CANCELLED ? "cancelled" : "backendFailure");
}
struct AssertionFree {
    void operator()(WEBAUTHN_ASSERTION *value) const {
        if (!value) return;
        if (value->dwVersion >= 3 && value->pHmacSecret) {
            auto secret = value->pHmacSecret;
            if (secret->pbFirst) SecureZeroMemory(secret->pbFirst, secret->cbFirst);
            if (secret->pbSecond) SecureZeroMemory(secret->pbSecond, secret->cbSecond);
        }
        api().freeAssertion(value);
    }
};
void run(const std::shared_ptr<Operation> &op, Json request, HWND window) {
    std::thread watchdog;
    try {
        if (!api().ready()) { fail(op, "backendUnavailable"); }
        else if (!window) { fail(op, "hostUnavailable"); }
        else if (request.at("operation") == "availability") {
            finish(op, {{"platform","windows"},{"origin","https://"+request.at("domain").get<std::string>()},{"multiple",true}});
        } else {
            auto &options = request.at("publicKey");
            bool registration = request.at("operation") == "register";
            if (!registration && request.at("operation") != "evaluate") throw std::runtime_error("operation");
            auto domain = registration ? options.at("rp").at("id").get<std::string>() : options.at("rpId").get<std::string>();
            auto rp = wide(domain);
            auto challenge = decode(options.at("challenge"), 32);
            if (challenge.size() != 32) throw std::runtime_error("challenge");
            auto client = Json({{"type", registration ? "webauthn.create" : "webauthn.get"},
                {"challenge",options.at("challenge")},{"origin","https://"+domain},{"crossOrigin",false}}).dump();
            WEBAUTHN_CLIENT_DATA data{1, static_cast<DWORD>(client.size()), reinterpret_cast<PBYTE>(client.data()), WEBAUTHN_HASH_ALGORITHM_SHA_256};
            if (FAILED(api().cancellation(&op->cancellation))) throw std::runtime_error("cancellation");
            op->hasCancellation = true;
            // Retrying closes the race where cancellation reaches the OS just
            // before its blocking request starts. The DLL stays pinned in-process.
            watchdog = std::thread([op] {
                const auto start = std::chrono::steady_clock::now();
                while (op->running) {
                    if (std::chrono::steady_clock::now() - start > std::chrono::seconds(125)) {
                        op->cancelled = true; fail(op, "timeout");
                    }
                    if (op->cancelled) api().cancel(&op->cancellation);
                    std::this_thread::sleep_for(std::chrono::milliseconds(20));
                }
            });
            if (op->cancelled) { fail(op, "cancelled"); }
            else if (registration) {
                auto name = wide(options.at("rp").at("name").get<std::string>());
                auto label = wide(options.at("user").at("name").get<std::string>());
                auto user = decode(options.at("user").at("id"),64);
                WEBAUTHN_RP_ENTITY_INFORMATION rpInfo{1, rp.c_str(), name.c_str(), nullptr};
                WEBAUTHN_USER_ENTITY_INFORMATION userInfo{1, static_cast<DWORD>(user.size()), user.data(), label.c_str(), nullptr, label.c_str()};
                WEBAUTHN_COSE_CREDENTIAL_PARAMETER parameter{1, WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY, -7};
                WEBAUTHN_COSE_CREDENTIAL_PARAMETERS parameters{1, &parameter};
                WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS config{};
                config.dwVersion = 6; config.dwTimeoutMilliseconds = 120000;
                config.bRequireResidentKey = TRUE; config.bEnablePrf = TRUE;
                config.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
                config.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE;
                config.pCancellationId = &op->cancellation;
                PWEBAUTHN_CREDENTIAL_ATTESTATION raw = nullptr;
                auto hr = api().create(window, &rpInfo, &userInfo, &parameters, &data, &config, &raw);
                std::unique_ptr<WEBAUTHN_CREDENTIAL_ATTESTATION, decltype(api().freeRegistration)> value(raw, api().freeRegistration);
                if (FAILED(hr)) sdkError(op,hr);
                else if (!value) fail(op,"verificationFailed");
                else finish(op, {{"credentialId",encode(value->pbCredentialId,value->cbCredentialId)},
                    {"clientDataJSON",encode(client)},{"attestationObject",encode(value->pbAttestationObject,value->cbAttestationObject)},
                    {"prfEnabled",value->dwVersion >= 5 && value->bPrfEnabled != FALSE}});
            } else {
                auto &allowed = options.at("allowCredentials");
                if (!allowed.is_array() || allowed.empty() || allowed.size() > 64) throw std::runtime_error("credentials");
                std::vector<std::vector<uint8_t>> ids, inputs;
                for (auto &item: allowed) {
                    ids.push_back(decode(item.at("id"), 1024));
                    inputs.push_back(decode(options.at("extensions").at("prf").at("evalByCredential").at(item.at("id").get<std::string>()).at("first"),1024));
                }
                std::vector<WEBAUTHN_CREDENTIAL> credentials;
                std::vector<WEBAUTHN_HMAC_SECRET_SALT> salts;
                for (size_t i=0; i<ids.size(); ++i) {
                    credentials.push_back({1, static_cast<DWORD>(ids[i].size()), ids[i].data(), WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY});
                    salts.push_back({static_cast<DWORD>(inputs[i].size()),inputs[i].data(),0,nullptr});
                }
                std::vector<WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT> perCredential;
                for (size_t i=0; i<ids.size(); ++i) perCredential.push_back({static_cast<DWORD>(ids[i].size()),ids[i].data(),&salts[i]});
                WEBAUTHN_HMAC_SECRET_SALT_VALUES values{nullptr, static_cast<DWORD>(perCredential.size()), perCredential.data()};
                WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS config{};
                config.dwVersion = 6; config.dwTimeoutMilliseconds = 120000;
                config.CredentialList = {static_cast<DWORD>(credentials.size()), credentials.data()};
                config.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED;
                config.pCancellationId = &op->cancellation; config.pHmacSecretSaltValues = &values;
                // dwFlags remains zero: Windows hashes WebAuthn PRF inputs with
                // the standard prefix. Setting RAW HMAC salt mode would break portability.
                PWEBAUTHN_ASSERTION raw = nullptr;
                auto hr = api().get(window, rp.c_str(), &data, &config, &raw);
                std::unique_ptr<WEBAUTHN_ASSERTION, AssertionFree> value(raw);
                if (FAILED(hr)) sdkError(op,hr);
                else if (!value || value->dwVersion < 3 || !value->pHmacSecret || value->pHmacSecret->cbFirst != 32 || !value->pHmacSecret->pbFirst) fail(op,"prfUnavailable");
                else {
                    Json metadata{{"credentialId",encode(value->Credential.pbId,value->Credential.cbId)},
                        {"clientDataJSON",encode(client)},{"authenticatorData",encode(value->pbAuthenticatorData,value->cbAuthenticatorData)},
                        {"signature",encode(value->pbSignature,value->cbSignature)}};
                    if (value->cbUserId) metadata["userHandle"] = encode(value->pbUserId,value->cbUserId);
                    finish(op, metadata, value->pHmacSecret->pbFirst, 32);
                }
            }
        }
    } catch (...) { fail(op, "backendFailure"); }
    // The OS assertion/registration RAII owners have left scope. Stop and join
    // the cancellation worker before making a successful packet observable.
    op->running = false;
    if (watchdog.joinable()) watchdog.join();
    std::lock_guard<std::mutex> guard(mutex); busy = false;
}
}
extern "C" __declspec(dllexport) uint32_t keypass_abi_version() { return 1; }
extern "C" __declspec(dllexport) uint64_t keypass_start(const uint8_t *request, uint32_t length) {
    std::shared_ptr<Operation> op;
    { std::lock_guard<std::mutex> guard(mutex);
      if (active || busy || sequence == UINT64_MAX) return 0;
      op = active = std::make_shared<Operation>(++sequence); busy = true; }
    if (!request || !length || length > 262144) { fail(op,"invalidRequest"); std::lock_guard<std::mutex> guard(mutex); busy=false; return op->id; }
    HMODULE pinned = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN, reinterpret_cast<LPCWSTR>(&keypass_start), &pinned);
    auto window = GetForegroundWindow(); DWORD pid = 0;
    if (window) GetWindowThreadProcessId(window,&pid);
    if (pid != GetCurrentProcessId()) window = nullptr;
    try { auto json = Json::parse(request, request+length); std::thread(run,op,std::move(json),window).detach(); }
    catch (...) { fail(op,"invalidRequest"); std::lock_guard<std::mutex> guard(mutex); busy=false; }
    return op->id;
}
extern "C" __declspec(dllexport) uint8_t *keypass_poll(uint64_t id, uint32_t *length) {
    std::lock_guard<std::mutex> guard(mutex);
    if (!length || !active || active->id != id || active->response.empty()) return nullptr;
    const auto &data = active->response;
    // Error/cancellation can return promptly while busy fences an OS request
    // that has not returned. Success transfers only after all worker cleanup.
    if (data[0] == 0 && busy) return nullptr;
    auto buffer = static_cast<uint8_t *>(malloc(data.size()));
    if (!buffer) return nullptr;
    memcpy(buffer,data.data(),data.size()); *length=static_cast<uint32_t>(data.size());
    SecureZeroMemory(active->response.data(), active->response.size()); active->response.clear(); active.reset(); return buffer;
}
extern "C" __declspec(dllexport) void keypass_cancel(uint64_t id) {
    std::shared_ptr<Operation> op;
    { std::lock_guard<std::mutex> guard(mutex); if (!active || active->id != id) return; op=active; }
    op->cancelled=true; fail(op,"cancelled");
    if (op->hasCancellation && api().cancel) api().cancel(&op->cancellation);
}
extern "C" __declspec(dllexport) void keypass_free(uint8_t *buffer, uint32_t length) {
    if (buffer) { SecureZeroMemory(buffer,length); free(buffer); }
}
