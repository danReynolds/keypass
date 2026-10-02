#include <jni.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <vector>

namespace {
JavaVM *vm = nullptr;
jclass bridge = nullptr;
jmethodID dispatch = nullptr, cancel = nullptr;
std::mutex mutex;
uint64_t sequence = 0, active = 0;
std::vector<uint8_t> result;
void wipe(void *p, size_t n) { volatile uint8_t *b = static_cast<volatile uint8_t *>(p); while (n--) *b++ = 0; }
struct Environment {
    JNIEnv *env = nullptr;
    bool attached = false;
    Environment() {
        if (!vm) return;
        if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) == JNI_EDETACHED) {
            if (vm->AttachCurrentThread(&env, nullptr) == JNI_OK) attached = true;
            else env = nullptr;
        }
    }
    ~Environment() { if (attached) vm->DetachCurrentThread(); }
};
void complete(uint64_t id, const uint8_t *metadata, size_t count, uint8_t *secret, size_t secretCount, bool error) {
    std::lock_guard<std::mutex> guard(mutex);
    struct ClearSecret {
        uint8_t *data; size_t size;
        ~ClearSecret() { if (data) wipe(data, size); }
    } clear{secret, secretCount};
    if (active != id || !result.empty() || count > 65536 || (secretCount != 0 && secretCount != 32)) return;
    result.resize(12 + count + secretCount);
    uint32_t words[] = {error ? 1u : 0u, static_cast<uint32_t>(count), static_cast<uint32_t>(secretCount)};
    for (size_t i = 0; i < 3; ++i) for (size_t j = 0; j < 4; ++j) result[i*4+j] = static_cast<uint8_t>(words[i] >> (8*j));
    memcpy(result.data()+12, metadata, count);
    if (secretCount) memcpy(result.data()+12+count, secret, secretCount);
}
void fail(uint64_t id, const char *json) { complete(id, reinterpret_cast<const uint8_t *>(json), strlen(json), nullptr, 0, true); }
}
extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM *machine, void *) {
    vm = machine;
    JNIEnv *env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    auto local = env->FindClass("dev/keypass/KeypassNative");
    if (!local) return JNI_ERR;
    bridge = static_cast<jclass>(env->NewGlobalRef(local)); env->DeleteLocalRef(local);
    dispatch = env->GetStaticMethodID(bridge, "dispatch", "(J[B)V");
    cancel = env->GetStaticMethodID(bridge, "cancel", "(J)V");
    return dispatch && cancel ? JNI_VERSION_1_6 : JNI_ERR;
}
extern "C" __attribute__((visibility("default"))) uint32_t keypass_abi_version() { return 1; }
extern "C" __attribute__((visibility("default"))) uint64_t keypass_start(const uint8_t *request, uint32_t length) {
    uint64_t id;
    { std::lock_guard<std::mutex> guard(mutex); if (active || sequence == UINT64_MAX) return 0; active = id = ++sequence; }
    if (!request || !length || length > 262144) { fail(id, "{\"error\":\"invalidRequest\"}"); return id; }
    Environment scope;
    if (!scope.env || !bridge) { fail(id, "{\"error\":\"hostUnavailable\"}"); return id; }
    auto data = scope.env->NewByteArray(length);
    if (data) {
        scope.env->SetByteArrayRegion(data, 0, length, reinterpret_cast<const jbyte *>(request));
        scope.env->CallStaticVoidMethod(bridge, dispatch, static_cast<jlong>(id), data);
        scope.env->DeleteLocalRef(data);
    }
    if (!data || scope.env->ExceptionCheck()) {
        scope.env->ExceptionClear(); fail(id, "{\"error\":\"backendFailure\"}");
    }
    return id;
}
extern "C" __attribute__((visibility("default"))) uint8_t *keypass_poll(uint64_t id, uint32_t *length) {
    std::lock_guard<std::mutex> guard(mutex);
    if (!length || active != id || result.empty()) return nullptr;
    auto buffer = static_cast<uint8_t *>(malloc(result.size()));
    if (!buffer) return nullptr;
    memcpy(buffer, result.data(), result.size()); *length = static_cast<uint32_t>(result.size());
    wipe(result.data(), result.size()); result.clear(); active = 0; return buffer;
}
extern "C" __attribute__((visibility("default"))) void keypass_cancel(uint64_t id) {
    fail(id, "{\"error\":\"cancelled\"}");
    Environment scope;
    if (scope.env && bridge) {
        scope.env->CallStaticVoidMethod(bridge, cancel, static_cast<jlong>(id));
        if (scope.env->ExceptionCheck()) scope.env->ExceptionClear();
    }
}
extern "C" __attribute__((visibility("default"))) void keypass_free(uint8_t *buffer, uint32_t length) {
    if (buffer) { wipe(buffer, length); free(buffer); }
}
extern "C" JNIEXPORT void JNICALL Java_dev_keypass_KeypassNative_complete(JNIEnv *env, jclass, jlong id, jbyteArray metadata, jbyteArray secret, jboolean error) {
    if (!metadata) { fail(id, "{\"error\":\"backendFailure\"}"); return; }
    auto count = env->GetArrayLength(metadata), secretCount = secret ? env->GetArrayLength(secret) : 0;
    if (count > 65536 || (secretCount != 0 && secretCount != 32)) { fail(id, "{\"error\":\"backendFailure\"}"); return; }
    std::vector<uint8_t> publicBytes(count);
    uint8_t secretBytes[32] = {};
    env->GetByteArrayRegion(metadata, 0, count, reinterpret_cast<jbyte *>(publicBytes.data()));
    if (secretCount) {
        env->GetByteArrayRegion(secret, 0, secretCount, reinterpret_cast<jbyte *>(secretBytes));
        const jbyte zeroes[32] = {};
        if (!env->ExceptionCheck()) env->SetByteArrayRegion(secret, 0, secretCount, zeroes);
    }
    if (!env->ExceptionCheck()) complete(id, publicBytes.data(), count, secretBytes, secretCount, error);
    else { env->ExceptionClear(); fail(id, "{\"error\":\"backendFailure\"}"); }
    wipe(secretBytes, sizeof secretBytes);
}

extern "C" JNIEXPORT jboolean JNICALL Java_dev_keypass_KeypassNative_isPending(JNIEnv *, jclass, jlong id) {
    std::lock_guard<std::mutex> guard(mutex);
    return active == static_cast<uint64_t>(id) && result.empty();
}
