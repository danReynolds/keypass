#include "broker.hpp"
#include <jni.h>

namespace {
HardwareBroker broker;
JavaVM *vm = nullptr;
jclass bridge = nullptr;
jmethodID dispatchMethod = nullptr, cancelMethod = nullptr, pinMethod = nullptr;
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
}
extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM *machine, void *) {
  vm = machine; JNIEnv *env = nullptr;
  if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
  auto local = env->FindClass("dev/keypass/hardware/HardwareNative");
  if (!local) return JNI_ERR;
  bridge = static_cast<jclass>(env->NewGlobalRef(local)); env->DeleteLocalRef(local);
  dispatchMethod = env->GetStaticMethodID(bridge, "dispatch", "(J[B)V");
  cancelMethod = env->GetStaticMethodID(bridge, "cancel", "(J)V");
  pinMethod = env->GetStaticMethodID(bridge, "submitPin", "(J[B)Z");
  return dispatchMethod && cancelMethod && pinMethod ? JNI_VERSION_1_6 : JNI_ERR;
}
#define EXPORT extern "C" __attribute__((visibility("default")))
EXPORT uint32_t keypass_hardware_abi_version() { return 1; }
EXPORT uint64_t keypass_hardware_start(const uint8_t *input, uint32_t length) {
  auto id = broker.reserve();
  if (!id) return 0;
  if (!input || !length || length > 65536) {
    broker.fail(id, "{\"error\":\"invalidRequest\"}"); return id;
  }
  Environment scope;
  if (!scope.env || !bridge) { broker.fail(id, "{\"error\":\"hostUnavailable\"}"); return id; }
  auto array = scope.env->NewByteArray(length);
  if (array) {
    scope.env->SetByteArrayRegion(array, 0, length, reinterpret_cast<const jbyte *>(input));
    if (!scope.env->ExceptionCheck()) scope.env->CallStaticVoidMethod(bridge, dispatchMethod, static_cast<jlong>(id), array);
    scope.env->DeleteLocalRef(array);
  }
  if (!array || scope.env->ExceptionCheck()) {
    scope.env->ExceptionClear(); broker.fail(id, "{\"error\":\"backendFailure\"}");
  }
  return id;
}
EXPORT uint8_t *keypass_hardware_poll(uint64_t id, uint32_t *size) { return broker.poll(id, size); }
EXPORT void keypass_hardware_free(uint8_t *data, uint32_t length) {
  if (data) { kp_wipe(data, length); free(data); }
}
EXPORT uint32_t keypass_hardware_pin(uint64_t id, const uint8_t *pin, uint32_t length) {
  if (!pin || length < 4 || length > 63 || memchr(pin, 0, length) || !broker.pending(id)) return 0;
  Environment scope;
  if (!scope.env || !bridge) return 0;
  auto array = scope.env->NewByteArray(length);
  jboolean accepted = false;
  if (array) {
    scope.env->SetByteArrayRegion(array, 0, length, reinterpret_cast<const jbyte *>(pin));
    if (!scope.env->ExceptionCheck()) accepted = scope.env->CallStaticBooleanMethod(bridge, pinMethod, static_cast<jlong>(id), array);
    if (scope.env->ExceptionCheck()) { scope.env->ExceptionClear(); accepted = false; }
    jbyte zeros[63] = {};
    scope.env->SetByteArrayRegion(array, 0, length, zeros);
    scope.env->DeleteLocalRef(array);
  }
  if (scope.env->ExceptionCheck()) { scope.env->ExceptionClear(); accepted = false; }
  return accepted ? 1 : 0;
}
EXPORT void keypass_hardware_cancel(uint64_t id) {
  if (!broker.cancel(id)) return;
  Environment scope;
  if (scope.env && bridge) {
    scope.env->CallStaticVoidMethod(bridge, cancelMethod, static_cast<jlong>(id));
    if (scope.env->ExceptionCheck()) scope.env->ExceptionClear();
  }
}
extern "C" JNIEXPORT jboolean JNICALL Java_dev_keypass_hardware_HardwareNative_isPending(JNIEnv *, jclass, jlong id) {
  return broker.pending(id);
}
extern "C" JNIEXPORT jboolean JNICALL Java_dev_keypass_hardware_HardwareNative_event(JNIEnv *env, jclass, jlong id, jbyteArray json) {
  if (!json) return false;
  auto size = env->GetArrayLength(json);
  if (size > 65536) return false;
  std::vector<uint8_t> bytes(size);
  env->GetByteArrayRegion(json, 0, size, reinterpret_cast<jbyte *>(bytes.data()));
  if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
  return broker.event(id, bytes.data(), bytes.size());
}
extern "C" JNIEXPORT void JNICALL Java_dev_keypass_hardware_HardwareNative_complete(JNIEnv *env, jclass, jlong id, jbyteArray json, jbyteArray secret, jboolean failed) {
  if (!json) { broker.fail(id, "{\"error\":\"backendFailure\"}"); return; }
  auto size = env->GetArrayLength(json);
  auto secretSize = secret ? env->GetArrayLength(secret) : 0;
  if (size > 65536 || (secretSize != 0 && secretSize != 32)) {
    broker.fail(id, "{\"error\":\"backendFailure\"}"); return;
  }
  std::vector<uint8_t> bytes(size);
  uint8_t secretBytes[32] = {};
  env->GetByteArrayRegion(json, 0, size, reinterpret_cast<jbyte *>(bytes.data()));
  if (secretSize) {
    env->GetByteArrayRegion(secret, 0, secretSize, reinterpret_cast<jbyte *>(secretBytes));
    const jbyte zeroes[32] = {};
    if (!env->ExceptionCheck()) env->SetByteArrayRegion(secret, 0, secretSize, zeroes);
  }
  if (!env->ExceptionCheck()) broker.finish(id, bytes.data(), size, secretBytes, secretSize, failed);
  else { env->ExceptionClear(); broker.fail(id, "{\"error\":\"backendFailure\"}"); }
  kp_wipe(secretBytes, sizeof secretBytes);
}
