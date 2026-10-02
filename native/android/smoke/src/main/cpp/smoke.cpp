#include <jni.h>
#include <dlfcn.h>
#include <cstdint>
#include <vector>
#include <thread>
#include <chrono>
extern "C" JNIEXPORT jbyteArray JNICALL Java_dev_keypass_smoke_SmokeActivity_roundTrip(JNIEnv *env, jobject, jbyteArray request, jboolean shouldCancel) {
    auto library = dlopen("libkeypass.so", RTLD_NOW);
    auto start = reinterpret_cast<uint64_t (*)(const uint8_t *, uint32_t)>(dlsym(library, "keypass_start"));
    auto poll = reinterpret_cast<uint8_t *(*)(uint64_t, uint32_t *)>(dlsym(library, "keypass_poll"));
    auto cancel = reinterpret_cast<void (*)(uint64_t)>(dlsym(library, "keypass_cancel"));
    auto release = reinterpret_cast<void (*)(uint8_t *, uint32_t)>(dlsym(library, "keypass_free"));
    if (!start || !poll || !cancel || !release) return env->NewByteArray(0);
    std::vector<uint8_t> input(env->GetArrayLength(request));
    env->GetByteArrayRegion(request, 0, input.size(), reinterpret_cast<jbyte *>(input.data()));
    auto id = start(input.data(), input.size());
    if (shouldCancel) cancel(id);
    for (int attempt = 0; attempt < 500; ++attempt) {
        uint32_t size = 0;
        auto response = poll(id, &size);
        if (response) {
            uint32_t count = 0;
            for (int i = 0; i < 4; ++i) count |= uint32_t(response[4+i]) << (8*i);
            auto output = env->NewByteArray(size == count + 12 ? count : 0);
            if (size == count + 12) env->SetByteArrayRegion(output, 0, count, reinterpret_cast<jbyte *>(response + 12));
            release(response, size); dlclose(library); return output;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    cancel(id); dlclose(library); return env->NewByteArray(0);
}
