#ifndef KEYPASS_HARDWARE_H
#define KEYPASS_HARDWARE_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define KP_EXPORT __attribute__((visibility("default")))
KP_EXPORT uint32_t keypass_hardware_abi_version(void);
// Bounded public JSON; start copies it. Zero means a process-wide operation is
// busy.
KP_EXPORT uint64_t keypass_hardware_start(const uint8_t *, uint32_t);
// Header: LE status (0 success, 1 error, 2 interaction), JSON length, secret
// length. Null means pending. Status 2 is not terminal. Caller must free every
// reply.
KP_EXPORT uint8_t *keypass_hardware_poll(uint64_t, uint32_t *);
// PIN is exclusively binary and never serialized. Copied before return, then
// wiped after use. Returns 1 only for an outstanding PIN request.
KP_EXPORT uint32_t keypass_hardware_pin(uint64_t, const uint8_t *, uint32_t);
KP_EXPORT void keypass_hardware_cancel(uint64_t);
KP_EXPORT void keypass_hardware_free(uint8_t *, uint32_t);
#ifdef __cplusplus
}
#endif
#endif
