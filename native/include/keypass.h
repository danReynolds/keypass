#ifndef KEYPASS_H
#define KEYPASS_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// Requests are UTF-8 JSON, <=256 KiB, with no secrets. start copies before return.
// 0 means busy; IDs are unique for the process lifetime. All functions thread-safe.
uint32_t keypass_abi_version(void);
uint64_t keypass_start(const uint8_t *request, uint32_t length);
// null means pending. Non-null transfers a buffer owned by keypass_free.
// 3 little-endian uint32: status (0 success / 1 error), public JSON length,
// binary secret length (0 / 32), then JSON and secret. Poll consumes the result.
uint8_t *keypass_poll(uint64_t id, uint32_t *length);
// Completes a cancelled response immediately; late provider completions ignored.
void keypass_cancel(uint64_t id);
// Clears the entire allocation before releasing it, including on parse failure.
void keypass_free(uint8_t *buffer, uint32_t length);
#ifdef __cplusplus
}
#endif
#endif
