#include <stdint.h>
#include <stdlib.h>
#include <string.h>
static int pending, malformed, frees, wiped;
static uint64_t serial;
uint32_t keypass_abi_version(void) { return 1; }
uint64_t keypass_start(const uint8_t *input, uint32_t length) {
  (void)length;
  // Dart JSON always starts with {"case": for this fixture; bounded copy.
  char text[128] = {0}; memcpy(text, input, length < 127 ? length : 127);
  pending = strstr(text, "pending") != NULL;
  malformed = strstr(text, "malformed") != NULL;
  return ++serial;
}
uint8_t *keypass_poll(uint64_t id, uint32_t *length) {
  (void)id;
  if (pending) return NULL;
  const char *metadata = malformed ? "{" : "{\"ok\":true}";
  uint32_t count = (uint32_t)strlen(metadata);
  *length = 12 + count + 32;
  uint8_t *out = calloc(1, *length);
  for (int i=0;i<4;++i) out[4+i] = (uint8_t)(count >> (i*8));
  out[8] = 32; memcpy(out+12,metadata,count); memset(out+12+count,7,32);
  return out;
}
void keypass_cancel(uint64_t id) { (void)id; pending = 0; }
void keypass_free(uint8_t *buffer, uint32_t length) {
  volatile uint8_t *p = buffer;
  for(uint32_t i=0;i<length;++i) p[i]=0;
  wiped = 1;
  for(uint32_t i=0;i<length;++i) if(p[i]) wiped=0;
  ++frees; free(buffer);
}
int fixture_frees(void) { return frees; }
int fixture_wiped(void) { return wiped; }
