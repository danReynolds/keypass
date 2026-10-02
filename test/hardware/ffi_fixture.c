#include <stdint.h>
#include <stdlib.h>
#include <string.h>
static int state, freed, submitted, cancelled, malformed, cancelled_late, nfc;
static uint64_t sequence, active;
uint32_t keypass_hardware_abi_version(void) { return 1; }
uint64_t keypass_hardware_start(const uint8_t *p, uint32_t n) {
  if (active)
    return 0;
  char request[128] = {0};
  memcpy(request, p, n < 127 ? n : 127);
  malformed = strstr(request, "malformed") != NULL;
  cancelled_late = strstr(request, "late") != NULL;
  nfc = strstr(request, "nfc") != NULL;
  state = 0;
  cancelled = 0;
  submitted = 0;
  return active = ++sequence;
}
uint8_t *keypass_hardware_poll(uint64_t id, uint32_t *n) {
  if (id != active)
    return NULL;
  const char *json;
  int status, secret = 0;
  if (cancelled) {
    json = cancelled_late ? "{\"ok\":true}" : "{\"error\":\"cancelled\"}";
    status = cancelled_late ? 0 : 1;
    secret = cancelled_late ? 32 : 0;
    active = 0;
  } else if (nfc && state == 0) {
    json = "{\"event\":\"presentKey\"}";
    status = 2;
    nfc = 0;
  } else if (state == 0) {
    json = malformed ? "{" : "{\"event\":\"pin\",\"attemptsRemaining\":8}";
    status = 2;
    state = 1;
  } else if (state == 1)
    return NULL;
  else {
    json = "{\"ok\":true}";
    status = 0;
    secret = 32;
    active = 0;
  }
  uint32_t len = (uint32_t)strlen(json);
  *n = 12 + len + secret;
  uint8_t *out = calloc(1, *n);
  out[0] = status;
  out[8] = secret;
  for (int i = 0; i < 4; i++)
    out[4 + i] = (uint8_t)(len >> (8 * i));
  memcpy(out + 12, json, len);
  if (secret)
    memset(out + 12 + len, 7, 32);
  return out;
}
uint32_t keypass_hardware_pin(uint64_t id, const uint8_t *pin, uint32_t n) {
  if (id != active || state != 1 || n != 4 || memcmp(pin, "1234", 4))
    return 0;
  submitted++;
  state = 2;
  return 1;
}
void keypass_hardware_cancel(uint64_t id) {
  if (id == active)
    cancelled = 1;
}
void keypass_hardware_free(uint8_t *p, uint32_t n) {
  volatile uint8_t *b = p;
  for (uint32_t i = 0; i < n; i++)
    b[i] = 0;
  freed++;
  free(p);
}
int fixture_submitted(void) { return submitted; }
int fixture_freed(void) { return freed; }
