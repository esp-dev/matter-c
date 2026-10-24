#ifndef MATTER_LAB_TEST_CLOCK_H
#define MATTER_LAB_TEST_CLOCK_H 1
/* Clock-only adapter for the existing host crypto/SPAKE test translation units.
 * No Windows APIs are used by the library or application. */
#include <stdint.h>
#include "esp_timer.h"
typedef struct { int64_t QuadPart; } LARGE_INTEGER;
static inline int QueryPerformanceFrequency(LARGE_INTEGER* out) { out->QuadPart=1000000; return 1; }
static inline int QueryPerformanceCounter(LARGE_INTEGER* out) { out->QuadPart=esp_timer_get_time(); return 1; }
#endif
