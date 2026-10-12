#include <stdio.h>
#include "transport/matter_counter.h"

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #c); return false; } } while (0)
typedef struct {
    uint32_t sample;
    Matter_Result_T result;
    unsigned calls, violations;
    Matter_Counter_T* reenter;
    bool omit_sample;
} Random;
static Matter_Result_T random28(void* user, uint32_t* sample) {
    Random* r = user; ++r->calls;
    if (!r->omit_sample) *sample = r->sample;
    if (r->reenter) {
        Matter_Counter_Value_T out = {99, true};
        if (matter_counter_init(r->reenter, MATTER_COUNTER_UNSECURED, random28, r) != MATTER_BUSY ||
            matter_counter_take(r->reenter, &out) != MATTER_BUSY || out.counter != 99 || !out.expires_session)
            ++r->violations;
    }
    return r->result;
}
static bool same(const Matter_Counter_T* a, const Matter_Counter_T* b) {
    return a->next == b->next && a->mode == b->mode && a->initialized == b->initialized &&
        a->exhausted == b->exhausted && a->busy == b->busy;
}
static bool initialization(void) {
    static const uint32_t samples[] = {0, 1, UINT32_C(0x0ffffffe), UINT32_C(0x0fffffff)};
    static const uint32_t expected[] = {1, 2, UINT32_C(0x0fffffff), UINT32_C(0x10000000)};
    for (unsigned mode = 1; mode <= 2; ++mode) for (unsigned i = 0; i < 4; ++i) {
        Matter_Counter_T s = {0};
        Random r = {.sample = samples[i], .reenter = &s};
        Matter_Counter_Value_T out;
        CHECK(matter_counter_init(&s, (Matter_Counter_Mode_T)mode, random28, &r) == MATTER_OK);
        CHECK(r.calls == 1 && !r.violations && !s.busy && s.initialized && !s.exhausted);
        CHECK(matter_counter_take(&s, &out) == MATTER_OK && out.counter == expected[i] && !out.expires_session);
        CHECK(s.next == expected[i] + 1);
        CHECK(matter_counter_init(&s, (Matter_Counter_Mode_T)mode, random28, &r) == MATTER_INVALID_STATE && r.calls == 1);
    }
    printf("Outgoing counter: %zu bytes, no allocations\n", sizeof(Matter_Counter_T));
    return true;
}
static bool rng_failures(void) {
    static const Matter_Result_T failures[] = {MATTER_WOULD_BLOCK, MATTER_OFFLINE, MATTER_PORT_ERROR, MATTER_PENDING};
    Matter_Counter_T s = {0}, before = s;
    Random r = {.sample = 17, .reenter = &s};
    Matter_Counter_Value_T out = {99, true};
    for (unsigned i = 0; i < 4; ++i) {
        r.result = failures[i];
        CHECK(matter_counter_init(&s, MATTER_COUNTER_SECURE_UNICAST, random28, &r) ==
            (i == 3 ? MATTER_PORT_ERROR : failures[i]));
        CHECK(same(&s, &before) && !r.violations);
        CHECK(matter_counter_take(&s, &out) == MATTER_INVALID_STATE && out.counter == 99 && out.expires_session);
    }
    r.result = MATTER_OK; r.sample = UINT32_C(0x10000000);
    CHECK(matter_counter_init(&s, MATTER_COUNTER_SECURE_UNICAST, random28, &r) == MATTER_PORT_ERROR && same(&s, &before));
    r.sample = UINT32_MAX;
    CHECK(matter_counter_init(&s, MATTER_COUNTER_SECURE_UNICAST, random28, &r) == MATTER_PORT_ERROR && same(&s, &before));
    r.omit_sample = true;
    CHECK(matter_counter_init(&s, MATTER_COUNTER_SECURE_UNICAST, random28, &r) == MATTER_PORT_ERROR && same(&s, &before));
    r.omit_sample = false;
    r.sample = 17;
    CHECK(matter_counter_init(&s, MATTER_COUNTER_SECURE_UNICAST, random28, &r) == MATTER_OK);
    CHECK(matter_counter_take(&s, &out) == MATTER_OK && out.counter == 18);
    return true;
}
static bool errors_preserve_state(void) {
    Matter_Counter_T s = {0}, before = s;
    Random r = {0};
    Matter_Counter_Value_T out = {99, true};
    CHECK(matter_counter_init(NULL, MATTER_COUNTER_UNSECURED, random28, &r) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_counter_init(&s, (Matter_Counter_Mode_T)0, random28, &r) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_counter_init(&s, (Matter_Counter_Mode_T)3, random28, &r) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_counter_init(&s, MATTER_COUNTER_UNSECURED, NULL, &r) == MATTER_INVALID_ARGUMENT);
    CHECK(!r.calls && same(&s, &before));
    CHECK(matter_counter_take(NULL, &out) == MATTER_INVALID_ARGUMENT && out.counter == 99 && out.expires_session);
    CHECK(matter_counter_take(&s, NULL) == MATTER_INVALID_ARGUMENT && same(&s, &before));
    CHECK(matter_counter_init(&s, MATTER_COUNTER_UNSECURED, random28, &r) == MATTER_OK);
    before = s;
    CHECK(matter_counter_take(&s, NULL) == MATTER_INVALID_ARGUMENT && same(&s, &before));
    CHECK(matter_counter_init(&s, MATTER_COUNTER_SECURE_UNICAST, random28, &r) == MATTER_INVALID_STATE && same(&s, &before));
    return true;
}
static bool rollover_and_expiry(void) {
    Random r = {0};
    Matter_Counter_T a = {0}, b = {0};
    Matter_Counter_Value_T out;
    CHECK(matter_counter_init(&a, MATTER_COUNTER_UNSECURED, random28, &r) == MATTER_OK);
    CHECK(matter_counter_init(&b, MATTER_COUNTER_SECURE_UNICAST, random28, &r) == MATTER_OK);
    /* Test-only fast-forward models earlier consumption; no production restore API. */
    a.next = b.next = UINT32_MAX - 1;
    CHECK(matter_counter_take(&a, &out) == MATTER_OK && out.counter == UINT32_MAX - 1 && !out.expires_session);
    CHECK(matter_counter_take(&b, &out) == MATTER_OK && out.counter == UINT32_MAX - 1 && !out.expires_session);
    CHECK(matter_counter_take(&a, &out) == MATTER_OK && out.counter == UINT32_MAX && !out.expires_session && a.next == 0);
    CHECK(matter_counter_take(&a, &out) == MATTER_OK && out.counter == 0 && !out.expires_session && a.next == 1);
    CHECK(matter_counter_take(&b, &out) == MATTER_OK && out.counter == UINT32_MAX && out.expires_session && b.exhausted);
    Matter_Counter_T before = b;
    out = (Matter_Counter_Value_T){99, false};
    CHECK(matter_counter_take(&b, &out) == MATTER_LIMIT_REACHED && out.counter == 99 && !out.expires_session && same(&b, &before));
    unsigned calls = r.calls;
    CHECK(matter_counter_init(&b, MATTER_COUNTER_SECURE_UNICAST, random28, &r) == MATTER_INVALID_STATE && r.calls == calls);
    CHECK(same(&b, &before));
    return true;
}
static bool shared_node_and_independent_sessions(void) {
    Random r = {.sample = 99};
    Matter_Counter_T node = {0}, session = {0};
    Matter_Counter_Value_T discarded, a, b;
    CHECK(matter_counter_init(&node, MATTER_COUNTER_UNSECURED, random28, &r) == MATTER_OK);
    CHECK(matter_counter_init(&session, MATTER_COUNTER_SECURE_UNICAST, random28, &r) == MATTER_OK);
    /* Two destinations share one NODE counter. Discarded preparation is not refunded. */
    CHECK(matter_counter_take(&node, &discarded) == MATTER_OK && discarded.counter == 100);
    CHECK(matter_counter_take(&node, &a) == MATTER_OK && a.counter == 101);
    CHECK(matter_counter_take(&node, &b) == MATTER_OK && b.counter == 102);
    CHECK(matter_counter_take(&session, &a) == MATTER_OK && a.counter == 100);
    for (uint32_t i = 0; i < 10000; ++i)
        CHECK(matter_counter_take(&session, &a) == MATTER_OK && a.counter == 101 + i && !a.expires_session);
    CHECK(node.next == 103 && r.calls == 2);
    return true;
}
int main(void) {
    if (!initialization() || !rng_failures() || !errors_preserve_state() || !rollover_and_expiry() ||
        !shared_node_and_independent_sessions()) return 1;
    puts("PASS outgoing counter: 5 groups"); return 0;
}
