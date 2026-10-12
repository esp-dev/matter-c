#include <stdio.h>
#include <stdlib.h>
#include "transport/matter_reception.h"

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #c); return false; } } while (0)
static bool same(const Matter_Reception_T* a, const Matter_Reception_T* b) {
    return a->max_counter == b->max_counter && a->bitmap == b->bitmap && a->mode == b->mode &&
        a->initialized == b->initialized;
}
static bool expect(Matter_Reception_T* s, uint32_t counter, bool duplicate, uint32_t maximum, uint32_t bitmap) {
    Matter_Reception_T before = *s;
    bool actual = !duplicate;
    CHECK(matter_reception_classify(s, counter, &actual) == MATTER_OK && actual == duplicate && same(s, &before));
    CHECK(matter_reception_commit(s, counter, &actual) == MATTER_OK && actual == duplicate);
    CHECK(s->initialized && s->max_counter == maximum && s->bitmap == bitmap);
    if (duplicate) CHECK(same(s, &before));
    return true;
}
static bool initialization_and_errors(void) {
    Matter_Reception_T s = {0}, before = s;
    bool duplicate = true;
    CHECK(MATTER_RECEPTION_WINDOW_SIZE == 32);
    CHECK(matter_reception_classify(&s, 0, &duplicate) == MATTER_INVALID_STATE && duplicate);
    CHECK(matter_reception_commit(&s, 0, &duplicate) == MATTER_INVALID_STATE && same(&s, &before));
    CHECK(matter_reception_reset(NULL, MATTER_RECEPTION_UNSECURED) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_reception_seed(NULL, MATTER_RECEPTION_UNSECURED, 0) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_reception_reset(&s, (Matter_Reception_Mode_T)0) == MATTER_INVALID_ARGUMENT && same(&s, &before));
    CHECK(matter_reception_seed(&s, (Matter_Reception_Mode_T)3, 0) == MATTER_INVALID_ARGUMENT && same(&s, &before));
    CHECK(matter_reception_classify(NULL, 0, &duplicate) == MATTER_INVALID_ARGUMENT && duplicate);
    CHECK(matter_reception_commit(NULL, 0, &duplicate) == MATTER_INVALID_ARGUMENT && duplicate);
    CHECK(matter_reception_reset(&s, MATTER_RECEPTION_SECURE_UNICAST) == MATTER_OK);
    before = s;
    CHECK(matter_reception_classify(&s, 0, NULL) == MATTER_INVALID_ARGUMENT && same(&s, &before));
    CHECK(matter_reception_commit(&s, 0, NULL) == MATTER_INVALID_ARGUMENT && same(&s, &before));
    CHECK(expect(&s, 0, false, 0, UINT32_MAX));
    CHECK(expect(&s, 0, true, 0, UINT32_MAX));
    CHECK(matter_reception_seed(&s, MATTER_RECEPTION_SECURE_UNICAST, 100) == MATTER_OK);
    CHECK(expect(&s, 100, true, 100, UINT32_MAX));
    CHECK(expect(&s, 68, true, 100, UINT32_MAX));
    CHECK(matter_reception_reset(&s, MATTER_RECEPTION_UNSECURED) == MATTER_OK && !s.initialized);
    CHECK(expect(&s, UINT32_MAX, false, UINT32_MAX, UINT32_MAX));
    printf("Reception state: %zu bytes, no allocations\n", sizeof(s));
    return true;
}
static bool secure_window(void) {
    Matter_Reception_T s;
    CHECK(matter_reception_seed(&s, MATTER_RECEPTION_SECURE_UNICAST, 100) == MATTER_OK);
    CHECK(expect(&s, 102, false, 102, UINT32_C(0xfffffffe)));
    CHECK(expect(&s, 101, false, 102, UINT32_MAX)); /* hole, max does not move */
    CHECK(expect(&s, 135, false, 135, 0)); /* shift 33 clears history */
    CHECK(expect(&s, 103, false, 135, UINT32_C(0x80000000)));
    CHECK(expect(&s, 104, false, 135, UINT32_C(0xc0000000)));
    CHECK(expect(&s, 134, false, 135, UINT32_C(0xc0000001)));
    CHECK(expect(&s, 102, true, 135, UINT32_C(0xc0000001)));
    CHECK(expect(&s, 167, false, 167, UINT32_C(0x80000000))); /* shift exactly 32 */
    CHECK(expect(&s, 198, false, 198, UINT32_C(0x40000000))); /* shift 31 */
    CHECK(expect(&s, 200, false, 200, 2));
    CHECK(expect(&s, 0, true, 200, 2)); /* no rollback */
    CHECK(expect(&s, UINT32_MAX, false, UINT32_MAX, 0));
    CHECK(expect(&s, UINT32_MAX - 32, false, UINT32_MAX, UINT32_C(0x80000000)));
    CHECK(expect(&s, 0, true, UINT32_MAX, UINT32_C(0x80000000))); /* no rollover */
    CHECK(matter_reception_seed(&s, MATTER_RECEPTION_SECURE_UNICAST, 0) == MATTER_OK);
    CHECK(expect(&s, UINT32_MAX, false, UINT32_MAX, 0)); /* numeric future before modulo window */
    return true;
}
static bool unsecured_window(void) {
    Matter_Reception_T s;
    CHECK(matter_reception_seed(&s, MATTER_RECEPTION_UNSECURED, UINT32_MAX - 1) == MATTER_OK);
    CHECK(expect(&s, 0, false, 0, UINT32_C(0xfffffffe)));
    CHECK(expect(&s, UINT32_MAX, false, 0, UINT32_MAX)); /* hole across wrap */
    CHECK(expect(&s, UINT32_MAX - 31, true, 0, UINT32_MAX)); /* window offset 32 */
    CHECK(expect(&s, UINT32_MAX - 32, false, UINT32_MAX - 32, 0)); /* rollback offset 33 */
    CHECK(expect(&s, 0, false, 0, 0)); /* forward 33, no retained history */
    CHECK(expect(&s, UINT32_MAX, false, 0, 1));
    CHECK(matter_reception_seed(&s, MATTER_RECEPTION_UNSECURED, 100) == MATTER_OK);
    CHECK(expect(&s, 1000, false, 1000, 0));
    CHECK(expect(&s, 5, false, 5, 0)); /* peer reboot, reset window without all-ones seed */
    CHECK(expect(&s, 4, false, 5, 1));
    CHECK(expect(&s, 4, true, 5, 1));
    CHECK(expect(&s, UINT32_MAX, false, 5, 33)); /* preceding six positions, modulo */
    CHECK(expect(&s, UINT32_C(0x80000005), false, UINT32_C(0x80000005), 0));
    CHECK(expect(&s, 5, false, 5, 0)); /* half-range jump in either direction is new */
    return true;
}
static bool readonly_and_isolation(void) {
    Matter_Reception_T a, b, before;
    bool duplicate;
    CHECK(matter_reception_reset(&a, MATTER_RECEPTION_UNSECURED) == MATTER_OK);
    CHECK(matter_reception_seed(&b, MATTER_RECEPTION_SECURE_UNICAST, 100) == MATTER_OK);
    before = a;
    CHECK(matter_reception_classify(&a, 20, &duplicate) == MATTER_OK && !duplicate && same(&a, &before));
    CHECK(matter_reception_classify(&a, 30, &duplicate) == MATTER_OK && !duplicate && same(&a, &before));
    CHECK(expect(&a, 20, false, 20, UINT32_MAX));
    CHECK(b.max_counter == 100 && b.bitmap == UINT32_MAX);
    before = a;
    for (unsigned i = 0; i < 100; ++i)
        CHECK(matter_reception_classify(&a, 30, &duplicate) == MATTER_OK && !duplicate && same(&a, &before));
    /* A stale previous classification is NOT reused: commit checks current state. */
    CHECK(expect(&a, 30, false, 30, UINT32_C(0xfffffe00)));
    CHECK(expect(&a, 30, true, 30, UINT32_C(0xfffffe00)));
    CHECK(expect(&b, 20, true, 100, UINT32_MAX));
    return true;
}

/* Independent representation: explicit history counters, no bitmap shifts.
 * Heap-owned model keeps the 33-counter array off the test call stack.
 */
typedef struct { uint32_t maximum, history[33]; size_t count; bool initialized, secure; } Model;
static bool model_receive(Model* m, uint32_t counter) {
    if (!m->initialized) {
        m->initialized = true; m->maximum = counter; m->count = 33;
        for (unsigned i = 0; i < 33; ++i) m->history[i] = counter - i;
        return false;
    }
    uint32_t back = m->maximum - counter;
    bool future = m->secure && counter > m->maximum;
    if (!future) {
        if (m->secure && back > 32) return true;
        for (size_t i = 0; i < m->count; ++i) if (m->history[i] == counter) return true;
    }
    if (future && counter - m->maximum > 32) m->count = 0;
    if (future || back > 32) m->maximum = counter;
    size_t kept = 0;
    for (size_t i = 0; i < m->count; ++i)
        if ((uint32_t)(m->maximum - m->history[i]) <= 32) m->history[kept++] = m->history[i];
    m->history[kept++] = counter; m->count = kept;
    return false;
}
static bool reference_sequences(void) {
    bool ok = true;
    Model* model = calloc(1, sizeof(*model));
    CHECK(model);
    Matter_Reception_T state;
    uint32_t random = UINT32_C(0x725ad319);
    for (unsigned mode = 1; mode <= 2 && ok; ++mode) {
        *model = (Model){.secure = mode == 2};
        ok = matter_reception_reset(&state, (Matter_Reception_Mode_T)mode) == MATTER_OK;
        for (unsigned i = 0; i < 20000 && ok; ++i) {
            random ^= random << 13; random ^= random >> 17; random ^= random << 5;
            uint32_t counter = i % 7 == 0 ? random : model->maximum + (random % 81u) - 40u;
            bool expected = model_receive(model, counter), actual;
            ok = matter_reception_commit(&state, counter, &actual) == MATTER_OK && actual == expected &&
                state.max_counter == model->maximum;
            for (unsigned j = 1; j <= 32 && ok; ++j) {
                bool present = false;
                for (size_t k = 0; k < model->count; ++k) present |= model->history[k] == model->maximum - j;
                ok = ((state.bitmap & (UINT32_C(1) << (j - 1))) != 0) == present;
            }
            if (!ok) fprintf(stderr, "model mismatch: mode %u, iteration %u\n", mode, i);
        }
    }
    free(model);
    CHECK(ok);
    return true;
}
int main(void) {
    if (!initialization_and_errors() || !secure_window() || !unsecured_window() ||
        !readonly_and_isolation() || !reference_sequences()) return 1;
    puts("PASS reception: 5 groups (40000 explicit-history comparisons)");
    return 0;
}
