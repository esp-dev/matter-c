#include <stdio.h>
#include <stdlib.h>
#include "transport/matter_unsecured.h"

#ifdef MATTER_TEST_ALLOC
static size_t live, allocations, last_size;
static bool fail_next;
void* matter_test_calloc(size_t count, size_t size) {
    if (fail_next) { fail_next = false; return NULL; }
    void* p = calloc(count, size);
    if (p) { ++live; ++allocations; last_size = count * size; }
    return p;
}
void matter_test_free(void* p) {
    if (p) { if (!live) abort(); --live; }
    free(p);
}
#endif
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #c); goto done; } } while (0)

/* Test cleanup only: production callers must drain their actual consumers. */
static void cleanup(Matter_Unsecured_T t, uint64_t first, uint64_t last) {
    if (!t) return;
    for (uint64_t id = first;; ++id) {
        Matter_Unsecured_Info_T info;
        if (matter_unsecured_get(t, id, &info) == MATTER_OK) {
            for (unsigned i = 0; i < info.pins; ++i)
                if (matter_unsecured_unpin(t, id) != MATTER_OK) abort();
            if (matter_unsecured_remove(t, id) != MATTER_OK) abort();
        }
        if (id == last) break;
    }
    if (matter_unsecured_delete(t) != MATTER_OK) abort();
}
typedef struct {
    uint64_t samples[8];
    unsigned count, calls, violations;
    Matter_Result_T result;
    Matter_Unsecured_T reenter;
    bool omit;
} Random;
static Matter_Result_T random64(void* user, uint64_t* sample) {
    Random* r = user;
    unsigned i = r->calls++;
    if (!r->omit) *sample = r->samples[i < r->count ? i : r->count - 1];
    if (r->reenter) {
        Matter_Exchange_Session_T token = 99;
        Matter_Unsecured_Info_T info = {88, 77, true};
        Matter_Message_Header_T h = {.message_flags = MATTER_MESSAGE_SOURCE_PRESENT, .source_node_id = 1};
        bool dup = true;
        if (matter_unsecured_initiate(r->reenter, random64, r, &token) != MATTER_BUSY ||
            matter_unsecured_resolve(r->reenter, &h, true, &token) != MATTER_BUSY ||
            matter_unsecured_delete(r->reenter) != MATTER_BUSY ||
            matter_unsecured_get(r->reenter, 1, &info) != MATTER_BUSY ||
            matter_unsecured_pin(r->reenter, 1) != MATTER_BUSY ||
            matter_unsecured_unpin(r->reenter, 1) != MATTER_BUSY ||
            matter_unsecured_remove(r->reenter, 1) != MATTER_BUSY ||
            matter_unsecured_classify(r->reenter, 1, 0, &dup) != MATTER_BUSY ||
            matter_unsecured_commit(r->reenter, 1, 0, &dup) != MATTER_BUSY ||
            token != 99 || info.ephemeral_node_id != 88 || info.pins != 77 || !info.initiator || !dup)
            ++r->violations;
    }
    return r->result;
}
static bool matching_and_roles(void) {
    bool ok = false;
    Matter_Unsecured_T t = matter_unsecured_new(1, 100);
    /* Independent wire literal: unsecured, counter 7, source ID 0x123456789abcdef0. */
    static const uint8_t wire[] = {4,0,0,0,7,0,0,0,0xf0,0xde,0xbc,0x9a,0x78,0x56,0x34,0x12};
    Matter_Message_Header_T h;
    Matter_Unsecured_Info_T info;
    Matter_Exchange_Session_T token = 99;
    size_t used = 0;
    Random r = {.samples = {1}, .count = 1};
    CHECK(t && matter_message_header_read(wire, sizeof(wire), &h, &used) == MATTER_MESSAGE_OK && used == 16);
    CHECK(matter_unsecured_resolve(t, &h, false, &token) == MATTER_INVALID_STATE && token == 99);
    CHECK(matter_unsecured_resolve(t, &h, true, &token) == MATTER_OK && token == 1);
    CHECK(matter_unsecured_get(t, token, &info) == MATTER_OK && !info.initiator && !info.pins &&
        info.ephemeral_node_id == UINT64_C(0x123456789abcdef0));
    CHECK(matter_unsecured_resolve(t, &h, false, &token) == MATTER_OK && token == 1);
    h.message_flags = MATTER_MESSAGE_DESTINATION_NODE; h.destination_id = h.source_node_id;
    /* Matching is by ID; lookup never silently switches the recorded role. */
    CHECK(matter_unsecured_resolve(t, &h, true, &token) == MATTER_OK && token == 1);
    CHECK(matter_unsecured_get(t, token, &info) == MATTER_OK && !info.initiator);
    h.destination_id = 1;
    CHECK(matter_unsecured_resolve(t, &h, true, &token) == MATTER_INVALID_STATE && token == 1);
    CHECK(matter_unsecured_initiate(t, random64, &r, &token) == MATTER_OK && token == 2);
    CHECK(matter_unsecured_resolve(t, &h, false, &token) == MATTER_OK && token == 2);
    CHECK(matter_unsecured_get(t, token, &info) == MATTER_OK && info.initiator && info.ephemeral_node_id == 1);
    CHECK(matter_unsecured_delete(t) == MATTER_INVALID_STATE);
    ok = true;
done: cleanup(t, 1, 100); return ok;
}
static bool rng_and_collisions(void) {
    bool ok = false;
    Matter_Unsecured_T t = matter_unsecured_new(1, 100);
    Matter_Exchange_Session_T token = 99;
    Matter_Unsecured_Info_T info;
    Random r = {.samples = {0, UINT64_MAX, UINT64_C(0xfffffff000000000), 1}, .count = 4, .reenter = t};
    CHECK(t && matter_unsecured_initiate(t, random64, &r, &token) == MATTER_OK && token == 1);
    CHECK(r.calls == 4 && !r.violations);
    r = (Random){.samples = {1}, .count = 1, .reenter = t};
    CHECK(matter_unsecured_initiate(t, random64, &r, &token) == MATTER_LIMIT_REACHED && token == 1);
    CHECK(r.calls == MATTER_UNSECURED_RANDOM_ATTEMPTS && !r.violations);
    r = (Random){.samples = {UINT64_C(0xffffffefffffffff)}, .count = 1};
    CHECK(matter_unsecured_initiate(t, random64, &r, &token) == MATTER_OK && token == 2);
    CHECK(matter_unsecured_get(t, token, &info) == MATTER_OK && info.ephemeral_node_id == UINT64_C(0xffffffefffffffff));
    Matter_Message_Header_T h = {.message_flags = 4, .source_node_id = 2};
    CHECK(matter_unsecured_resolve(t, &h, true, &token) == MATTER_OK && token == 3);
    r = (Random){.samples = {1, 2, 3}, .count = 3}; /* Collisions with both roles. */
    CHECK(matter_unsecured_initiate(t, random64, &r, &token) == MATTER_OK && token == 4 && r.calls == 3);
    static const Matter_Result_T errors[] = {MATTER_WOULD_BLOCK, MATTER_OFFLINE, MATTER_PORT_ERROR, MATTER_PENDING};
    for (unsigned i = 0; i < 4; ++i) {
        r = (Random){.samples = {4}, .count = 1, .result = errors[i], .reenter = t};
        CHECK(matter_unsecured_initiate(t, random64, &r, &token) == (i == 3 ? MATTER_PORT_ERROR : errors[i]));
        CHECK(token == 4 && r.calls == 1 && !r.violations);
    }
    r = (Random){.count = 1, .omit = true};
    CHECK(matter_unsecured_initiate(t, random64, &r, &token) == MATTER_LIMIT_REACHED && token == 4);
    CHECK(r.calls == MATTER_UNSECURED_RANDOM_ATTEMPTS);
    r = (Random){.samples = {4}, .count = 1};
    CHECK(matter_unsecured_initiate(t, random64, &r, &token) == MATTER_OK && token == 5);
    ok = true;
done: cleanup(t, 1, 100); return ok;
}
static bool headers_and_arguments(void) {
    bool ok = false;
    Matter_Unsecured_T t = matter_unsecured_new(1, 100);
    Matter_Exchange_Session_T token = 99;
    Matter_Unsecured_Info_T info = {88, 77, true};
    Matter_Message_Header_T h = {.source_node_id = 1, .message_flags = 4};
    Random r = {.samples = {1}, .count = 1};
    bool duplicate = true;
    CHECK(t && !matter_unsecured_new(0, 1) && !matter_unsecured_new(2, 1));
    CHECK(matter_unsecured_delete(NULL) == MATTER_OK);
    CHECK(matter_unsecured_initiate(NULL, random64, &r, &token) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_unsecured_initiate(t, NULL, &r, &token) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_unsecured_initiate(t, random64, &r, NULL) == MATTER_INVALID_ARGUMENT && !r.calls);
    CHECK(matter_unsecured_resolve(t, NULL, true, &token) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_unsecured_resolve(t, &h, true, NULL) == MATTER_INVALID_ARGUMENT);
    /* Invalid version, absent/both/group/reserved destination. */
    static const uint8_t flags[] = {0x14, 0, 5, 2, 6, 3};
    for (unsigned i = 0; i < sizeof(flags); ++i) {
        h.message_flags = flags[i]; h.destination_id = 1;
        CHECK(matter_unsecured_resolve(t, &h, true, &token) == MATTER_INVALID_ARGUMENT && token == 99);
    }
    h.message_flags = 4;
    static const uint8_t security[] = {1, 2, 3, 0x40, 0x80};
    for (unsigned i = 0; i < sizeof(security); ++i) {
        h.security_flags = security[i];
        CHECK(matter_unsecured_resolve(t, &h, true, &token) == MATTER_INVALID_ARGUMENT && token == 99);
    }
    h.security_flags = 0; h.session_id = 1;
    CHECK(matter_unsecured_resolve(t, &h, true, &token) == MATTER_INVALID_ARGUMENT);
    h.session_id = 0;
    static const uint64_t invalid[] = {0, UINT64_C(0xfffffff000000000), UINT64_MAX};
    for (unsigned i = 0; i < 3; ++i) {
        h.source_node_id = h.destination_id = invalid[i];
        h.message_flags = 4;
        CHECK(matter_unsecured_resolve(t, &h, true, &token) == MATTER_INVALID_ARGUMENT);
        h.message_flags = 1;
        CHECK(matter_unsecured_resolve(t, &h, true, &token) == MATTER_INVALID_ARGUMENT);
    }
    CHECK(token == 99);
    h = (Matter_Message_Header_T){.source_node_id = 1, .message_flags = 0x0c, .security_flags = 0x3c};
    CHECK(matter_unsecured_resolve(t, &h, true, &token) == MATTER_OK && token == 1); /* Reserved bits ignored; parsed MX. */
    CHECK(matter_unsecured_get(t, 0, &info) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_unsecured_get(t, 2, &info) == MATTER_INVALID_STATE && info.ephemeral_node_id == 88 && info.pins == 77);
    CHECK(matter_unsecured_get(t, 1, NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_unsecured_pin(NULL, 1) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_unsecured_unpin(t, 0) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_unsecured_remove(t, 0) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_unsecured_classify(t, 1, 7, &duplicate) == MATTER_INVALID_STATE && duplicate);
    CHECK(matter_unsecured_commit(t, 1, 7, &duplicate) == MATTER_INVALID_STATE && duplicate);
    CHECK(matter_unsecured_pin(t, 1) == MATTER_OK);
    CHECK(matter_unsecured_classify(t, 1, 7, NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_unsecured_commit(t, 1, 7, NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_unsecured_classify(t, 1, 7, &duplicate) == MATTER_OK && !duplicate);
    ok = true;
done: cleanup(t, 1, 100); return ok;
}
static bool capacity_and_tokens(void) {
    bool ok = false;
    Matter_Unsecured_T t = matter_unsecured_new(1, 100);
    Matter_Unsecured_T end = matter_unsecured_new(UINT64_MAX - 1, UINT64_MAX);
    Matter_Exchange_Session_T token = 99;
    Random r = {.samples = {1}, .count = 1};
    Matter_Unsecured_Info_T info;
    bool duplicate = true;
    CHECK(t && end);
    for (unsigned i = 1; i <= MATTER_UNSECURED_CAPACITY; ++i) {
        r.samples[0] = i;
        CHECK(matter_unsecured_initiate(t, random64, &r, &token) == MATTER_OK && token == i);
    }
    unsigned calls = r.calls;
    CHECK(matter_unsecured_initiate(t, random64, &r, &token) == MATTER_BUSY && r.calls == calls);
    Matter_Message_Header_T h = {.message_flags = 4, .source_node_id = 99};
    CHECK(matter_unsecured_resolve(t, &h, true, &token) == MATTER_BUSY && token == 8);
    h.source_node_id = 1;
    CHECK(matter_unsecured_resolve(t, &h, true, &token) == MATTER_OK && token == 1);
    CHECK(matter_unsecured_remove(t, 3) == MATTER_OK);
    r.samples[0] = 3;
    CHECK(matter_unsecured_initiate(t, random64, &r, &token) == MATTER_OK && token == 9);
    CHECK(matter_unsecured_get(t, 3, &info) == MATTER_INVALID_STATE);
    CHECK(matter_unsecured_pin(t, 3) == MATTER_INVALID_STATE);
    CHECK(matter_unsecured_unpin(t, 3) == MATTER_INVALID_STATE);
    CHECK(matter_unsecured_remove(t, 3) == MATTER_INVALID_STATE);
    CHECK(matter_unsecured_commit(t, 3, 1, &duplicate) == MATTER_INVALID_STATE && duplicate);
    CHECK(matter_unsecured_classify(t, 3, 1, &duplicate) == MATTER_INVALID_STATE && duplicate);
    CHECK(matter_unsecured_initiate(end, random64, &r, &token) == MATTER_OK && token == UINT64_MAX - 1);
    h.source_node_id = 1;
    CHECK(matter_unsecured_resolve(end, &h, true, &token) == MATTER_OK && token == UINT64_MAX);
    CHECK(matter_unsecured_resolve(end, &h, false, &token) == MATTER_OK && token == UINT64_MAX);
    CHECK(matter_unsecured_remove(end, UINT64_MAX - 1) == MATTER_OK);
    calls = r.calls;
    CHECK(matter_unsecured_initiate(end, random64, &r, &token) == MATTER_LIMIT_REACHED && r.calls == calls && token == UINT64_MAX);
    h.source_node_id = 2;
    CHECK(matter_unsecured_resolve(end, &h, true, &token) == MATTER_LIMIT_REACHED && token == UINT64_MAX);
    ok = true;
done: cleanup(t, 1, 100); cleanup(end, UINT64_MAX - 1, UINT64_MAX); return ok;
}
static bool retention_reception_and_isolation(void) {
    bool ok = false, dup = true;
    Matter_Unsecured_T a = matter_unsecured_new(1, 100), b = matter_unsecured_new(101, 200);
    Matter_Exchange_Session_T token;
    Matter_Unsecured_Info_T info;
    Matter_Message_Header_T h = {.message_flags = 4, .source_node_id = 1};
    CHECK(a && b && matter_unsecured_resolve(a, &h, true, &token) == MATTER_OK && token == 1);
    CHECK(matter_unsecured_resolve(b, &h, true, &token) == MATTER_OK && token == 101);
    CHECK(matter_unsecured_pin(a, 1) == MATTER_OK && matter_unsecured_pin(b, 101) == MATTER_OK);
    CHECK(matter_unsecured_pin(a, 1) == MATTER_OK); /* exchange + in-flight I/O */
    CHECK(matter_unsecured_classify(a, 1, UINT32_MAX, &dup) == MATTER_OK && !dup);
    CHECK(matter_unsecured_classify(a, 1, UINT32_MAX, &dup) == MATTER_OK && !dup); /* Rejected RX did not commit. */
    CHECK(matter_unsecured_commit(a, 1, UINT32_MAX, &dup) == MATTER_OK && !dup);
    CHECK(matter_unsecured_classify(a, 1, UINT32_MAX, &dup) == MATTER_OK && dup);
    CHECK(matter_unsecured_classify(b, 101, UINT32_MAX, &dup) == MATTER_OK && !dup);
    CHECK(matter_unsecured_commit(a, 1, 0, &dup) == MATTER_OK && !dup); /* Unsecured wraps. */
    CHECK(matter_unsecured_remove(a, 1) == MATTER_BUSY);
    CHECK(matter_unsecured_unpin(a, 1) == MATTER_OK && matter_unsecured_remove(a, 1) == MATTER_BUSY);
    CHECK(matter_unsecured_delete(a) == MATTER_INVALID_STATE);
    CHECK(matter_unsecured_resolve(a, &h, false, &token) == MATTER_OK && token == 1); /* Control RX during drain. */
    CHECK(matter_unsecured_commit(a, 1, 0, &dup) == MATTER_OK && dup);
    CHECK(matter_unsecured_unpin(a, 1) == MATTER_OK);
    CHECK(matter_unsecured_unpin(a, 1) == MATTER_INVALID_STATE);
    CHECK(matter_unsecured_remove(a, 1) == MATTER_OK);
    CHECK(matter_unsecured_resolve(a, &h, true, &token) == MATTER_OK && token == 2);
    CHECK(matter_unsecured_pin(a, 2) == MATTER_OK);
    CHECK(matter_unsecured_classify(a, 2, 0, &dup) == MATTER_OK && !dup); /* New context, fresh window. */
    for (unsigned i = 1; i < UINT16_MAX; ++i) CHECK(matter_unsecured_pin(a, 2) == MATTER_OK);
    CHECK(matter_unsecured_pin(a, 2) == MATTER_LIMIT_REACHED);
    CHECK(matter_unsecured_get(a, 2, &info) == MATTER_OK && info.pins == UINT16_MAX);
    for (unsigned i = 0; i < UINT16_MAX; ++i) CHECK(matter_unsecured_unpin(a, 2) == MATTER_OK);
    CHECK(matter_unsecured_unpin(a, 2) == MATTER_INVALID_STATE);
    CHECK(matter_unsecured_get(b, 101, &info) == MATTER_OK && info.pins == 1);
    ok = true;
done: cleanup(a, 1, 100); cleanup(b, 101, 200); return ok;
}
#ifdef MATTER_TEST_ALLOC
static bool allocation_failures(void) {
    bool ok = false;
    Matter_Unsecured_T t = NULL;
    Matter_Exchange_Session_T token;
    Random r = {.samples = {1}, .count = 1};
    fail_next = true;
    CHECK(!matter_unsecured_new(1, 100) && !live);
    size_t before = allocations;
    t = matter_unsecured_new(1, 100);
    CHECK(t && allocations == before + 1 && live == 1);
    printf("Unsecured table: %zu bytes, one allocation\n", last_size);
    fail_next = true;
    for (unsigned i = 0; i < 100; ++i) {
        CHECK(matter_unsecured_initiate(t, random64, &r, &token) == MATTER_OK && token == i + 1);
        CHECK(matter_unsecured_pin(t, token) == MATTER_OK && matter_unsecured_unpin(t, token) == MATTER_OK);
        CHECK(matter_unsecured_remove(t, token) == MATTER_OK);
    }
    CHECK(fail_next && allocations == before + 1); /* No allocation per context/message. */
    ok = true;
done: fail_next = false; cleanup(t, 1, 100); return ok;
}
#endif
int main(void) {
    unsigned passed = 0;
#define RUN(t) do { if (!(t)()) return 1; ++passed; } while (0)
    RUN(matching_and_roles); RUN(rng_and_collisions); RUN(headers_and_arguments);
    RUN(capacity_and_tokens); RUN(retention_reception_and_isolation);
#ifdef MATTER_TEST_ALLOC
    RUN(allocation_failures);
    if (live) abort();
#endif
    printf("PASS unsecured: %u groups\n", passed); return 0;
}
