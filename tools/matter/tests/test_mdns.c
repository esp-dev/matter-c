#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "matter_mdns.h"

#ifdef MATTER_TEST_ALLOC
#include "alloc.h"
static size_t live;
static bool fail_next;
void* matter_test_calloc(size_t count, size_t size) {
    if (fail_next) { fail_next = false; return NULL; }
    void* ptr = calloc(count, size);
    if (ptr) ++live;
    return ptr;
}
void matter_test_free(void* ptr) {
    if (ptr) { if (!live) abort(); --live; }
    free(ptr);
}
#endif

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d %s: %s\n", __FILE__, __LINE__, __func__, #condition); \
    goto done; } } while (0)

typedef struct { uint64_t next_binding; unsigned detached; } Backend;
typedef struct {
    Backend* backend;
    Matter_Mdns_T target;
    uint64_t binding, generation, request;
    unsigned publishes, removes, cancels, violations;
    bool pending, publishing, installed, reject;
    const Matter_Mdns_Record_T* record;
} Binding;
typedef struct { Matter_T owner; Matter_Mdns_T mdns; Binding route; } Fixture;
typedef struct { uint64_t binding, request; } Event;

static const Matter_Mdns_Txt_T txt[] = {{"fixture", "host-only"}};
static const char* const subtypes[] = {"_fixture"};
/* Arbitrary test record, deliberately not a Matter discovery payload. */
static const Matter_Mdns_Record_T record = {
    "host-test", "_fixture", "_udp", NULL, 1234, txt, 1, subtypes, 1
};

static void probe(Binding* binding) {
    Matter_Mdns_T mdns = binding->target;
    if (matter_mdns_start(mdns) != MATTER_BUSY) ++binding->violations;
    if (matter_mdns_stop(mdns) != MATTER_BUSY) ++binding->violations;
    if (matter_mdns_process(mdns) != MATTER_BUSY) ++binding->violations;
    if (matter_mdns_retry(mdns) != MATTER_BUSY) ++binding->violations;
    if (matter_mdns_delete(mdns) != MATTER_BUSY) ++binding->violations;
    if (matter_mdns_backend(mdns, binding->generation + 1, false) != MATTER_BUSY) ++binding->violations;
    if (matter_mdns_complete(mdns, binding->request, MATTER_OPERATION_SUCCEEDED) != MATTER_BUSY)
        ++binding->violations;
}

static bool publish(void* user, uint64_t request, const Matter_Mdns_Record_T* data) {
    Binding* binding = user;
    ++binding->publishes;
    binding->request = request;
    probe(binding);
    if (binding->pending || binding->installed) ++binding->violations;
    if (binding->reject) return false;
    binding->pending = true;
    binding->publishing = true;
    binding->record = data;
    return true;
}
static bool remove_record(void* user, uint64_t request) {
    Binding* binding = user;
    ++binding->removes;
    binding->request = request;
    probe(binding);
    if (binding->pending || !binding->installed) ++binding->violations;
    if (binding->reject) return false;
    binding->pending = true;
    binding->publishing = false;
    return true;
}
static void cancel(void* user, uint64_t request) {
    Binding* binding = user;
    ++binding->cancels;
    if (!binding->pending || binding->request != request) ++binding->violations;
    probe(binding);
}
static void detach(void* user) {
    Binding* binding = user;
    probe(binding);
    if (binding->pending || binding->installed || binding->record) ++binding->violations;
    binding->target = NULL;
    ++binding->backend->detached;
}
static Matter_Mdns_Port_T port_for(Binding* binding) {
    return (Matter_Mdns_Port_T){binding, publish, remove_record, cancel, detach};
}
static bool create(Fixture* fixture, Backend* backend) {
    fixture->route.backend = backend;
    fixture->route.binding = ++backend->next_binding;
    fixture->owner = matter_new(NULL);
    Matter_Mdns_Port_T port = port_for(&fixture->route);
    Matter_Mdns_Record_T copy = record;
    fixture->mdns = matter_mdns_new(fixture->owner, &port, &copy);
    fixture->route.target = fixture->mdns;
    /* Both local descriptors expire here. The pointed-to immutable data remains. */
    return fixture->mdns != NULL;
}
static Matter_Result_T availability(Fixture* fixture, bool ready) {
    Binding* binding = &fixture->route;
    binding->pending = false;
    binding->installed = false;
    binding->record = NULL;
    return matter_mdns_backend(fixture->mdns, ++binding->generation, ready);
}
static Event queued(Fixture* fixture) {
    return (Event){fixture->route.binding, fixture->route.request};
}
static bool deliver(Binding* binding, Event event, Matter_Operation_Result_T result) {
    /* Check binding BEFORE touching the target: IDs may repeat after recreation. */
    if (!binding->target || binding->binding != event.binding || !binding->pending ||
        binding->request != event.request) return false;
    binding->pending = false;
    if (result == MATTER_OPERATION_SUCCEEDED) binding->installed = binding->publishing;
    if (!binding->installed) binding->record = NULL;
    return matter_mdns_complete(binding->target, event.request, result) == MATTER_OK;
}
static bool finish(Fixture* fixture, Matter_Operation_Result_T result) {
    return deliver(&fixture->route, queued(fixture), result);
}
static bool publish_now(Fixture* fixture) {
    return matter_start(fixture->owner) == MATTER_OK &&
        matter_mdns_start(fixture->mdns) == MATTER_OK &&
        availability(fixture, true) == MATTER_OK &&
        matter_mdns_process(fixture->mdns) == MATTER_PENDING &&
        finish(fixture, MATTER_OPERATION_SUCCEEDED);
}
static void cleanup(Fixture* fixture) {
    if (fixture->mdns) {
        if (availability(fixture, false) != MATTER_OK) abort();
        matter_mdns_stop(fixture->mdns);
        if (matter_mdns_process(fixture->mdns) != MATTER_OK) abort();
        if (matter_mdns_delete(fixture->mdns) != MATTER_OK) abort();
        fixture->mdns = NULL;
    }
    matter_stop(fixture->owner);
    if (matter_delete(fixture->owner) != MATTER_OK) abort();
    fixture->owner = NULL;
}

typedef struct { Matter_Operation_Id_T id; unsigned cancels, violations; } Extra;
static void extra_cancel(void* user, Matter_Operation_Id_T id) {
    Extra* extra = user;
    ++extra->cancels;
    if (id != extra->id) ++extra->violations;
}

static bool test_mdns_and_other_operation(void) {
    bool passed = false;
    Backend backend = {0}; Fixture fixture = {0}; Extra extra = {0};
    Matter_Operation_Port_T port = {&extra, extra_cancel, NULL};
    CHECK(create(&fixture, &backend));
    for (unsigned mdns_first = 0; mdns_first < 2; ++mdns_first) {
        CHECK(publish_now(&fixture));
        CHECK(matter_operation_begin(fixture.owner, &port, &extra.id) == MATTER_OK);
        CHECK(matter_stop(fixture.owner) == MATTER_PENDING && extra.cancels == mdns_first+1);
        CHECK(matter_stop(fixture.owner) == MATTER_PENDING && extra.cancels == mdns_first+1);
        if (!mdns_first) {
            CHECK(matter_operation_complete(fixture.owner, extra.id, MATTER_OPERATION_CANCELLED) == MATTER_OK);
            extra.id = 0;
            CHECK(matter_get_state(fixture.owner) == MATTER_STATE_STOPPING);
        }
        CHECK(matter_mdns_process(fixture.mdns) == MATTER_PENDING);
        CHECK(finish(&fixture, MATTER_OPERATION_SUCCEEDED));
        CHECK(matter_mdns_process(fixture.mdns) == MATTER_OK);
        if (mdns_first) {
            CHECK(matter_get_state(fixture.owner) == MATTER_STATE_STOPPING);
            CHECK(matter_delete(fixture.owner) == MATTER_INVALID_STATE);
            CHECK(matter_operation_complete(fixture.owner, extra.id, MATTER_OPERATION_FAILED) == MATTER_OK);
            extra.id = 0;
        }
        CHECK(matter_get_state(fixture.owner) == MATTER_STATE_STOPPED);
        CHECK(!matter_mdns_is_active(fixture.mdns) && !fixture.route.installed);
    }
    CHECK(extra.violations == 0 && fixture.route.violations == 0);
    passed = true;
done:
    if (extra.id) matter_operation_complete(fixture.owner, extra.id, MATTER_OPERATION_CANCELLED);
    cleanup(&fixture);
    return passed;
}

static bool test_validation_and_offline(void) {
    bool passed = false;
    Backend backend = {0}; Fixture fixture = {0};
    CHECK(matter_mdns_new(NULL, NULL, NULL) == NULL);
    CHECK(matter_mdns_delete(NULL) == MATTER_OK);
    CHECK(matter_mdns_start(NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_mdns_stop(NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_mdns_process(NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_mdns_retry(NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_mdns_backend(NULL, 1, true) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_mdns_complete(NULL, 1, MATTER_OPERATION_FAILED) == MATTER_INVALID_ARGUMENT);
    CHECK(!matter_mdns_is_active(NULL) && !matter_mdns_is_published(NULL));
    CHECK(create(&fixture, &backend));
    Matter_Mdns_Port_T bad = port_for(&fixture.route); bad.cancel = NULL;
    CHECK(!matter_mdns_new(fixture.owner, &bad, &record));
    CHECK(matter_mdns_start(fixture.mdns) == MATTER_INVALID_STATE);
    CHECK(matter_start(fixture.owner) == MATTER_OK);
    CHECK(matter_mdns_start(fixture.mdns) == MATTER_OK);
    CHECK(matter_mdns_start(fixture.mdns) == MATTER_OK);
    CHECK(matter_mdns_delete(fixture.mdns) == MATTER_INVALID_STATE);
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PENDING && fixture.route.publishes == 0);
    CHECK(matter_mdns_backend(fixture.mdns, 0, true) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_stop(fixture.owner) == MATTER_PENDING);
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_OK);
    CHECK(matter_get_state(fixture.owner) == MATTER_STATE_STOPPED);
    CHECK(!matter_mdns_is_active(fixture.mdns));
    passed = true;
done: cleanup(&fixture); return passed;
}

static bool test_publication_lifetime_and_remove(void) {
    bool passed = false;
    Backend backend = {0}; Fixture fixture = {0};
    CHECK(create(&fixture, &backend) && publish_now(&fixture));
    CHECK(matter_mdns_is_published(fixture.mdns));
    CHECK(strcmp(fixture.route.record->txt[0].value, "host-only") == 0);
    CHECK(strcmp(fixture.route.record->subtypes[0], "_fixture") == 0);
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_OK && fixture.route.publishes == 1);
    CHECK(matter_stop(fixture.owner) == MATTER_PENDING);
    CHECK(matter_delete(fixture.owner) == MATTER_INVALID_STATE);
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PENDING && fixture.route.removes == 1);
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PENDING && fixture.route.cancels == 0);
    CHECK(finish(&fixture, MATTER_OPERATION_SUCCEEDED));
    CHECK(!matter_mdns_is_published(fixture.mdns));
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_OK);
    CHECK(matter_get_state(fixture.owner) == MATTER_STATE_STOPPED);
    CHECK(fixture.route.violations == 0);
    passed = true;
done: cleanup(&fixture); return passed;
}

static bool test_stop_during_publish(void) {
    bool passed = false;
    Backend backend = {0}; Fixture fixture = {0};
    CHECK(create(&fixture, &backend));
    CHECK(matter_start(fixture.owner) == MATTER_OK && availability(&fixture, true) == MATTER_OK);
    CHECK(matter_mdns_start(fixture.mdns) == MATTER_OK);
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PENDING);
    CHECK(matter_stop(fixture.owner) == MATTER_PENDING);
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PENDING);
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PENDING && fixture.route.cancels == 1);
    CHECK(matter_mdns_start(fixture.mdns) == MATTER_INVALID_STATE);
    /* Publication won the cancellation race: it still must be removed. */
    CHECK(finish(&fixture, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PENDING && fixture.route.removes == 1);
    CHECK(finish(&fixture, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_OK);
    CHECK(matter_start(fixture.owner) == MATTER_OK && matter_mdns_start(fixture.mdns) == MATTER_OK);
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PENDING);
    CHECK(matter_mdns_stop(fixture.mdns) == MATTER_PENDING);
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PENDING);
    CHECK(finish(&fixture, MATTER_OPERATION_CANCELLED));
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_OK && fixture.route.removes == 1);
    CHECK(matter_get_state(fixture.owner) == MATTER_STATE_RUNNING && fixture.route.violations == 0);
    CHECK(matter_mdns_start(fixture.mdns) == MATTER_OK);
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PENDING);
    CHECK(matter_stop(fixture.owner) == MATTER_PENDING);
    CHECK(finish(&fixture, MATTER_OPERATION_FAILED));
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PORT_ERROR);
    CHECK(!matter_mdns_is_active(fixture.mdns) && matter_get_state(fixture.owner) == MATTER_STATE_STOPPED);
    passed = true;
done: cleanup(&fixture); return passed;
}

static bool test_backend_restart_and_late_results(void) {
    bool passed = false;
    Backend backend = {0}; Fixture fixture = {0};
    CHECK(create(&fixture, &backend) && publish_now(&fixture));
    CHECK(availability(&fixture, false) == MATTER_OK);
    CHECK(!matter_mdns_is_published(fixture.mdns));
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PENDING && fixture.route.publishes == 1);
    CHECK(availability(&fixture, true) == MATTER_OK);
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PENDING);
    Event old = queued(&fixture);
    CHECK(availability(&fixture, false) == MATTER_OK); /* Lose an in-flight publish. */
    CHECK(availability(&fixture, true) == MATTER_OK);
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PENDING);
    CHECK(!deliver(&fixture.route, old, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_mdns_complete(fixture.mdns, old.request, MATTER_OPERATION_SUCCEEDED) == MATTER_INVALID_STATE);
    CHECK(matter_mdns_backend(fixture.mdns, fixture.route.generation - 1, false) == MATTER_INVALID_STATE);
    CHECK(matter_mdns_complete(fixture.mdns, 0, MATTER_OPERATION_SUCCEEDED) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_mdns_complete(fixture.mdns, fixture.route.request, (Matter_Operation_Result_T)99) == MATTER_INVALID_ARGUMENT);
    CHECK(finish(&fixture, MATTER_OPERATION_SUCCEEDED) && fixture.route.publishes == 3);
    CHECK(matter_mdns_stop(fixture.mdns) == MATTER_PENDING);
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PENDING); /* Removing. */
    CHECK(availability(&fixture, false) == MATTER_OK);
    CHECK(availability(&fixture, true) == MATTER_OK);
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_OK && fixture.route.publishes == 3);
    CHECK(fixture.route.violations == 0);
    passed = true;
done: cleanup(&fixture); return passed;
}

static bool test_failures_require_retry(void) {
    bool passed = false;
    Backend backend = {0}; Fixture fixture = {0};
    CHECK(create(&fixture, &backend));
    CHECK(matter_start(fixture.owner) == MATTER_OK && matter_mdns_start(fixture.mdns) == MATTER_OK);
    CHECK(availability(&fixture, true) == MATTER_OK);
    fixture.route.reject = true;
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PORT_ERROR);
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PORT_ERROR && fixture.route.publishes == 1);
    fixture.route.reject = false;
    CHECK(matter_mdns_retry(fixture.mdns) == MATTER_OK);
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PENDING);
    CHECK(matter_mdns_retry(fixture.mdns) == MATTER_BUSY);
    CHECK(finish(&fixture, MATTER_OPERATION_FAILED));
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PORT_ERROR);
    CHECK(matter_mdns_retry(fixture.mdns) == MATTER_OK);
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PENDING && finish(&fixture, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_stop(fixture.owner) == MATTER_PENDING);
    fixture.route.reject = true;
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PORT_ERROR);
    CHECK(matter_mdns_is_published(fixture.mdns) && matter_delete(fixture.owner) == MATTER_INVALID_STATE);
    fixture.route.reject = false;
    CHECK(matter_mdns_retry(fixture.mdns) == MATTER_OK);
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PENDING && finish(&fixture, MATTER_OPERATION_FAILED));
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PORT_ERROR && fixture.route.installed);
    CHECK(matter_mdns_retry(fixture.mdns) == MATTER_OK);
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PENDING && finish(&fixture, MATTER_OPERATION_CANCELLED));
    unsigned remove_count = fixture.route.removes;
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PORT_ERROR);
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PORT_ERROR && fixture.route.removes == remove_count);
    CHECK(matter_mdns_retry(fixture.mdns) == MATTER_OK);
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_PENDING && finish(&fixture, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_mdns_process(fixture.mdns) == MATTER_OK && fixture.route.violations == 0);
    passed = true;
done: cleanup(&fixture); return passed;
}

static bool test_shared_backend_and_recreated_context(void) {
    bool passed = false;
    Backend backend = {0}; Fixture first = {0}, second = {0};
    CHECK(create(&first, &backend) && create(&second, &backend));
    CHECK(publish_now(&first) && publish_now(&second));
    Event old = queued(&first);
    CHECK(matter_mdns_stop(first.mdns) == MATTER_PENDING);
    CHECK(matter_mdns_process(first.mdns) == MATTER_PENDING && finish(&first, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_mdns_process(first.mdns) == MATTER_OK);
    CHECK(matter_mdns_delete(first.mdns) == MATTER_OK); first.mdns = NULL;
    CHECK(!deliver(&first.route, old, MATTER_OPERATION_SUCCEEDED));
    CHECK(second.route.installed && matter_mdns_is_published(second.mdns));
    CHECK(backend.detached == 1 && first.route.violations == 0);
    cleanup(&first);
    /* Reuse same adapter storage with fresh binding; request counter restarts. */
    first = (Fixture){0};
    CHECK(create(&first, &backend));
    CHECK(matter_start(first.owner) == MATTER_OK && matter_mdns_start(first.mdns) == MATTER_OK);
    CHECK(availability(&first, true) == MATTER_OK && matter_mdns_process(first.mdns) == MATTER_PENDING);
    CHECK(first.route.request == old.request && first.route.binding != old.binding);
    CHECK(!deliver(&first.route, old, MATTER_OPERATION_SUCCEEDED));
    CHECK(!matter_mdns_is_published(first.mdns) && first.route.pending);
    CHECK(finish(&first, MATTER_OPERATION_SUCCEEDED));
    CHECK(second.route.installed && second.route.removes == 0 && second.route.violations == 0);
    passed = true;
done: cleanup(&first); cleanup(&second); return passed;
}

#ifdef MATTER_TEST_ALLOC
static bool test_oom(void) {
    bool passed = false;
    Backend backend = {0}; Fixture fixture = {0};
    fixture.route.backend = &backend;
    fixture.owner = matter_new(NULL);
    CHECK(fixture.owner != NULL);
    Matter_Mdns_Port_T port = port_for(&fixture.route);
    fail_next = true;
    fixture.mdns = matter_mdns_new(fixture.owner, &port, &record);
    CHECK(!fixture.mdns && !fail_next && live == 1 && backend.detached == 0);
    CHECK(matter_get_state(fixture.owner) == MATTER_STATE_STOPPED);
    passed = true;
done: fail_next = false; cleanup(&fixture); return passed;
}
#endif

int main(void) {
    const struct { const char* name; bool (*run)(void); } tests[] = {
        {"validation/offline", test_validation_and_offline},
        {"publication lease and remove", test_publication_lifetime_and_remove},
        {"stop during publication", test_stop_during_publish},
        {"backend restart and stale events", test_backend_restart_and_late_results},
        {"failures and explicit retry", test_failures_require_retry},
        {"shared backend and new binding", test_shared_backend_and_recreated_context},
        {"mDNS alongside another operation", test_mdns_and_other_operation},
#ifdef MATTER_TEST_ALLOC
        {"allocation failure", test_oom},
#endif
    };
    unsigned failures = 0;
    size_t count = sizeof(tests) / sizeof(tests[0]);
    for (size_t i = 0; i < count; ++i) {
        bool passed = tests[i].run();
#ifdef MATTER_TEST_ALLOC
        if (live) { fprintf(stderr, "Unreleased allocations: %zu\n", live); passed = false; }
#endif
        printf("%s mdns: %s\n", passed ? "PASS" : "FAIL", tests[i].name);
        if (!passed) ++failures;
    }
    printf("%zu/%zu mdns tests passed\n", count - failures, count);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
