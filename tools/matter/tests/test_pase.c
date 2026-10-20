/* Reuse the exercised transport fixture without copying RX/MRP/UDP wiring.
 * Original tests remain compiled and run by their normal runner targets. */
#define MATTER_TEST_PASE 1
#define main mrp_regression_main
#include "test_mrp_pair.c"
#undef main
#include "crypto/matter_crypto_mbedtls.h"
#ifdef MATTER_TEST_SECURE_EXHAUSTION
/* Additional host target only: advance a private counter to its final value.
 * The normal host target links the production object; no reset API is exported. */
#ifdef MATTER_TEST_ALLOC
#define calloc matter_test_calloc
#define free matter_test_free
#endif
#include "../../../main/apps/matter/session/matter_secure.c"
#ifdef MATTER_TEST_ALLOC
#undef calloc
#undef free
#endif
#endif

typedef struct {
    Matter_Crypto_Mbedtls_T crypto;
    Matter_Crypto_Port_T port;
    Matter_Pase_Config_T config[2];
    Matter_Pase_T s[2];
    Matter_Pase_Keys_T keys[2];
    uint8_t wide[80], w1[32], pin[4], buffer[1024];
    Pair* link;
    unsigned im_reads;
    bool im_denied;
    bool im_close_wait;
    bool invoke_close;
    bool timed_close;
    unsigned write_close;
    bool write_list_close;
    bool subscribe_close;
    bool commissioning_expiry;
    bool wifi_commissioning;
    bool opcreds_commissioning, fabric_commissioning;
    unsigned failures[2];
} PaseFixture;
static void failed_attempt(void* u,uint64_t token) {
    PaseFixture* f=u; REQUIRE(token>=100 && token<=101); ++f->failures[token-100];
}
static Matter_Pase_T new_pase(PaseFixture* f, unsigned i) {
    Matter_Pase_T s = matter_pase_new(&f->port, &f->config[i], 0);
#ifdef MATTER_TEST_ALLOC
    if (s) {
        REQUIRE(last_alloc == s && !pase_allocations[i].p);
        pase_allocations[i].p = s; pase_allocations[i].size = last_alloc_size;
    }
#endif
    return s;
}
static void dispose(PaseFixture* f) {
    if (!f) return;
    if (f->link) { f->link->a.pase = f->link->b.pase = NULL; cleanup(f->link); }
    REQUIRE(matter_pase_delete(f->s[0]) == MATTER_OK && matter_pase_delete(f->s[1]) == MATTER_OK);
    REQUIRE(matter_crypto_mbedtls_delete(f->crypto) == MATTER_OK);
    memset(f, 0, sizeof(*f)); free(f);
}
static PaseFixture* setup(bool known, bool bad_pin) {
    PaseFixture* f = calloc(1, sizeof(*f)); REQUIRE(f);
    f->crypto = matter_crypto_mbedtls_new(NULL); REQUIRE(f->crypto);
    REQUIRE(matter_crypto_mbedtls_port(f->crypto, &f->port) == MATTER_OK);
    f->config[0] = (Matter_Pase_Config_T){.local_session_id = 123, .pin = 20202021,
        .iterations = 1000, .salt_size = 16, .timeout_ms = 30000, .has_parameters = known};
    memset(f->config[0].salt, 0x42, 16);
    f->config[1] = f->config[0]; f->config[1].responder = true; f->config[1].local_session_id = 456;
    for (unsigned i = 0; i < 4; ++i) f->pin[i] = (uint8_t)(f->config[0].pin >> (8*i));
    REQUIRE(f->port.pbkdf2_sha256(f->port.user, f->pin, 4, f->config[1].salt, 16, 1000, f->wide, 80) == MATTER_OK);
    REQUIRE(f->port.p256_reduce(f->port.user, f->wide, 40, f->config[1].w0) == MATTER_OK);
    REQUIRE(f->port.p256_reduce(f->port.user, f->wide + 40, 40, f->w1) == MATTER_OK);
    REQUIRE(f->port.p256_base(f->port.user, f->w1, 32, f->config[1].L) == MATTER_OK);
    if (bad_pin) ++f->config[0].pin;
    for (unsigned i = 0; i < 2; ++i) {
        f->s[i] = new_pase(f, i); REQUIRE(f->s[i]);
        REQUIRE(matter_pase_on_failure(f->s[i],f,100+i,failed_attempt)==MATTER_OK);
        REQUIRE(matter_pase_on_failure(f->s[i],f,100+i,failed_attempt)==MATTER_INVALID_STATE);
    }
    return f;
}
static bool same_keys(PaseFixture* f) {
    bool ok = false;
    for (unsigned i = 0; i < 2; ++i) CHECK(matter_pase_keys(f->s[i], &f->keys[i]) == MATTER_OK);
    CHECK(f->keys[0].local_session_id == 123 && f->keys[0].peer_session_id == 456);
    CHECK(f->keys[1].local_session_id == 456 && f->keys[1].peer_session_id == 123);
    CHECK(!memcmp(f->keys[0].send_key, f->keys[1].receive_key, 16));
    CHECK(!memcmp(f->keys[1].send_key, f->keys[0].receive_key, 16));
    CHECK(!memcmp(f->keys[0].attestation_challenge, f->keys[1].attestation_challenge, 16));
    CHECK(memcmp(f->keys[0].send_key, f->keys[0].receive_key, 16));
    CHECK(memcmp(f->keys[0].send_key, f->keys[0].attestation_challenge, 16));
    ok = true;
done: return ok;
}
static bool direct(PaseFixture* f, unsigned from, uint64_t now) {
    Matter_Pase_Message_T m;
    if (matter_pase_process(f->s[from], now) != MATTER_PENDING || matter_pase_output(f->s[from], &m) != MATTER_OK) return false;
    return matter_pase_receive(f->s[1-from], m.opcode, m.data, m.size) == MATTER_OK && matter_pase_sent(f->s[from]) == MATTER_OK;
}
static bool core_success(void) {
    bool ok = false; PaseFixture* f = NULL;
    for (unsigned known = 0; known < 2; ++known) {
        f = setup(known != 0, false);
        for (unsigned i = 0; i < 6; ++i) {
            CHECK(matter_pase_keys(f->s[0], &f->keys[0]) == MATTER_INVALID_STATE);
            CHECK(matter_pase_keys(f->s[1], &f->keys[1]) == MATTER_INVALID_STATE);
            CHECK(direct(f, i % 2, i));
        }
        CHECK(matter_pase_process(f->s[0], 6) == MATTER_OK);
        CHECK(matter_pase_keys(f->s[1], &f->keys[1]) == MATTER_INVALID_STATE);
        CHECK(matter_pase_confirm_delivery(f->s[1], 6) == MATTER_OK && same_keys(f));
        CHECK(matter_pase_confirm_delivery(f->s[1], 6) == MATTER_INVALID_STATE);
        CHECK(matter_pase_process(f->s[0], 5) == MATTER_INVALID_ARGUMENT);
        CHECK(matter_pase_cancel(f->s[0]) == MATTER_OK && matter_pase_keys(f->s[0], &f->keys[0]) == MATTER_INVALID_STATE);
        CHECK(!f->failures[0] && !f->failures[1]);
        dispose(f); f = NULL;
    }
    ok = true;
done: dispose(f); return ok;
}
static bool rejected(void) {
    bool ok = false; PaseFixture* f = NULL;
    for (unsigned mode = 0; mode < 9; ++mode) {
        f = setup(false, mode == 0);
        Matter_Pase_Message_T m;
        unsigned receiver = 1;
        if (mode == 0 || mode == 1) { /* Wrong PIN or altered cB. */
            for (unsigned i = 0; i < 3; ++i) CHECK(direct(f, i % 2, i));
            CHECK(matter_pase_process(f->s[1], 3) == MATTER_PENDING && matter_pase_output(f->s[1], &m) == MATTER_OK);
            receiver = 0;
        } else if (mode >= 6) { /* Reflected random, PBKDF iterations, session ID. */
            CHECK(direct(f, 0, 0));
            CHECK(matter_pase_process(f->s[1], 1) == MATTER_PENDING && matter_pase_output(f->s[1], &m) == MATTER_OK);
            receiver = 0;
        } else CHECK(matter_pase_process(f->s[0], 0) == MATTER_PENDING && matter_pase_output(f->s[0], &m) == MATTER_OK);
        memcpy(f->buffer, m.data, m.size);
        if (mode == 1) f->buffer[m.size-2] ^= 1;
        if (mode == 2) f->buffer[1] = 0x2c; /* UTF8 instead of bytes. */
        if (mode == 3) f->buffer[m.size-5] = 1; /* passcodeId != 0 */
        if (mode == 4) { /* duplicate field */
            f->buffer[m.size-1] = 0x28; f->buffer[m.size++] = 4; f->buffer[m.size++] = 0x18;
        }
        if (mode == 5) --m.size; /* truncated root */
        if (mode == 6) f->buffer[4] ^= 1;
        if (mode == 7) {
            bool found = false;
            for (size_t i = 0; i + 3 < m.size; ++i) if (f->buffer[i] == 0x25 && f->buffer[i+1] == 1 && f->buffer[i+2] == 0xe8) {
                f->buffer[i+2] = 1; f->buffer[i+3] = 0; found = true; break;
            }
            CHECK(found);
        }
        if (mode == 8) { /* response session ID, after two 32-byte strings */ f->buffer[73] = 0; f->buffer[74] = 0; }
        CHECK(matter_pase_sent(f->s[1-receiver]) == MATTER_OK);
        CHECK(matter_pase_receive(f->s[receiver], m.opcode, f->buffer, m.size) == MATTER_OK);
        CHECK(matter_pase_process(f->s[receiver], 4) == MATTER_PORT_ERROR);
        CHECK(matter_pase_state(f->s[receiver]) == MATTER_PASE_FAILED);
        CHECK(f->failures[receiver]==1 && matter_pase_process(f->s[receiver],4)==MATTER_PORT_ERROR && f->failures[receiver]==1);
        CHECK(matter_pase_keys(f->s[receiver], &f->keys[receiver]) == MATTER_INVALID_STATE);
        CHECK(matter_pase_output(f->s[receiver], &m) == MATTER_OK && m.opcode == 0x40 && m.size == 8);
        static const uint8_t error[] = {1,0,0,0,0,0,2,0};
        CHECK(!memcmp(m.data, error, 8));
        CHECK(matter_pase_receive(f->s[1-receiver], m.opcode, m.data, m.size) == MATTER_OK);
        CHECK(matter_pase_sent(f->s[receiver]) == MATTER_OK);
        CHECK(matter_pase_process(f->s[1-receiver], 5) == MATTER_PORT_ERROR);
        CHECK(matter_pase_output(f->s[1-receiver], &m) == MATTER_WOULD_BLOCK);
        CHECK(f->failures[1-receiver]==1);
        dispose(f); f = NULL;
    }
    ok = true;
done: dispose(f); return ok;
}
static Matter_Result_T fixed_random(void* u, uint8_t* p, size_t n) { (void)u; for (size_t i=0;i<n;++i) p[i]=(uint8_t)i; return MATTER_OK; }
static Matter_Result_T scalar_one(void* u, uint8_t* p) { (void)u; memset(p,0,32); p[31]=1; return MATTER_OK; }
static Matter_Result_T scalar_two(void* u, uint8_t* p) { scalar_one(u,p); p[31]=2; return MATTER_OK; }
static bool equal_hex(const uint8_t* p, size_t n, const char* hex) {
    if (strlen(hex) != 2*n) return false;
    for (size_t i=0;i<n;++i) { unsigned b; if (sscanf(hex+2*i,"%2x",&b)!=1 || p[i]!=b) return false; }
    return true;
}
static bool independent_vector(void) {
    bool ok = false; PaseFixture* f = setup(false, false);
    for (unsigned i=0;i<2;++i) {
        CHECK(matter_pase_delete(f->s[i]) == MATTER_OK); f->s[i] = NULL;
        f->port.random = fixed_random; f->port.p256_scalar = i ? scalar_two : scalar_one;
        f->s[i] = new_pase(f, i); CHECK(f->s[i]);
    }
    /* Generated by fixtures/pase-vector.py, independent of C/TLV/mbedTLS. */
    static const char* vectors[] = {
        "15300120000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f25027b0025030000280418",
        "15300120000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f300220000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2503c80135042501e803300210424242424242424242424242424242421818",
        "15300141041156f7d49fce98d41b6a73a9d0a0c3516c90589fda6f3c687d7bd7b2ca6e1cbca5ca348553758454e1a16519c8421271e6e7cec84b4d5a39f214fba9b2acacf018",
        "1530014104b61a4c464b77da6696cf3142a854234ed5df36fb6b34c8598caccd7f9af14985917b38c61167ed2d05afe4a6fac704477d37889248349b8159fbf4b4eb960e6b3002205ada301005043db7cf9a235c46aba598fcf626ee732b17947bbe050a7e0ec94618",
        "153001207b3bab3ccaa21d72af400f5c0eea940932e3132e690ab39ec8d5c00b73c816cb18",
        "0000000000000000"
    };
    for (unsigned i=0;i<6;++i) {
        Matter_Pase_Message_T m;
        CHECK(matter_pase_process(f->s[i%2], i) == MATTER_PENDING);
        CHECK(matter_pase_output(f->s[i%2], &m) == MATTER_OK && equal_hex(m.data, m.size, vectors[i]));
        CHECK(direct(f, i%2, i));
    }
    CHECK(matter_pase_process(f->s[0], 6) == MATTER_OK && matter_pase_confirm_delivery(f->s[1],6) == MATTER_OK && same_keys(f));
    CHECK(equal_hex(f->keys[0].send_key,16,"666391cabf6ae972e5fe736507b3215b"));
    CHECK(equal_hex(f->keys[0].receive_key,16,"026916c85158565a242513c7b92c6613"));
    CHECK(equal_hex(f->keys[0].attestation_challenge,16,"39810c1f620881ff09ca4b4eb1f8f522"));
    ok = true;
done: dispose(f); return ok;
}
static Matter_Crypto_Port_T fault_forward;
static Matter_Pase_T fault_target;
static unsigned fault_mode;
static Matter_Result_T bad_random(void* u, uint8_t* out, size_t n) {
    REQUIRE(matter_pase_cancel(fault_target) == MATTER_BUSY && matter_pase_delete(fault_target) == MATTER_BUSY);
    if (fault_mode == 0) { out[0]=1; return MATTER_PORT_ERROR; }
    return fault_forward.random(u,out,n);
}
static Matter_Result_T bad_pbkdf(void* u, const uint8_t* p, size_t pn, const uint8_t* salt, size_t sn,
    uint32_t iterations, uint8_t* out, size_t n) {
    if (fault_mode == 1) { out[0]=1; return MATTER_PORT_ERROR; }
    return fault_forward.pbkdf2_sha256(u,p,pn,salt,sn,iterations,out,n);
}
static Matter_Result_T bad_kdf(void* u, const uint8_t* k, size_t kn, const uint8_t* salt, size_t sn,
    const uint8_t* info, size_t in, uint8_t* out, size_t n) {
    if (fault_mode == 2 && in==11 && !memcmp(info,"SessionKeys",11)) { out[0]=1; return MATTER_PORT_ERROR; }
    return fault_forward.hkdf_sha256(u,k,kn,salt,sn,info,in,out,n);
}
static bool failures_and_deadline(void) {
    bool ok = false; PaseFixture* f = NULL;
    for (fault_mode=0;fault_mode<3;++fault_mode) {
        f=setup(false,false); unsigned target=fault_mode==2 ? 1 : 0;
        CHECK(matter_pase_delete(f->s[target]) == MATTER_OK); f->s[target]=NULL;
        fault_forward=f->port; f->port.random=bad_random; f->port.pbkdf2_sha256=bad_pbkdf; f->port.hkdf_sha256=bad_kdf;
        f->s[target]=new_pase(f,target); CHECK(f->s[target]); fault_target=f->s[target];
        unsigned before=fault_mode==0 ? 0 : fault_mode==1 ? 2 : 5;
        for (unsigned i=0;i<before;++i) CHECK(direct(f,i%2,i));
        CHECK(matter_pase_process(f->s[target],6)==MATTER_PORT_ERROR);
        CHECK(matter_pase_keys(f->s[target],&f->keys[target])==MATTER_INVALID_STATE);
        CHECK(matter_pase_state(f->s[target])==MATTER_PASE_FAILED);
        dispose(f); f=NULL; fault_target=NULL;
    }
    f=setup(false,false);
    for (unsigned i=0;i<6;++i) CHECK(direct(f,i%2,i));
    CHECK(matter_pase_confirm_delivery(f->s[1],30000)==MATTER_PORT_ERROR);
    CHECK(matter_pase_process(f->s[0],30000)==MATTER_PORT_ERROR);
    for (unsigned i=0;i<2;++i) CHECK(matter_pase_keys(f->s[i],&f->keys[i])==MATTER_INVALID_STATE);
    dispose(f); f=NULL;
#ifdef MATTER_TEST_ALLOC
    f=setup(false,false);
    CHECK(direct(f,0,0) && direct(f,1,1));
    fail_at=calls+1; /* Context buffer allocation before PBKDF/ECP. */
    CHECK(matter_pase_process(f->s[0],2)==MATTER_PORT_ERROR); fail_at=0;
    CHECK(matter_pase_keys(f->s[0],&f->keys[0])==MATTER_INVALID_STATE);
#endif
    ok=true;
done:
#ifdef MATTER_TEST_ALLOC
    fail_at=0;
#endif
    fault_target=NULL; dispose(f); return ok;
}
static bool schema_and_lifecycle(void) {
    bool ok = false; PaseFixture* f = setup(false, false);
    CHECK(matter_pase_delete(f->s[0]) == MATTER_OK); f->s[0] = NULL;
    f->port.random = fixed_random; f->config[0].local_session_id = 1;
    f->s[0] = new_pase(f, 0); CHECK(f->s[0]);
    Matter_Pase_Message_T m, again;
    CHECK(matter_pase_process(f->s[0], 0) == MATTER_PENDING && matter_pase_output(f->s[0], &m) == MATTER_OK);
    static const uint8_t request[] = {0x15,0x30,1,32,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
        16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,0x25,2,1,0,0x25,3,0,0,0x28,4,0x18};
    CHECK(m.opcode == 0x20 && m.size == sizeof(request) && !memcmp(m.data, request, sizeof(request)));
    CHECK(matter_pase_process(f->s[0], 1) == MATTER_PENDING && matter_pase_output(f->s[0], &again) == MATTER_OK);
    CHECK(m.data == again.data && !memcmp(m.data, request, sizeof(request)));
    /* Future context field: valid unknown nested structure must be skipped. */
    memcpy(f->buffer, m.data, m.size-1);
    static const uint8_t suffix[] = {0x35,200,0x24,1,7,0x18,0x18};
    memcpy(f->buffer + m.size-1, suffix, sizeof(suffix));
    CHECK(matter_pase_receive(f->s[1], m.opcode, f->buffer, m.size-1+sizeof(suffix)) == MATTER_OK);
    CHECK(matter_pase_receive(f->s[1], m.opcode, f->buffer, 1) == MATTER_WOULD_BLOCK);
    CHECK(matter_pase_process(f->s[1], 1) == MATTER_PENDING && matter_pase_output(f->s[1], &again) == MATTER_OK);
    CHECK(again.opcode == 0x21);
    /* Optional peer MRP parameters + unknown context tag zero. */
    CHECK(matter_pase_delete(f->s[1]) == MATTER_OK); f->s[1]=new_pase(f,1); CHECK(f->s[1]);
    static const uint8_t peer_params[] = {0x35,5,0x25,1,0x26,2,0x24,2,80,0x25,3,0xc8,0,0x18,0x18};
    f->buffer[0]=0x15; f->buffer[1]=0x24; f->buffer[2]=0; f->buffer[3]=9;
    memcpy(f->buffer+4,request+1,sizeof(request)-2);
    memcpy(f->buffer+sizeof(request)+2,peer_params,sizeof(peer_params));
    CHECK(matter_pase_receive(f->s[1],0x20,f->buffer,sizeof(request)+2+sizeof(peer_params))==MATTER_OK);
    CHECK(matter_pase_process(f->s[1],1)==MATTER_PENDING);
    Matter_Pase_Intervals_T intervals;
    CHECK(matter_pase_peer_intervals(f->s[1],&intervals)==MATTER_OK && intervals.idle_ms==550 &&
        intervals.active_ms==80 && intervals.active_threshold_ms==200);
    CHECK(matter_pase_process(f->s[0], 30000) == MATTER_PORT_ERROR);
    CHECK(matter_pase_output(f->s[0], &m) == MATTER_WOULD_BLOCK);
    CHECK(matter_pase_cancel(f->s[1]) == MATTER_OK && matter_pase_confirm_delivery(f->s[1], 2) == MATTER_INVALID_STATE);
    f->config[0].pin = 11111111; CHECK(!matter_pase_new(&f->port, &f->config[0], 0));
    f->config[0].pin = 20202021; f->config[0].local_session_id = 0; CHECK(!matter_pase_new(&f->port, &f->config[0], 0));
#ifdef MATTER_TEST_ALLOC
    f->config[0].local_session_id = 1;
    fail_at = calls + 1; CHECK(!matter_pase_new(&f->port, &f->config[0], 0)); fail_at = 0;
#endif
    ok = true;
done:
#ifdef MATTER_TEST_ALLOC
    fail_at = 0;
#endif
    dispose(f); return ok;
}
static bool queue_pase(Peer* p) {
    Matter_Pase_Message_T m;
    if ((p->case_session?matter_case_output(p->case_session,&m):matter_pase_output(p->pase,&m)) != MATTER_OK || p->tx_pins) return false;
    if (!p->handle && (matter_rx_initiate(p->rx, p->session, &p->handle) != MATTER_OK ||
        matter_rx_get(p->rx, p->handle, &p->key) != MATTER_OK)) return false;
    Matter_Protocol_Header_T h = {.exchange_id=p->key.exchange_id, .protocol_id=0, .opcode=m.opcode,
        .exchange_flags=MATTER_PROTOCOL_RELIABLE | (p->key.initiator ? MATTER_PROTOCOL_INITIATOR : 0)};
    Matter_Unsecured_Prepared_T prepared;
    if (matter_unsecured_prepare(p->sessions, p->key.session, &p->outgoing, &h, m.data, m.size,
        p->outbound.data, sizeof(p->outbound.data), &prepared) != MATTER_OK) return false;
    p->outbound.size = prepared.size;
    if (matter_retransmission_sender_add(p->tx, &p->key, prepared.counter, p->outbound.data,
        p->outbound.size, &p->message_id) != MATTER_OK) return false;
    p->pase_final = m.opcode == 0x40 && m.size == 8 && m.data[0] == 0;
    return (p->case_session?matter_case_sent(p->case_session):matter_pase_sent(p->pase)) == MATTER_OK;
}
static bool transport_message(PaseFixture* f, Peer* from, Peer* to, uint64_t* now, bool loss, bool duplicate) {
    bool ok = false;
    CHECK(queue_pase(from) && tick(from, *now) && from->retained);
    unsigned delivered_before = to->deliveries, notified_before = from->notifications;
    f->link->delayed_data = from->wire;
    for (unsigned retry = 0; retry < (loss ? 2u : 1u); ++retry) {
#ifdef MATTER_TEST_HOST_UDP
        if (from->host) {
            network_poll(from); CHECK(network_take(from)); CHECK(network_receive(to));
            CHECK(to->inbox.size == f->link->delayed_data.size && !memcmp(to->inbox.data, f->link->delayed_data.data, to->inbox.size));
            if (loss && !retry) to->inbox_full = false;
            else CHECK(network_admit(to, *now));
        } else
#endif
        {
            CHECK(complete_tx(from, MATTER_RETRANSMISSION_SENT));
            if (!loss || retry) CHECK(receive_packet(to, &from->wire, *now) == MATTER_OK);
        }
        if (loss && !retry) { *now += 330; CHECK(tick(from, *now) && from->retained); complete_resolver(from); }
    }
    CHECK(tick(to, *now) && to->deliveries == delivered_before + 1);
    if (duplicate) {
        CHECK(receive_packet(to, &f->link->delayed_data, *now) == MATTER_OK && tick(to, *now));
        CHECK(to->deliveries == delivered_before + 1);
    }
    *now += 200;
    CHECK(tick(to, *now) && to->retained_ack);
#ifdef MATTER_TEST_HOST_UDP
    if (from->host) {
        network_poll(to); CHECK(network_take(to)); CHECK(network_receive(from) && network_admit(from, *now));
    } else
#endif
    {
        f->link->delayed_ack = to->wire;
        CHECK(complete_ack(to, MATTER_OPERATION_SUCCEEDED));
        CHECK(receive_packet(from, &f->link->delayed_ack, *now) == MATTER_OK);
    }
    CHECK(tick(from, *now) && from->notifications == notified_before + 1);
    CHECK(from->outcome == MATTER_RETRANSMISSION_ACKNOWLEDGED && !from->tx_pins);
    ok = true;
done: return ok;
}
#include "test_im_network.h"
#include "test_invoke_network.h"
#include "test_timed_network.h"
#include "test_write_network.h"
#include "test_write_lists_network.h"
#include "test_subscribe_network.h"
#include "test_root_network.h"
#include "test_commissioning_network.h"
#include "test_wifi_network.h"
#include "test_opcreds_network.h"
#include "test_fabric_network.h"
#include "test_pase_secure.h"
#include "test_case_network.h"
#include "test_complete_network.h"
#include "test_acl_network.h"
#include "test_power_topology_network.h"
#include "test_epm_network.h"
#include "test_eem_network.h"
#include "test_groupkey_network.h"
#include "test_diagnostics_network.h"
#include "test_admin_commissioning.h"
#include "test_admin_commissioning_network.h"
static bool network_pase(void) {
    bool ok = false; PaseFixture* f = NULL;
    unsigned modes=2;
#ifdef MATTER_TEST_HOST_UDP
    modes=13; /* Existing close cases plus fail-safe expiry with retained TX. */
#endif
    for (unsigned mode = 0; mode < modes; ++mode) {
        f = setup(mode != 0, false);
        f->im_close_wait=mode==2;
        f->invoke_close=mode==3;
        f->timed_close=mode==4;
        f->write_close=mode==5 || mode==6 ? mode-4 : 0;
        f->write_list_close=mode==7;
        f->subscribe_close=mode==8;
        f->commissioning_expiry=mode==9;
        f->wifi_commissioning=mode==10;
        f->opcreds_commissioning=mode==11;
        f->fabric_commissioning=mode==12;
#ifdef MATTER_TEST_HOST_UDP
        f->link = create_network();
#else
        f->link = create();
#endif
        CHECK(f->link);
        f->link->a.pase = f->s[0]; f->link->b.pase = f->s[1];
        CHECK(matter_rx_register(f->link->a.rx, 0, 0) == MATTER_OK && matter_rx_register(f->link->b.rx, 0, 0) == MATTER_OK);
        uint64_t now = 0;
        for (unsigned i = 0; i < 6; ++i) {
            Peer* from = i % 2 ? &f->link->b : &f->link->a;
            Peer* to = i % 2 ? &f->link->a : &f->link->b;
            CHECK(matter_pase_keys(f->s[0], &f->keys[0]) == MATTER_INVALID_STATE);
            CHECK(matter_pase_keys(f->s[1], &f->keys[1]) == MATTER_INVALID_STATE);
            CHECK(matter_pase_process(from->pase, now) == MATTER_PENDING);
            CHECK(transport_message(f, from, to, &now, mode != 0, mode != 0));
        }
        CHECK(matter_pase_process(f->s[0], now) == MATTER_OK && same_keys(f));
        CHECK(f->link->a.deliveries == 3 && f->link->b.deliveries == 3);
        CHECK(secure_traffic(f, now));
        dispose(f); f = NULL;
    }
    ok = true;
done: dispose(f); return ok;
}
static bool network_abort(void) {
    bool ok=false; PaseFixture* f=NULL;
    for (unsigned timeout=0;timeout<2;++timeout) {
        f=setup(false,false);
#ifdef MATTER_TEST_HOST_UDP
        f->link=create_network();
#else
        f->link=create();
#endif
        CHECK(f->link); Peer* p=&f->link->a; p->pase=f->s[0];
        CHECK(matter_pase_process(p->pase,0)==MATTER_PENDING && queue_pase(p) && tick(p,0) && p->retained);
        if (timeout) CHECK(matter_pase_process(p->pase,30000)==MATTER_PORT_ERROR);
        else CHECK(matter_pase_cancel(p->pase)==MATTER_OK);
        CHECK(f->failures[0]==timeout && !f->failures[1]);
        CHECK(matter_pase_process(p->pase,30000)==MATTER_PORT_ERROR && f->failures[0]==timeout);
        CHECK(matter_pase_keys(p->pase,&f->keys[0])==MATTER_INVALID_STATE);
        CHECK(matter_retransmission_sender_cancel(p->tx,p->message_id)==MATTER_PENDING);
        CHECK(p->tx_pins && !p->notifications); /* Retained bytes survive cancellation. */
#ifdef MATTER_TEST_HOST_UDP
        if (p->host) { network_poll(p); CHECK(network_take(p)); }
        else
#endif
        CHECK(complete_tx(p,MATTER_RETRANSMISSION_SENT));
        CHECK(tick(p,30000) && !p->tx_pins && p->notifications==1 && p->outcome==MATTER_RETRANSMISSION_CANCELLED);
        dispose(f); f=NULL;
    }
    ok=true;
done: dispose(f); return ok;
}
#ifdef MATTER_TEST_ALLOC
static void pase_memory(bool faults) {
    size_t counts[7]={0},failures=0;
    PaseFixture* f=setup(false,false); size_t idle=live_bytes,owner=matter_test_allocation_size(f->s[0]);
    peak_bytes=idle;
    printf("MEMORY PASE owners=%zu idle_pair_tracked=%zu\n",owner,idle);
    for(unsigned phase=0;phase<7;++phase) {
        size_t start=calls;
        REQUIRE(matter_pase_process(f->s[phase%2],phase)==(phase==6?MATTER_OK:MATTER_PENDING));
        counts[phase]=calls-start;
        printf("MEMORY PASE phase=%u live=%zu peak=%zu process_allocations=%zu\n",phase,live_bytes,peak_bytes,counts[phase]);
        if(phase<6) {
            Matter_Pase_Message_T m,again; REQUIRE(matter_pase_output(f->s[phase%2],&m)==MATTER_OK);
            start=calls; fail_at=calls+1;
            REQUIRE(matter_pase_process(f->s[phase%2],phase)==MATTER_PENDING);
            REQUIRE(matter_pase_output(f->s[phase%2],&again)==MATTER_OK && again.data==m.data && again.size==m.size && calls==start);
            if(faults) {
                size_t before=live_bytes;
                REQUIRE(matter_pase_receive(f->s[1-phase%2],m.opcode,m.data,m.size)==MATTER_LIMIT_REACHED && live_bytes==before);
                ++failures;
            }
            fail_at=0;
            size_t before=live_bytes;
            REQUIRE(matter_pase_receive(f->s[1-phase%2],m.opcode,m.data,m.size)==MATTER_OK);
            if(faults) REQUIRE(live_bytes-before==m.size);
            REQUIRE(matter_pase_sent(f->s[phase%2])==MATTER_OK);
        }
    }
    REQUIRE(matter_pase_confirm_delivery(f->s[1],7)==MATTER_OK && same_keys(f));
    if(faults) REQUIRE(live_bytes==idle);
    printf("MEMORY PASE completed_live=%zu peak=%zu\n",live_bytes,peak_bytes); dispose(f);
    if(faults) for(unsigned phase=0;phase<7;++phase) for(size_t point=1;point<=counts[phase];++point) {
        f=setup(false,false);
        for(unsigned i=0;i<phase;++i) REQUIRE(direct(f,i%2,i));
        fail_at=calls+point;
        REQUIRE(matter_pase_process(f->s[phase%2],phase)==MATTER_PORT_ERROR); fail_at=0;
        REQUIRE(matter_pase_state(f->s[phase%2])==MATTER_PASE_FAILED && f->failures[phase%2]==1);
        REQUIRE(matter_pase_keys(f->s[phase%2],&f->keys[phase%2])==MATTER_INVALID_STATE);
        Matter_Pase_Message_T status; size_t start=calls; fail_at=calls+1;
        if(phase && phase!=6) REQUIRE(matter_pase_output(f->s[phase%2],&status)==MATTER_OK && status.opcode==0x40 && status.size==8);
        REQUIRE(matter_pase_process(f->s[phase%2],phase)==MATTER_PORT_ERROR && calls==start); fail_at=0;
        dispose(f); REQUIRE(!live); ++failures;
    }
    if(faults) printf("PASS PASE phase memory: %zu RX/process OOM positions, stable output/idle polls, context release, no key transfer on failure\n",failures);
}
#endif
int main(int argc,char** argv) {
#ifdef MATTER_TEST_ALLOC
    if(argc==2 && (!strcmp(argv[1],"--memory-profile") || !strcmp(argv[1],"--memory-only"))) {
        pase_memory(!strcmp(argv[1],"--memory-only")); REQUIRE(!live); return 0;
    }
    pase_memory(true);
#else
    (void)argc; (void)argv;
#endif
    if(!admin_core()) return 1;
#ifdef MATTER_TEST_HOST_UDP
    if(!network_eem() || !network_epm() || !network_power_topology() || !network_admin_commissioning() || !network_case() || !network_acl() || !network_groupkey() || !network_diagnostics()) return 1;
    for(unsigned complete_mode=0;complete_mode<3;++complete_mode) if(!network_complete(complete_mode)) return 1;
#endif
    if (!core_success() || !rejected() || !schema_and_lifecycle() || !independent_vector() ||
        !failures_and_deadline() || !network_pase() || !network_abort()) return 1;
#ifdef MATTER_TEST_ALLOC
    REQUIRE(!live);
    printf("PASE: %zu contexts zeroized before free, context %zu bytes\n", pase_wiped, pase_allocations[0].size);
#endif
    puts("PASS PASE: schemas, PIN/verifier, confirmation gates, errors, timeout/cancel and two-peer MRP");
    puts("PASS post-PASE: one-shot keys, encrypted data/ACK, replay filtering and close with pending TX");
#ifdef MATTER_TEST_HOST_UDP
    puts("PASS PASE real IPv6: six messages, loss/retry each stage, duplicates, known PBKDF parameters, matching keys");
#endif
    return 0;
}
