#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "codec/matter_protocol_header.h"

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr,"%s:%d %s: %s\n",__FILE__,__LINE__,__func__,#c); \
    return false; } } while (0)

typedef struct {
    uint8_t input[65550], output[32], snapshot[32];
    Matter_Protocol_Header_T header, before;
    size_t count;
} Fixture;

static void reset(Fixture* f) {
    memset(&f->header,0xa5,sizeof(f->header));
    memcpy(&f->before,&f->header,sizeof(f->header));
    memset(f->output,0xa5,sizeof(f->output));
    memcpy(f->snapshot,f->output,sizeof(f->output));
    f->count=123456;
}

static bool unchanged(Fixture* f) {
    CHECK(f->count==123456);
    CHECK(!memcmp(&f->header,&f->before,sizeof(f->header)));
    CHECK(!memcmp(f->output,f->snapshot,sizeof(f->output)));
    return true;
}

static bool same(const Matter_Protocol_Header_T* a, const Matter_Protocol_Header_T* b) {
    return a->exchange_flags==b->exchange_flags && a->opcode==b->opcode &&
        a->exchange_id==b->exchange_id && a->protocol_id==b->protocol_id &&
        a->vendor_id==b->vendor_id && a->acknowledged_message_counter==b->acknowledged_message_counter;
}

static bool test_vectors(Fixture* f) {
    /* Hand-calculated bytes independent of writer. See protocol-header-sources.md. */
    static const struct {
        const char* bytes; size_t size; Matter_Protocol_Header_T header;
    } cases[]={
#define V(s,...) {s,sizeof(s)-1,{__VA_ARGS__}}
        V("\0\0\0\0\0\0",0),
        V("\1\x42\x34\x12\1\0",.exchange_flags=1,.opcode=0x42,
            .exchange_id=0x1234,.protocol_id=1),
        V("\x10\x42\x34\x12\xf1\xff\x78\x56",.exchange_flags=0x10,
            .opcode=0x42,.exchange_id=0x1234,.vendor_id=0xfff1,.protocol_id=0x5678),
        V("\6\x42\x34\x12\1\0\x12\x34\x56\x78",.exchange_flags=6,
            .opcode=0x42,.exchange_id=0x1234,.protocol_id=1,.acknowledged_message_counter=0x78563412),
        V("\x17\x42\x34\x12\xf1\xff\x78\x56\x12\x34\x56\x78",.exchange_flags=0x17,
            .opcode=0x42,.exchange_id=0x1234,.vendor_id=0xfff1,.protocol_id=0x5678,
            .acknowledged_message_counter=0x78563412),
        V("\x12\0\0\0\0\0\0\0\0\0\0\0",.exchange_flags=0x12),
        V("\x17\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",.exchange_flags=0x17,
            .opcode=UINT8_MAX,.exchange_id=UINT16_MAX,.vendor_id=UINT16_MAX,
            .protocol_id=UINT16_MAX,.acknowledged_message_counter=UINT32_MAX)
    };
    for (size_t i=0;i<sizeof(cases)/sizeof(cases[0]);++i) {
        reset(f);
        CHECK(matter_protocol_header_read((const uint8_t*)cases[i].bytes,cases[i].size,
            &f->header,&f->count)==MATTER_MESSAGE_OK);
        CHECK(f->count==cases[i].size && same(&f->header,&cases[i].header));
        CHECK(matter_protocol_header_write(&cases[i].header,f->output,sizeof(f->output),&f->count)==MATTER_MESSAGE_OK);
        CHECK(f->count==cases[i].size && !memcmp(f->output,cases[i].bytes,f->count));
        CHECK(!memcmp(f->output+f->count,f->snapshot+f->count,sizeof(f->output)-f->count));
        for (size_t cut=0;cut<cases[i].size;++cut) {
            uint8_t* short_input=cut ? malloc(cut) : NULL;
            CHECK(!cut || short_input);
            if (cut) memcpy(short_input,cases[i].bytes,cut);
            reset(f);
            Matter_Message_Result_T result=matter_protocol_header_read(short_input,cut,&f->header,&f->count);
            free(short_input);
            CHECK(result==MATTER_MESSAGE_TRUNCATED && unchanged(f));
            CHECK(matter_protocol_header_write(&cases[i].header,f->output,cut,&f->count)==MATTER_MESSAGE_NO_SPACE);
            CHECK(unchanged(f));
        }
    }
    return true;
}

static bool test_flags_and_optional_fields(Fixture* f) {
    for (unsigned flags=0;flags<256;++flags) {
        Matter_Protocol_Header_T header={.exchange_flags=(uint8_t)flags,.opcode=0xa5,
            .exchange_id=0x1234,.vendor_id=0xfff1,.protocol_id=0x5678,
            .acknowledged_message_counter=0x78563412};
        /* Construct input from independent literal fields, including SX length 0. */
        static const uint8_t vendor[]={0xf1,0xff}, protocol[]={0x78,0x56}, ack[]={0x12,0x34,0x56,0x78};
        size_t fixed=4;
        f->input[0]=(uint8_t)flags; f->input[1]=0xa5; f->input[2]=0x34; f->input[3]=0x12;
        if (flags&0x10) { memcpy(f->input+fixed,vendor,2); fixed+=2; }
        memcpy(f->input+fixed,protocol,2); fixed+=2;
        if (flags&2) { memcpy(f->input+fixed,ack,4); fixed+=4; }
        size_t size=fixed;
        if (flags&8) { f->input[size++]=0; f->input[size++]=0; }
        f->input[size]=0xcc;
        reset(f);
        CHECK(matter_protocol_header_read(f->input,size+1,&f->header,&f->count)==MATTER_MESSAGE_OK);
        CHECK(f->count==size && f->input[f->count]==0xcc);
        Matter_Protocol_Header_T expected=header;
        if (!(flags&0x10)) expected.vendor_id=0;
        if (!(flags&2)) expected.acknowledged_message_counter=0;
        CHECK(same(&f->header,&expected));
        for (size_t cut=0;cut<size;++cut) {
            reset(f);
            CHECK(matter_protocol_header_read(f->input,cut,&f->header,&f->count)==MATTER_MESSAGE_TRUNCATED);
            CHECK(unchanged(f));
        }
        reset(f);
        CHECK(matter_protocol_header_write(&header,f->output,32,&f->count)==
            ((flags&8) ? MATTER_MESSAGE_UNSUPPORTED : MATTER_MESSAGE_OK));
        if (flags&8) CHECK(unchanged(f));
        else {
            CHECK(f->count==fixed && f->output[0]==(flags&0x17));
            CHECK(!memcmp(f->output+1,f->input+1,fixed-1));
            CHECK(!memcmp(f->output+fixed,f->snapshot+fixed,32-fixed));
        }
    }
    return true;
}

static bool test_extensions(Fixture* f) {
    static const uint8_t bytes[]={0x1f,0x42,0x34,0x12,0xf1,0xff,0x78,0x56,
        0x12,0x34,0x56,0x78,3,0,0xaa,0xbb,0xcc,0xee};
    for (size_t cut=0;cut<sizeof(bytes)-1;++cut) {
        reset(f);
        CHECK(matter_protocol_header_read(bytes,cut,&f->header,&f->count)==MATTER_MESSAGE_TRUNCATED);
        CHECK(unchanged(f));
    }
    CHECK(matter_protocol_header_read(bytes,sizeof(bytes),&f->header,&f->count)==MATTER_MESSAGE_OK);
    CHECK(f->count==17 && bytes[f->count]==0xee && f->header.vendor_id==0xfff1);
    CHECK(f->header.acknowledged_message_counter==0x78563412);
    memset(f->input,0,sizeof(f->input));
    f->input[0]=0x1a; f->input[12]=255; f->input[13]=255; f->input[65549]=0xdd;
    reset(f);
    CHECK(matter_protocol_header_read(f->input,65548,&f->header,&f->count)==MATTER_MESSAGE_TRUNCATED);
    CHECK(unchanged(f));
    CHECK(matter_protocol_header_read(f->input,65550,&f->header,&f->count)==MATTER_MESSAGE_OK);
    CHECK(f->count==65549 && f->input[f->count]==0xdd);
    /* Exercise every declared uint16 length and its one-byte-short input. */
    for (unsigned length=0;length<=65535;++length) {
        f->input[12]=(uint8_t)length; f->input[13]=(uint8_t)(length>>8);
        reset(f);
        CHECK(matter_protocol_header_read(f->input,14+length-1,&f->header,&f->count)==MATTER_MESSAGE_TRUNCATED);
        CHECK(unchanged(f));
        CHECK(matter_protocol_header_read(f->input,14+length,&f->header,&f->count)==MATTER_MESSAGE_OK);
        CHECK(f->count==14+length);
    }
    return true;
}

static bool test_arguments_and_reuse(Fixture* f) {
    Matter_Protocol_Header_T header={0};
    reset(f);
    CHECK(matter_protocol_header_read(NULL,1,&f->header,&f->count)==MATTER_MESSAGE_INVALID_ARGUMENT);
    CHECK(matter_protocol_header_read(f->input,6,NULL,&f->count)==MATTER_MESSAGE_INVALID_ARGUMENT);
    CHECK(matter_protocol_header_read(f->input,6,&f->header,NULL)==MATTER_MESSAGE_INVALID_ARGUMENT);
    CHECK(matter_protocol_header_write(NULL,f->output,32,&f->count)==MATTER_MESSAGE_INVALID_ARGUMENT);
    CHECK(matter_protocol_header_write(&header,NULL,1,&f->count)==MATTER_MESSAGE_INVALID_ARGUMENT);
    CHECK(matter_protocol_header_write(&header,f->output,32,NULL)==MATTER_MESSAGE_INVALID_ARGUMENT);
    CHECK(matter_protocol_header_write(&header,NULL,0,&f->count)==MATTER_MESSAGE_NO_SPACE);
    CHECK(unchanged(f));
    header.vendor_id=UINT16_MAX; header.acknowledged_message_counter=UINT32_MAX;
    CHECK(matter_protocol_header_write(&header,f->output,6,&f->count)==MATTER_MESSAGE_OK);
    CHECK(matter_protocol_header_read(f->output,6,&f->header,&f->count)==MATTER_MESSAGE_OK);
    CHECK(f->count==6 && !f->header.vendor_id && !f->header.acknowledged_message_counter);
    header.exchange_flags=0x12;
    CHECK(matter_protocol_header_write(&header,f->input+1,12,&f->count)==MATTER_MESSAGE_OK);
    CHECK(matter_protocol_header_read(f->input+1,12,&f->header,&f->count)==MATTER_MESSAGE_OK);
    CHECK(f->count==12 && same(&f->header,&header));
    CHECK(matter_protocol_header_read(f->output,6,&f->header,&f->count)==MATTER_MESSAGE_OK);
    CHECK(f->count==6 && !f->header.vendor_id && !f->header.acknowledged_message_counter);
    return true;
}

static bool test_message_composition(Fixture* f) {
    /* Literal unsecured envelope + protocol + opaque application bytes. */
    static const uint8_t packet[]={0,0,0,0,1,0,0,0,
        3,0x20,0x34,0x12,0,0,0x12,0x34,0x56,0x78,4,0x2a};
    Matter_Message_Header_T message;
    size_t envelope, protocol, written;
    CHECK(matter_message_header_read(packet,sizeof(packet),&message,&envelope)==MATTER_MESSAGE_OK);
    CHECK(envelope==8 && message.session_id==0 && message.message_counter==1);
    CHECK(matter_protocol_header_read(packet+envelope,sizeof(packet)-envelope,&f->header,&protocol)==MATTER_MESSAGE_OK);
    CHECK(protocol==10 && envelope+protocol==sizeof(packet)-2);
    CHECK(f->header.exchange_id==0x1234 && f->header.acknowledged_message_counter==0x78563412);
    reset(f); /* Re-read after reset so both outputs can be encoded independently. */
    CHECK(matter_protocol_header_read(packet+envelope,sizeof(packet)-envelope,&f->header,&protocol)==MATTER_MESSAGE_OK);
    CHECK(matter_message_header_write(&message,f->output,8,&written)==MATTER_MESSAGE_OK && written==8);
    CHECK(matter_protocol_header_write(&f->header,f->output+envelope,protocol,&written)==MATTER_MESSAGE_OK);
    CHECK(written==10 && !memcmp(f->output,packet,envelope+protocol));
    CHECK(!memcmp(f->output+envelope+protocol,f->snapshot+envelope+protocol,32-envelope-protocol));
    return true;
}

int main(void) {
    Fixture* f=malloc(sizeof(*f));
    if (!f) return 1;
    static const struct { const char* name; bool (*run)(Fixture*); } tests[]={
        {"vectors, prefixes and capacity",test_vectors},
        {"all flags and optional fields",test_flags_and_optional_fields},
        {"extensions and all uint16 lengths",test_extensions},
        {"arguments, retry and buffer reuse",test_arguments_and_reuse},
        {"composition with message header",test_message_composition}
    };
    for (size_t i=0;i<sizeof(tests)/sizeof(tests[0]);++i) {
        if (!tests[i].run(f)) { free(f); return 1; }
        printf("PASS protocol header: %s\n",tests[i].name);
    }
    free(f);
    return 0;
}
