#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "codec/matter_message_header.h"

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr,"%s:%d %s: %s\n",__FILE__,__LINE__,__func__,#c); \
    return false; } } while (0)

/* Host-only storage, off the stack; production has no large scratch buffer. */
typedef struct {
    uint8_t input[65562], output[32], snapshot[32];
    Matter_Message_Header_T header, before;
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

static bool same(const Matter_Message_Header_T* a, const Matter_Message_Header_T* b) {
    return a->message_flags==b->message_flags && a->security_flags==b->security_flags &&
        a->session_id==b->session_id && a->message_counter==b->message_counter &&
        a->source_node_id==b->source_node_id && a->destination_id==b->destination_id;
}

static bool test_vectors(Fixture* f) {
    /* Independently calculated LE bytes; see fixtures/message-header-sources.md. */
    static const struct {
        const char* bytes; size_t size; Matter_Message_Header_T header;
    } cases[]={
#define V(s,...) {s,sizeof(s)-1,{__VA_ARGS__}}
        V("\0\0\0\0\0\0\0\0",0),
        V("\0\x34\x12\0\x12\x34\x56\x78",
            .session_id=0x1234,.message_counter=0x78563412),
        V("\x04\x34\x12\0\x12\x34\x56\x78\1\2\3\4\5\6\7\x08",
            .message_flags=4,.session_id=0x1234,.message_counter=0x78563412,
            .source_node_id=UINT64_C(0x0807060504030201)),
        V("\1\x34\x12\0\x12\x34\x56\x78\x11\x12\x13\x14\x15\x16\x17\x18",
            .message_flags=1,.session_id=0x1234,.message_counter=0x78563412,
            .destination_id=UINT64_C(0x1817161514131211)),
        V("\5\x34\x12\0\x12\x34\x56\x78\1\2\3\4\5\6\7\x08\x11\x12\x13\x14\x15\x16\x17\x18",
            .message_flags=5,.session_id=0x1234,.message_counter=0x78563412,
            .source_node_id=UINT64_C(0x0807060504030201),
            .destination_id=UINT64_C(0x1817161514131211)),
        V("\2\x34\x12\1\x12\x34\x56\x78\x11\x22",
            .message_flags=2,.security_flags=1,.session_id=0x1234,
            .message_counter=0x78563412,.destination_id=0x2211),
        V("\6\x34\x12\x41\x12\x34\x56\x78\1\2\3\4\5\6\7\x08\x11\x22",
            .message_flags=6,.security_flags=0x41,.session_id=0x1234,
            .message_counter=0x78563412,.source_node_id=UINT64_C(0x0807060504030201),
            .destination_id=0x2211),
        V("\5\xff\xff\x40\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
            .message_flags=5,.security_flags=0x40,.session_id=UINT16_MAX,
            .message_counter=UINT32_MAX,.source_node_id=UINT64_MAX,.destination_id=UINT64_MAX),
        V("\2\0\0\1\0\0\0\0\xff\xff",
            .message_flags=2,.security_flags=1,.destination_id=UINT16_MAX)
    };
    for (size_t i=0;i<sizeof(cases)/sizeof(cases[0]);++i) {
        reset(f);
        CHECK(matter_message_header_read((const uint8_t*)cases[i].bytes,cases[i].size,
            &f->header,&f->count)==MATTER_MESSAGE_OK);
        CHECK(f->count==cases[i].size && same(&f->header,&cases[i].header));
        CHECK(matter_message_header_write(&cases[i].header,f->output,sizeof(f->output),
            &f->count)==MATTER_MESSAGE_OK);
        CHECK(f->count==cases[i].size && !memcmp(f->output,cases[i].bytes,f->count));
        CHECK(!memcmp(f->output+f->count,f->snapshot+f->count,sizeof(f->output)-f->count));
        /* Non-header payload must remain unconsumed and unmodified. */
        memcpy(f->input,cases[i].bytes,cases[i].size);
        f->input[cases[i].size]=0xab;
        CHECK(matter_message_header_read(f->input,cases[i].size+1,&f->header,&f->count)==MATTER_MESSAGE_OK);
        CHECK(f->count==cases[i].size && f->input[f->count]==0xab);
        for (size_t cut=0;cut<cases[i].size;++cut) {
            uint8_t* short_input=cut ? malloc(cut) : NULL;
            CHECK(!cut || short_input);
            if (cut) memcpy(short_input,cases[i].bytes,cut);
            reset(f);
            Matter_Message_Result_T result=matter_message_header_read(short_input,cut,&f->header,&f->count);
            free(short_input);
            CHECK(result==MATTER_MESSAGE_TRUNCATED && unchanged(f));
            CHECK(matter_message_header_write(&cases[i].header,f->output,cut,&f->count)==MATTER_MESSAGE_NO_SPACE);
            CHECK(unchanged(f));
        }
    }
    return true;
}

static bool test_extensions(Fixture* f) {
    static const uint8_t bytes[]={6,0x34,0x12,0x21,0x12,0x34,0x56,0x78,
        1,2,3,4,5,6,7,8,0x11,0x22,3,0,0xaa,0xbb,0xcc,0xee};
    for (size_t cut=0;cut<sizeof(bytes)-1;++cut) {
        reset(f);
        CHECK(matter_message_header_read(bytes,cut,&f->header,&f->count)==MATTER_MESSAGE_TRUNCATED);
        CHECK(unchanged(f));
    }
    CHECK(matter_message_header_read(bytes,sizeof(bytes),&f->header,&f->count)==MATTER_MESSAGE_OK);
    CHECK(f->count==23 && bytes[f->count]==0xee && f->header.destination_id==0x2211);
    CHECK(f->header.source_node_id==UINT64_C(0x0807060504030201) && f->header.security_flags==0x21);
    /* Largest extensions after the largest fixed header, with trailing payload. */
    memset(f->input,0,sizeof(f->input));
    f->input[0]=5; f->input[3]=0x20; f->input[24]=0xff; f->input[25]=0xff;
    f->input[65561]=0xde;
    reset(f);
    CHECK(matter_message_header_read(f->input,65560,&f->header,&f->count)==MATTER_MESSAGE_TRUNCATED);
    CHECK(unchanged(f));
    CHECK(matter_message_header_read(f->input,65562,&f->header,&f->count)==MATTER_MESSAGE_OK);
    CHECK(f->count==65561 && f->input[f->count]==0xde);
    f->input[24]=0; f->input[25]=0;
    CHECK(matter_message_header_read(f->input,26,&f->header,&f->count)==MATTER_MESSAGE_OK);
    CHECK(f->count==26);
    return true;
}

static bool test_all_flags(Fixture* f) {
    /* All 65536 pairs. Security/session ADDRESS policy is intentionally separate. */
    memset(f->input,0,32);
    for (unsigned message=0;message<256;++message) for (unsigned security=0;security<256;++security) {
        f->input[0]=(uint8_t)message; f->input[3]=(uint8_t)security;
        reset(f);
        bool invalid=(message>>4)!=0 || (message&3)==3 || (security&3)>=2;
        Matter_Message_Result_T expected=invalid ? MATTER_MESSAGE_INVALID_ENCODING :
            (security&0x80) ? MATTER_MESSAGE_UNSUPPORTED : MATTER_MESSAGE_OK;
        CHECK(matter_message_header_read(f->input,32,&f->header,&f->count)==expected);
        if (expected!=MATTER_MESSAGE_OK) CHECK(unchanged(f));
        else {
            size_t fixed=8+((message&4) ? 8 : 0)+((message&3)==1 ? 8 : (message&3)==2 ? 2 : 0);
            CHECK(f->count==fixed+((security&0x20) ? 2 : 0));
            CHECK(f->header.message_flags==message && f->header.security_flags==security);
        }
        Matter_Message_Header_T header={.message_flags=(uint8_t)message,.security_flags=(uint8_t)security};
        reset(f);
        if (expected==MATTER_MESSAGE_OK && (security&0x20)) expected=MATTER_MESSAGE_UNSUPPORTED;
        CHECK(matter_message_header_write(&header,f->output,sizeof(f->output),&f->count)==expected);
        if (expected!=MATTER_MESSAGE_OK) CHECK(unchanged(f));
        else CHECK(f->output[0]==(message&7) && f->output[3]==(security&0x43));
    }
    return true;
}

static bool test_arguments_and_retry(Fixture* f) {
    Matter_Message_Header_T header={0};
    reset(f);
    CHECK(matter_message_header_read(NULL,1,&f->header,&f->count)==MATTER_MESSAGE_INVALID_ARGUMENT);
    CHECK(matter_message_header_read(f->input,8,NULL,&f->count)==MATTER_MESSAGE_INVALID_ARGUMENT);
    CHECK(matter_message_header_read(f->input,8,&f->header,NULL)==MATTER_MESSAGE_INVALID_ARGUMENT);
    CHECK(matter_message_header_write(NULL,f->output,32,&f->count)==MATTER_MESSAGE_INVALID_ARGUMENT);
    CHECK(matter_message_header_write(&header,NULL,1,&f->count)==MATTER_MESSAGE_INVALID_ARGUMENT);
    CHECK(matter_message_header_write(&header,f->output,32,NULL)==MATTER_MESSAGE_INVALID_ARGUMENT);
    CHECK(matter_message_header_write(&header,NULL,0,&f->count)==MATTER_MESSAGE_NO_SPACE);
    CHECK(unchanged(f));
    header.message_flags=2; header.destination_id=65536;
    CHECK(matter_message_header_write(&header,f->output,32,&f->count)==MATTER_MESSAGE_INVALID_ARGUMENT);
    CHECK(unchanged(f));
    header.destination_id=UINT64_MAX;
    CHECK(matter_message_header_write(&header,f->output,32,&f->count)==MATTER_MESSAGE_INVALID_ARGUMENT);
    CHECK(unchanged(f));
    header.destination_id=65535;
    CHECK(matter_message_header_write(&header,f->output,10,&f->count)==MATTER_MESSAGE_OK);
    CHECK(f->count==10 && f->output[8]==255 && f->output[9]==255);
    /* Inactive values ignored; decode clears absent IDs, including after reuse. */
    header.message_flags=0; header.source_node_id=UINT64_MAX;
    CHECK(matter_message_header_write(&header,f->output,8,&f->count)==MATTER_MESSAGE_OK);
    CHECK(matter_message_header_read(f->output,8,&f->header,&f->count)==MATTER_MESSAGE_OK);
    CHECK(f->count==8 && !f->header.source_node_id && !f->header.destination_id);
    /* Misaligned wire storage and a separate buffer. */
    CHECK(matter_message_header_write(&header,f->input+1,8,&f->count)==MATTER_MESSAGE_OK);
    CHECK(matter_message_header_read(f->input+1,8,&f->header,&f->count)==MATTER_MESSAGE_OK);
    CHECK(f->count==8 && f->header.message_flags==0);
    return true;
}

int main(void) {
    Fixture* f=malloc(sizeof(*f));
    if (!f) return 1;
    static const struct { const char* name; bool (*run)(Fixture*); } tests[]={
        {"vectors, prefixes and capacity",test_vectors},
        {"extensions and length bounds",test_extensions},
        {"all flag combinations",test_all_flags},
        {"arguments and retry",test_arguments_and_retry}
    };
    for (size_t i=0;i<sizeof(tests)/sizeof(tests[0]);++i) {
        if (!tests[i].run(f)) { free(f); return 1; }
        printf("PASS message header: %s\n",tests[i].name);
    }
    free(f);
    return 0;
}
