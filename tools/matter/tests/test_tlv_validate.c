#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "codec/matter_tlv_validate.h"
#include "test_tlv_reference.h"

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr,"%s:%d %s: %s\n",__FILE__,__LINE__,__func__,#condition); \
    return false; } } while (0)

/* Host fixtures live on heap, including both workspaces and slot arrays. */
typedef struct {
    Matter_Tlv_Validation_Workspace_T workspace[2];
    Matter_Tlv_Tag_T tags[2][16];
    Matter_Tlv_Validation_Report_T report[2];
} Fixture;

static Matter_Tlv_Validation_Options_T defaults(void) {
    return (Matter_Tlv_Validation_Options_T){.max_bytes=128,.max_tokens=128,
        .max_comparisons=128,.max_depth=16};
}

static Matter_Tlv_Result_T run(Fixture* f, unsigned i, const void* data, size_t size,
    const Matter_Tlv_Validation_Options_T* options, size_t capacity) {
    return matter_tlv_validate(data,size,options,&f->workspace[i],f->tags[i],capacity,&f->report[i]);
}

#define V(s) {s,sizeof(s)-1}
static bool test_reference_and_prefixes(Fixture* f) {
    Matter_Tlv_Validation_Options_T options=defaults();
    options.has_implicit_profile=true;
    for(size_t i=0;i<sizeof(tlv_reference)/sizeof(tlv_reference[0]);++i) {
        const Tlv_Reference_Case* v=&tlv_reference[i];
        CHECK(run(f,0,v->data,v->size,&options,16)==MATTER_TLV_OK);
        CHECK(f->report[0].offset==v->size);
        for(size_t cut=0;cut<v->size;++cut) {
            CHECK(run(f,0,v->data,cut,&options,16)==MATTER_TLV_TRUNCATED);
            CHECK(f->report[0].offset<=cut);
        }
    }
    return true;
}

static bool test_equivalent_tags(Fixture* f) {
    /* Same profile-specific number 1 or 65536 in common, implicit and fully
     * qualified forms. The same tuple is a duplicate regardless of wire form.
     */
    static const struct { const char* data; size_t size; } tags[]={
        V("\x54\1\0"),V("\x94\1\0"),V("\xd4\0\0\0\0\1\0"),
        V("\x74\0\0\1\0"),V("\xb4\0\0\1\0"),V("\xf4\0\0\0\0\0\0\1\0")
    };
    Matter_Tlv_Validation_Options_T options=defaults();
    options.has_implicit_profile=true; /* Explicitly common 0/0. */
    for (size_t a=0;a<6;++a) for (size_t b=0;b<6;++b) {
        uint8_t bytes[20]={0x15};
        memcpy(bytes+1,tags[a].data,tags[a].size);
        memcpy(bytes+1+tags[a].size,tags[b].data,tags[b].size);
        size_t size=2+tags[a].size+tags[b].size;
        bytes[size-1]=0x18;
        bool duplicate=a/3==b/3;
        CHECK(run(f,0,bytes,size,&options,2)==(duplicate ? MATTER_TLV_DUPLICATE_TAG : MATTER_TLV_OK));
        CHECK(f->report[0].comparisons==1);
        CHECK(f->report[0].offset==(duplicate ? 1+tags[a].size : size));
    }
    /* Type/value differ; tags remain equal. */
    static const char context[]="\x15\x24\1\x2a\x34\1\x18";
    CHECK(run(f,0,context,sizeof(context)-1,&options,2)==MATTER_TLV_DUPLICATE_TAG);
    CHECK(f->report[0].offset==4 && f->report[0].tokens==3);
    /* Nonzero profile match, both 16-bit and 32-bit tag numbers. */
    options.implicit_vendor=0xfff1; options.implicit_profile=0xdeed;
    static const char custom[]="\x15\x94\1\0\xd4\xf1\xff\xed\xde\1\0\x18";
    CHECK(run(f,0,custom,sizeof(custom)-1,&options,2)==MATTER_TLV_DUPLICATE_TAG);
    static const char custom32[]="\x15\xb4\xff\xff\xff\xff\xf4\xf1\xff\xed\xde\xff\xff\xff\xff\x18";
    CHECK(run(f,0,custom32,sizeof(custom32)-1,&options,2)==MATTER_TLV_DUPLICATE_TAG);
    options.implicit_profile++;
    CHECK(run(f,0,custom,sizeof(custom)-1,&options,2)==MATTER_TLV_OK);
    options.implicit_profile--; options.implicit_vendor++;
    CHECK(run(f,0,custom,sizeof(custom)-1,&options,2)==MATTER_TLV_OK);
    /* Context 1, common 1, vendor 1/profile 0/tag 1, vendor 0/profile 1/tag 1. */
    static const char distinct[]="\x15\x34\1\x54\1\0\xd4\1\0\0\0\1\0\xd4\0\0\1\0\1\0\x18";
    CHECK(run(f,0,distinct,sizeof(distinct)-1,&options,4)==MATTER_TLV_OK);
    return true;
}

static bool test_scopes_and_slots(Fixture* f) {
    Matter_Tlv_Validation_Options_T options=defaults();
    /* Outer context 1 is a structure with its own context 1. Then another
     * structure at context 2 also has context 1. Child slots must be reclaimed.
     */
    static const char nested[]="\x15\x35\1\x34\1\x18\x35\2\x34\1\x18\x18";
    CHECK(run(f,0,nested,sizeof(nested)-1,&options,3)==MATTER_TLV_OK);
    CHECK(f->report[0].peak_tags==3 && f->report[0].comparisons==1);
    CHECK(run(f,0,nested,sizeof(nested)-1,&options,2)==MATTER_TLV_LIMIT_REACHED);
    CHECK(f->report[0].offset==8 && f->report[0].peak_tags==2);
    static const char parent_duplicate[]="\x15\x35\1\x34\2\x18\x34\1\x18";
    CHECK(run(f,0,parent_duplicate,sizeof(parent_duplicate)-1,&options,2)==MATTER_TLV_DUPLICATE_TAG);
    CHECK(f->report[0].offset==6);
    static const char child_duplicate[]="\x15\x35\1\x34\2\x34\2\x18\x18";
    CHECK(run(f,0,child_duplicate,sizeof(child_duplicate)-1,&options,2)==MATTER_TLV_DUPLICATE_TAG);
    /* Lists accept repeated context and profile tags with zero slots/comparisons. */
    static const char list[]="\x17\x34\1\x34\1\x54\1\0\xd4\0\0\0\0\1\0\x18";
    options.max_comparisons=0;
    CHECK(run(f,0,list,sizeof(list)-1,&options,0)==MATTER_TLV_OK);
    CHECK(f->report[0].peak_tags==0 && f->report[0].comparisons==0);
    /* Sibling structures inside a list/array reuse the same one slot. */
    static const char siblings[]="\x16\x15\x34\1\x18\x15\x34\1\x18\x18";
    CHECK(run(f,0,siblings,sizeof(siblings)-1,&options,1)==MATTER_TLV_OK);
    CHECK(f->report[0].peak_tags==1);
    /* Parent keys survive list and array frames, including nested structures. */
    static const char through_list[]="\x15\x37\1\x16\x15\x34\1\x18\x18\x18\x34\1\x18";
    options.max_comparisons=128;
    CHECK(run(f,0,through_list,sizeof(through_list)-1,&options,2)==MATTER_TLV_DUPLICATE_TAG);
    CHECK(f->report[0].offset==10);
    return true;
}

static bool test_implicit_context_and_reuse(Fixture* f) {
    static const struct { const char* data; size_t size; size_t offset; } cases[]={
        {"\x94\1\0",3,0}, {"\x17\x94\1\0\x18",5,1},
        {"\xd5\xf1\xff\xed\xde\1\0\x94\1\0\x18",11,7}
    };
    Matter_Tlv_Validation_Options_T first=defaults(), second=defaults();
    second.has_implicit_profile=true; second.implicit_vendor=0xfff1; second.implicit_profile=0xdeed;
    for (size_t i=0;i<sizeof(cases)/sizeof(cases[0]);++i) {
        CHECK(run(f,0,cases[i].data,cases[i].size,&first,16)==MATTER_TLV_PROFILE_REQUIRED);
        CHECK(f->report[0].offset==cases[i].offset);
        CHECK(run(f,1,cases[i].data,cases[i].size,&second,16)==MATTER_TLV_OK);
        CHECK(f->report[0].offset==cases[i].offset); /* Separate reports/workspaces. */
        CHECK(run(f,0,cases[i].data,cases[i].size,&second,16)==MATTER_TLV_OK);
        CHECK(run(f,1,cases[i].data,cases[i].size,&first,16)==MATTER_TLV_PROFILE_REQUIRED);
    }
    /* All 16-bit profile components are representable, not a magic sentinel. */
    second.implicit_vendor=UINT16_MAX; second.implicit_profile=UINT16_MAX;
    CHECK(run(f,0,"\x94\1\0",3,&second,0)==MATTER_TLV_OK);
    return true;
}

static bool test_budgets(Fixture* f) {
    static const char three[]="\x15\x34\1\x34\2\x34\3\x18";
    Matter_Tlv_Validation_Options_T options=defaults();
    options.max_bytes=sizeof(three)-1; options.max_tokens=5; options.max_comparisons=3;
    CHECK(run(f,0,three,sizeof(three)-1,&options,3)==MATTER_TLV_OK);
    CHECK(f->report[0].tokens==5 && f->report[0].comparisons==3 && f->report[0].peak_tags==3);
    options.max_bytes--;
    CHECK(run(f,0,three,sizeof(three)-1,&options,3)==MATTER_TLV_LIMIT_REACHED);
    CHECK(f->report[0].offset==0 && f->report[0].tokens==0);
    options.max_bytes++;
    options.max_tokens--;
    CHECK(run(f,0,three,sizeof(three)-1,&options,3)==MATTER_TLV_LIMIT_REACHED);
    CHECK(f->report[0].offset==7 && f->report[0].tokens==4);
    options.max_tokens++;
    options.max_comparisons--;
    CHECK(run(f,0,three,sizeof(three)-1,&options,3)==MATTER_TLV_LIMIT_REACHED);
    CHECK(f->report[0].offset==5 && f->report[0].comparisons==2);
    options.max_comparisons++;
    CHECK(run(f,0,three,sizeof(three)-1,&options,2)==MATTER_TLV_LIMIT_REACHED);
    CHECK(f->report[0].peak_tags==2);
    options.max_tokens=0;
    CHECK(run(f,0,"\x14",1,&options,0)==MATTER_TLV_LIMIT_REACHED);
    CHECK(f->report[0].tokens==0);
    CHECK(run(f,0,NULL,0,&options,0)==MATTER_TLV_TRUNCATED);
    options.max_tokens=1;
    CHECK(run(f,0,"\x14",1,&options,0)==MATTER_TLV_OK);
    CHECK(run(f,0,"\x15",1,&options,0)==MATTER_TLV_TRUNCATED); /* EOF is free. */
    options=defaults(); options.max_depth=1;
    CHECK(run(f,0,"\x16\x16\x18\x18",4,&options,0)==MATTER_TLV_DEPTH_LIMIT);
    CHECK(f->report[0].offset==1 && f->report[0].tokens==1);
    uint8_t nested[32]; memset(nested,0x16,16); memset(nested+16,0x18,16);
    options.max_depth=16; options.max_tokens=32;
    CHECK(run(f,0,nested,sizeof(nested),&options,0)==MATTER_TLV_OK);
    /* Message byte limit bounds UTF-8 work before the reader touches payload. */
    options.max_bytes=3;
    CHECK(run(f,0,"\x0c\x03" "abc",5,&options,0)==MATTER_TLV_LIMIT_REACHED);
    CHECK(f->report[0].tokens==0);
    return true;
}

static bool poisoned(const void* data, size_t size) {
    const unsigned char* bytes=data;
    for (size_t i=0;i<size;++i) if (bytes[i]!=0xa5) return false;
    return true;
}

static bool test_arguments_and_syntax(Fixture* f) {
    Matter_Tlv_Validation_Options_T options=defaults();
    memset(f,0xa5,sizeof(*f));
    CHECK(run(f,0,NULL,1,&options,1)==MATTER_TLV_INVALID_ARGUMENT);
    CHECK(run(f,0,NULL,0,NULL,1)==MATTER_TLV_INVALID_ARGUMENT);
    CHECK(matter_tlv_validate(NULL,0,&options,NULL,NULL,0,&f->report[0])==MATTER_TLV_INVALID_ARGUMENT);
    CHECK(matter_tlv_validate(NULL,0,&options,&f->workspace[0],NULL,1,&f->report[0])==MATTER_TLV_INVALID_ARGUMENT);
    CHECK(matter_tlv_validate(NULL,0,&options,&f->workspace[0],NULL,0,NULL)==MATTER_TLV_INVALID_ARGUMENT);
    CHECK(run(f,0,NULL,0,&options,SIZE_MAX)==MATTER_TLV_INVALID_ARGUMENT);
    options.max_depth=0;
    CHECK(run(f,0,NULL,0,&options,0)==MATTER_TLV_INVALID_ARGUMENT);
    options.max_depth=17;
    CHECK(run(f,0,NULL,0,&options,0)==MATTER_TLV_INVALID_ARGUMENT);
    CHECK(poisoned(f,sizeof(*f)));
    options=defaults();
    CHECK(matter_tlv_validate((const uint8_t*)"\x14",1,&options,&f->workspace[0],NULL,0,&f->report[0])==MATTER_TLV_OK);
    static const struct { const char* data; size_t size; } invalid[]={
        V("\x15\x14\x18"),V("\x16\x34\1\x18"),V("\x34\1"),V("\x18"),
        V("\x14\x14"),V("\x19"),V("\x0c\2\xc0\xaf"),V("\x74\1\0\0\0")
    };
    for (size_t i=0;i<sizeof(invalid)/sizeof(invalid[0]);++i)
        CHECK(run(f,0,invalid[i].data,invalid[i].size,&options,16)==MATTER_TLV_INVALID_ENCODING);
    /* Truncated enormous string length remains a reader error, no arithmetic overflow. */
    CHECK(run(f,0,"\x13\xff\xff\xff\xff\xff\xff\xff\xff",9,&options,0)==MATTER_TLV_TRUNCATED);
    CHECK(run(f,0,"\x15\x34\1\x18",4,&options,0)==MATTER_TLV_LIMIT_REACHED);
    CHECK(run(f,0,"\x15\x34\1\x18",4,&options,1)==MATTER_TLV_OK);
    return true;
}

int main(void) {
    const struct { const char* name; bool (*run)(Fixture*); } tests[]={
        {"synthetic matrix and every prefix",test_reference_and_prefixes},
        {"normalized duplicate tags and namespaces",test_equivalent_tags},
        {"nested scopes, lists and slot reclamation",test_scopes_and_slots},
        {"explicit implicit profile and two workspaces",test_implicit_context_and_reuse},
        {"byte/token/comparison/slot/depth budgets",test_budgets},
        {"arguments, syntax errors and recovery",test_arguments_and_syntax}
    };
    unsigned failures=0;
    for (size_t i=0;i<sizeof(tests)/sizeof(tests[0]);++i) {
        Fixture* fixture=malloc(sizeof(*fixture));
        bool passed=false;
        if (fixture) { memset(fixture,0xa5,sizeof(*fixture)); passed=tests[i].run(fixture); free(fixture); }
        printf("%s tlv validate: %s\n",passed ? "PASS" : "FAIL",tests[i].name);
        if (!passed) ++failures;
    }
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
