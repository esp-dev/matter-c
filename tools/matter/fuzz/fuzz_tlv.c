#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "codec/matter_tlv_writer.h"
#include "codec/matter_tlv_validate.h"

#define MAX_INPUT 4096
#define REQUIRE(c) do { if (!(c)) { fprintf(stderr,"fuzz invariant line %d: %s\n",__LINE__,#c); abort(); } } while (0)

/* Per invocation, on heap. No retained state between test cases. */
typedef struct {
    uint8_t encoded[MAX_INPUT], output[MAX_INPUT], before[MAX_INPUT];
    Matter_Tlv_Validation_Workspace_T validation;
    Matter_Tlv_Tag_T tags[64];
} Scratch;

static uint8_t byte(const uint8_t* data, size_t size, size_t index) {
    return index < size ? data[index] : 0;
}

static uint64_t number(const uint8_t* data, size_t size, size_t offset, size_t width) {
    uint64_t value=0;
    for (size_t i=0;i<width;++i) value |= (uint64_t)byte(data,size,offset+i)<<(8*i);
    return value;
}

static Matter_Tlv_Result_T scan_and_encode(const uint8_t* data, size_t size, Scratch* s) {
    Matter_Tlv_Reader_T reader;
    Matter_Tlv_Writer_T writer;
    Matter_Tlv_Element_T element={0}, saved;
    REQUIRE(matter_tlv_init(&reader,data,size,16)==MATTER_TLV_OK);
    REQUIRE(matter_tlv_writer_init(&writer,s->encoded,sizeof(s->encoded),16)==MATTER_TLV_OK);
    for (size_t steps=0;steps<=size;++steps) {
        size_t before=reader.offset;
        memcpy(&saved,&element,sizeof(saved));
        Matter_Tlv_Result_T result=matter_tlv_next(&reader,&element);
        REQUIRE(reader.offset<=size);
        if (result!=MATTER_TLV_OK) {
            REQUIRE(reader.offset==before && memcmp(&saved,&element,sizeof(saved))==0);
            REQUIRE(matter_tlv_next(&reader,&element)==result);
            REQUIRE(reader.offset==before && memcmp(&saved,&element,sizeof(saved))==0);
            size_t written=SIZE_MAX;
            if (result==MATTER_TLV_DONE) {
                REQUIRE(matter_tlv_writer_finish(&writer,&written)==MATTER_TLV_OK && written==size);
                REQUIRE(memcmp(data,s->encoded,size)==0);
            }
            REQUIRE(result==MATTER_TLV_DONE || result==MATTER_TLV_TRUNCATED ||
                result==MATTER_TLV_INVALID_ENCODING || result==MATTER_TLV_DEPTH_LIMIT);
            return result;
        }
        REQUIRE(reader.offset>before);
        uint8_t width=0;
        if (element.type==MATTER_TLV_SIGNED || element.type==MATTER_TLV_UNSIGNED) width=(uint8_t)element.size;
        if (element.type==MATTER_TLV_UTF8 || element.type==MATTER_TLV_BYTES)
            width=(uint8_t)(1u<<(data[element.offset]&3));
        REQUIRE(matter_tlv_write(&writer,&element,width)==MATTER_TLV_OK);
        REQUIRE(writer.size==reader.offset && memcmp(data,s->encoded,writer.size)==0);
    }
    REQUIRE(false); /* Every token consumes at least one byte. */
    return MATTER_TLV_INVALID_ENCODING;
}

static void validate(const uint8_t* data, size_t size, Scratch* s, Matter_Tlv_Result_T syntax) {
    Matter_Tlv_Validation_Options_T options={.max_bytes=MAX_INPUT,.max_tokens=MAX_INPUT,
        .max_comparisons=4096,.max_depth=16,.has_implicit_profile=true};
    for (unsigned pass=0;pass<2;++pass) {
        size_t slots=64;
        if (pass) {
            options.max_bytes=(size_t)byte(data,size,0)*16;
            options.max_tokens=byte(data,size,1);
            options.max_comparisons=byte(data,size,2);
            options.max_depth=(uint8_t)(1+byte(data,size,3)%16);
            options.has_implicit_profile=(byte(data,size,4)&1)!=0;
            options.implicit_vendor=(uint16_t)number(data,size,5,2);
            options.implicit_profile=(uint16_t)number(data,size,7,2);
            slots=byte(data,size,9)%65;
        }
        Matter_Tlv_Validation_Report_T report;
        Matter_Tlv_Result_T result=matter_tlv_validate(data,size,&options,&s->validation,s->tags,slots,&report);
        REQUIRE(report.offset<=size && report.tokens<=options.max_tokens);
        REQUIRE(report.comparisons<=options.max_comparisons && report.peak_tags<=slots);
        REQUIRE(result!=MATTER_TLV_INVALID_ARGUMENT && result!=MATTER_TLV_DONE && result!=MATTER_TLV_NO_SPACE);
        if (result==MATTER_TLV_OK) REQUIRE(syntax==MATTER_TLV_DONE && report.offset==size);
        if (!pass && syntax==MATTER_TLV_DONE)
            REQUIRE(result==MATTER_TLV_OK || result==MATTER_TLV_DUPLICATE_TAG || result==MATTER_TLV_LIMIT_REACHED);
    }
}

static void scan_with_skip(const uint8_t* data, size_t size, Matter_Tlv_Result_T expected) {
    Matter_Tlv_Reader_T reader;
    Matter_Tlv_Element_T element;
    REQUIRE(matter_tlv_init(&reader,data,size,16)==MATTER_TLV_OK);
    for (size_t steps=0;steps<=size;++steps) {
        Matter_Tlv_Result_T result=matter_tlv_next(&reader,&element);
        if (result==MATTER_TLV_OK && (element.type==MATTER_TLV_STRUCTURE ||
            element.type==MATTER_TLV_ARRAY || element.type==MATTER_TLV_LIST))
            result=matter_tlv_skip_container(&reader);
        REQUIRE(reader.offset<=size);
        if (result!=MATTER_TLV_OK) { REQUIRE(result==expected); return; }
    }
    REQUIRE(false);
}

static void write_checked(Matter_Tlv_Writer_T* writer, const Matter_Tlv_Element_T* value,
    uint8_t width, Scratch* s) {
    Matter_Tlv_Writer_T saved;
    memcpy(&saved,writer,sizeof(saved));
    memcpy(s->before,s->output,sizeof(s->output));
    Matter_Tlv_Result_T result=matter_tlv_write(writer,value,width);
    if (result!=MATTER_TLV_OK) {
        REQUIRE(memcmp(&saved,writer,sizeof(saved))==0);
        REQUIRE(memcmp(s->before,s->output,sizeof(s->output))==0);
    } else {
        REQUIRE(writer->size>saved.size && writer->size<=writer->capacity);
        REQUIRE(memcmp(s->before,s->output,saved.size)==0);
        REQUIRE(memcmp(s->before+writer->size,s->output+writer->size,MAX_INPUT-writer->size)==0);
    }
}

static void semantic_writer(const uint8_t* data, size_t size, Scratch* s) {
    Matter_Tlv_Writer_T writer;
    size_t capacity=(size_t)number(data,size,0,2)%(MAX_INPUT+1);
    REQUIRE(matter_tlv_writer_init(&writer,s->output,capacity,(uint8_t)(1+byte(data,size,2)%16))==MATTER_TLV_OK);
    memset(s->output,0xa5,sizeof(s->output));
    Matter_Tlv_Element_T start={.type=(byte(data,size,3)&1) ? MATTER_TLV_LIST : MATTER_TLV_STRUCTURE};
    write_checked(&writer,&start,0,s);
    uint64_t bits=number(data,size,10,8);
    Matter_Tlv_Element_T value={.type=(Matter_Tlv_Type_T)(byte(data,size,4)%15),
        .tag={.control=(uint8_t)(byte(data,size,5)%10),.number=(uint32_t)number(data,size,6,4)},
        .unsigned_value=bits,.signed_value=bits<=INT64_MAX ? (int64_t)bits : -1-(int64_t)(UINT64_MAX-bits),
        .data=data,.size=size};
    if (value.tag.control>=6) {
        value.tag.vendor=(uint16_t)number(data,size,18,2);
        value.tag.profile=(uint16_t)number(data,size,20,2);
    }
    static const uint8_t widths[]={0,1,2,4,8,3};
    write_checked(&writer,&value,widths[byte(data,size,22)%6],s);
    Matter_Tlv_Element_T end={.type=MATTER_TLV_END};
    /* At most two opens (wrapper and fuzzed token). */
    for (unsigned i=0;i<2 && writer.depth;++i) write_checked(&writer,&end,0,s);
    size_t written=SIZE_MAX;
    if (matter_tlv_writer_finish(&writer,&written)==MATTER_TLV_OK) {
        REQUIRE(written==writer.size);
        REQUIRE(scan_and_encode(s->output,written,s)==MATTER_TLV_DONE);
    } else REQUIRE(written==SIZE_MAX);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size>MAX_INPUT) return 0;
    Scratch* scratch=malloc(sizeof(*scratch));
    REQUIRE(scratch!=NULL);
    Matter_Tlv_Result_T syntax=scan_and_encode(data,size,scratch);
    scan_with_skip(data,size,syntax);
    validate(data,size,scratch,syntax);
    semantic_writer(data,size,scratch);
    free(scratch);
    return 0;
}

#ifdef MATTER_FUZZ_STANDALONE
/* Portable replay of exact raw corpus/crash files; no libFuzzer dependency. */
int main(int argc, char** argv) {
    uint8_t* data=malloc(MAX_INPUT+1);
    if (!data) return EXIT_FAILURE;
    LLVMFuzzerTestOneInput((const uint8_t*)"",0);
    for (int i=1;i<argc;++i) {
        FILE* file=fopen(argv[i],"rb");
        if (!file) { free(data); return EXIT_FAILURE; }
        size_t size=fread(data,1,MAX_INPUT+1,file);
        bool failed=ferror(file)!=0 || size>MAX_INPUT;
        if (fclose(file)!=0) failed=true;
        if (failed) { free(data); return EXIT_FAILURE; }
        LLVMFuzzerTestOneInput(data,size);
    }
    free(data);
    printf("PASS fuzz replay: empty input + %d files\n",argc-1);
    return EXIT_SUCCESS;
}
#endif
