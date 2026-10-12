#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "codec/matter_tlv.h"

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s:%d %s: %s\n", __FILE__, __LINE__, __func__, #condition); \
    return false; } } while (0)

#include "test_tlv_reference.h"

/* Small hand-written boundary cases below do not need semantic token lists. */
typedef struct {
    const uint8_t* data;
    size_t size, tokens;
    Matter_Tlv_Type_T first_type;
    uint64_t u;
    int64_t s;
} Vector;
#define V(bytes, count, type, u, s) {(const uint8_t*)(bytes), sizeof(bytes)-1, count, type, u, s}

static Matter_Tlv_Result_T scan(const uint8_t* data, size_t size, size_t* count) {
    Matter_Tlv_Reader_T reader;
    Matter_Tlv_Element_T element;
    Matter_Tlv_Result_T result = matter_tlv_init(&reader, data, size, MATTER_TLV_MAX_DEPTH);
    *count = 0;
    if (result != MATTER_TLV_OK) return result;
    while ((result = matter_tlv_next(&reader, &element)) == MATTER_TLV_OK) {
        if (++*count > size || reader.offset > size) abort();
    }
    return result;
}

static bool test_reference_vectors_and_all_prefixes(void) {
    for(size_t i=0;i<sizeof(tlv_reference)/sizeof(tlv_reference[0]);++i) {
        const Tlv_Reference_Case* v=&tlv_reference[i];
        Matter_Tlv_Reader_T reader; Matter_Tlv_Element_T element; size_t count;
        CHECK(matter_tlv_init(&reader,v->data,v->size,8)==MATTER_TLV_OK);
        for(size_t j=0;j<v->count;++j) {
            const Matter_Tlv_Element_T* expected=&v->tokens[j].element;
            CHECK(matter_tlv_next(&reader,&element)==MATTER_TLV_OK);
            CHECK(element.type==expected->type && element.unsigned_value==expected->unsigned_value && element.signed_value==expected->signed_value);
            CHECK(element.tag.control==expected->tag.control && element.tag.number==expected->tag.number);
            CHECK(element.tag.vendor==expected->tag.vendor && element.tag.profile==expected->tag.profile);
            if(element.type==MATTER_TLV_UTF8 || element.type==MATTER_TLV_BYTES) {
                CHECK(element.size==expected->size && !memcmp(element.data,expected->data,element.size));
            }
        }
        CHECK(scan(v->data,v->size,&count)==MATTER_TLV_DONE && count==v->count);
        for(size_t cut=0;cut<v->size;++cut) CHECK(scan(v->data,cut,&count)==MATTER_TLV_TRUNCATED);
    }
    return true;
}

static bool test_tags_and_values(void) {
    /* All tag controls in a list (context tags cannot stand alone at root). */
    static const uint8_t data[] = {
        0x17, 0x04,42, 0x24,1,42, 0x44,1,0,42, 0x64,0xa0,0x86,1,0,42,
        0x84,2,0,42, 0xa4,0,0,1,0,42, 0xc4,0xf1,0xff,0xed,0xde,1,0,42,
        0xe4,0xf1,0xff,0xed,0xde,0xed,0xfe,0x55,0xaa,42, 0x18
    };
    static const uint32_t numbers[] = {0,1,1,100000,2,65536,1,UINT32_C(0xaa55feed)};
    Matter_Tlv_Reader_T reader;
    Matter_Tlv_Element_T element;
    CHECK(matter_tlv_init(&reader, data, sizeof(data), 2) == MATTER_TLV_OK);
    CHECK(matter_tlv_next(&reader, &element) == MATTER_TLV_OK && element.type == MATTER_TLV_LIST);
    for (unsigned i = 0; i < 8; ++i) {
        CHECK(matter_tlv_next(&reader, &element) == MATTER_TLV_OK);
        CHECK(element.tag.control == i && element.tag.number == numbers[i]);
        CHECK(element.unsigned_value == 42);
        CHECK(element.tag.vendor == (i >= 6 ? 65521 : 0));
        CHECK(element.tag.profile == (i >= 6 ? 57069 : 0));
    }
    CHECK(matter_tlv_next(&reader, &element) == MATTER_TLV_OK && element.type == MATTER_TLV_END);
    CHECK(matter_tlv_next(&reader, &element) == MATTER_TLV_DONE);
    return true;
}

static bool test_lengths_and_integer_boundaries(void) {
    Matter_Tlv_Reader_T reader;
    Matter_Tlv_Element_T element;
    for (unsigned width = 0; width < 4; ++width) {
        uint8_t data[12] = {0};
        size_t length_size = (size_t)1 << width;
        data[0] = (uint8_t)(0x10 + width); data[1] = 2;
        data[1 + length_size] = 0; data[2 + length_size] = 0xff;
        CHECK(matter_tlv_init(&reader, data, 3 + length_size, 1) == MATTER_TLV_OK);
        CHECK(matter_tlv_next(&reader, &element) == MATTER_TLV_OK && element.size == 2);
        CHECK(element.data[0] == 0 && element.data[1] == 255);
        CHECK(matter_tlv_next(&reader, &element) == MATTER_TLV_DONE);
        /* Each signed/unsigned width, including the 64-bit sign boundary. */
        memset(data, 0, sizeof(data));
        data[0] = (uint8_t)width;
        data[length_size] = 0x80;
        uint64_t sign = UINT64_C(1) << (length_size * 8 - 1);
        int64_t expected_minimum = -1 - (int64_t)(sign - 1);
        CHECK(matter_tlv_init(&reader, data, 1 + length_size, 1) == MATTER_TLV_OK);
        CHECK(matter_tlv_next(&reader, &element) == MATTER_TLV_OK && element.signed_value == expected_minimum);
        data[0] = (uint8_t)(4 + width);
        memset(data + 1, 0xff, length_size);
        uint64_t expected_maximum = length_size == 8 ? UINT64_MAX : (UINT64_C(1) << (length_size * 8)) - 1;
        CHECK(matter_tlv_init(&reader, data, 1 + length_size, 1) == MATTER_TLV_OK);
        CHECK(matter_tlv_next(&reader, &element) == MATTER_TLV_OK && element.unsigned_value == expected_maximum);
    }
    static const uint8_t minimum[] = {3,0,0,0,0,0,0,0,0x80};
    static const uint8_t maximum[] = {7,255,255,255,255,255,255,255,255};
    static const uint8_t huge_length[] = {0x13,255,255,255,255,255,255,255,255};
    CHECK(matter_tlv_init(&reader, minimum, sizeof(minimum), 1) == MATTER_TLV_OK);
    CHECK(matter_tlv_next(&reader, &element) == MATTER_TLV_OK && element.signed_value == INT64_MIN);
    CHECK(matter_tlv_init(&reader, maximum, sizeof(maximum), 1) == MATTER_TLV_OK);
    CHECK(matter_tlv_next(&reader, &element) == MATTER_TLV_OK && element.unsigned_value == UINT64_MAX);
    CHECK(matter_tlv_init(&reader, huge_length, sizeof(huge_length), 1) == MATTER_TLV_OK);
    CHECK(matter_tlv_next(&reader, &element) == MATTER_TLV_TRUNCATED && reader.offset == 0);
    CHECK(element.unsigned_value == UINT64_MAX); /* Failure leaves output intact. */
    CHECK(matter_tlv_next(&reader, &element) == MATTER_TLV_TRUNCATED);
    return true;
}

static bool test_invalid_framing_and_arguments(void) {
    static const Vector invalid[] = {
        V("\x18",0,0,0,0), V("\x24\x01\x2a",0,0,0,0), /* root context */
        V("\x15\x04\x2a\x18",0,0,0,0), /* anonymous struct member */
        V("\x16\x24\x01\x2a\x18",0,0,0,0), /* tagged array member */
        V("\x08\x09",0,0,0,0), V("\x15\x18\x18",0,0,0,0),
        V("\x64\x01\x00\x00\x00\x2a",0,0,0,0) /* non-minimal tag */
    };
    size_t count;
    Matter_Tlv_Reader_T reader;
    Matter_Tlv_Element_T element;
    CHECK(matter_tlv_init(NULL,NULL,0,1) == MATTER_TLV_INVALID_ARGUMENT);
    CHECK(matter_tlv_init(&reader,NULL,1,1) == MATTER_TLV_INVALID_ARGUMENT);
    CHECK(matter_tlv_init(&reader,NULL,0,0) == MATTER_TLV_INVALID_ARGUMENT);
    CHECK(matter_tlv_init(&reader,NULL,0,17) == MATTER_TLV_INVALID_ARGUMENT);
    CHECK(matter_tlv_next(NULL,&element) == MATTER_TLV_INVALID_ARGUMENT);
    CHECK(matter_tlv_skip_container(NULL) == MATTER_TLV_INVALID_ARGUMENT);
    CHECK(matter_tlv_init(&reader,NULL,0,1) == MATTER_TLV_OK);
    CHECK(matter_tlv_next(&reader,NULL) == MATTER_TLV_INVALID_ARGUMENT);
    CHECK(matter_tlv_next(&reader,&element) == MATTER_TLV_TRUNCATED);
    for (size_t i = 0; i < sizeof(invalid)/sizeof(invalid[0]); ++i)
        CHECK(scan(invalid[i].data,invalid[i].size,&count) == MATTER_TLV_INVALID_ENCODING);
    for (unsigned control = 0; control < 256; ++control) {
        if ((control & 31) < 24 || control == 24) continue;
        uint8_t data = (uint8_t)control;
        CHECK(scan(&data,1,&count) == MATTER_TLV_INVALID_ENCODING);
    }
    return true;
}

static bool test_skip_depth_and_two_readers(void) {
    static const uint8_t data[] = {0x15,0x36,99,0x17,0x09,0x18,0x18,0x24,1,42,0x18};
    Matter_Tlv_Reader_T first, second;
    Matter_Tlv_Element_T element;
    CHECK(matter_tlv_init(&first,data,sizeof(data),3) == MATTER_TLV_OK);
    CHECK(matter_tlv_init(&second,data,sizeof(data),2) == MATTER_TLV_OK);
    CHECK(matter_tlv_skip_container(&first) == MATTER_TLV_INVALID_ARGUMENT);
    CHECK(matter_tlv_next(&first,&element) == MATTER_TLV_OK);
    CHECK(matter_tlv_next(&first,&element) == MATTER_TLV_OK && element.tag.number == 99);
    CHECK(matter_tlv_skip_container(&first) == MATTER_TLV_OK);
    CHECK(matter_tlv_next(&first,&element) == MATTER_TLV_OK && element.tag.number == 1 && element.unsigned_value == 42);
    CHECK(matter_tlv_skip_container(&first) == MATTER_TLV_INVALID_ARGUMENT);
    CHECK(matter_tlv_next(&second,&element) == MATTER_TLV_OK);
    CHECK(matter_tlv_skip_container(&second) == MATTER_TLV_DEPTH_LIMIT && second.offset == 3);
    CHECK(matter_tlv_next(&first,&element) == MATTER_TLV_OK);
    CHECK(matter_tlv_next(&first,&element) == MATTER_TLV_DONE);
    uint8_t nested[2 * MATTER_TLV_MAX_DEPTH];
    memset(nested,0x16,MATTER_TLV_MAX_DEPTH);
    memset(nested+MATTER_TLV_MAX_DEPTH,0x18,MATTER_TLV_MAX_DEPTH);
    size_t count;
    CHECK(scan(nested,sizeof(nested),&count) == MATTER_TLV_DONE && count == sizeof(nested));
    CHECK(matter_tlv_init(&first,data,sizeof(data)-5,3) == MATTER_TLV_OK);
    CHECK(matter_tlv_next(&first,&element) == MATTER_TLV_OK);
    CHECK(matter_tlv_skip_container(&first) == MATTER_TLV_TRUNCATED);
    return true;
}

static bool test_utf8(void) {
    static const Vector invalid[] = {
        V("\x0c\x01\x80",0,0,0,0), V("\x0c\x02\xc0\xaf",0,0,0,0),
        V("\x0c\x02\xc2\x20",0,0,0,0), V("\x0c\x02\xe2\x82",0,0,0,0),
        V("\x0c\x03\xe0\x80\x80",0,0,0,0), V("\x0c\x03\xed\xa0\x80",0,0,0,0),
        V("\x0c\x04\xf0\x80\x80\x80",0,0,0,0), V("\x0c\x04\xf4\x90\x80\x80",0,0,0,0),
        V("\x0c\x01\xf5",0,0,0,0)
    };
    static const Vector valid[] = {
        V("\x0c\x00",0,0,0,0), V("\x0c\x02\xc2\x80",0,0,0,0),
        V("\x0c\x03\xe0\xa0\x80",0,0,0,0), V("\x0c\x03\xed\x9f\xbf",0,0,0,0),
        V("\x0c\x04\xf0\x90\x80\x80",0,0,0,0), V("\x0c\x04\xf4\x8f\xbf\xbf",0,0,0,0),
        V("\x0c\x03\x00\x41\x00",0,0,0,0)
    };
    size_t count;
    for (size_t i = 0; i < sizeof(invalid)/sizeof(invalid[0]); ++i)
        CHECK(scan(invalid[i].data,invalid[i].size,&count) == MATTER_TLV_INVALID_ENCODING);
    for (size_t i = 0; i < sizeof(valid)/sizeof(valid[0]); ++i)
        CHECK(scan(valid[i].data,valid[i].size,&count) == MATTER_TLV_DONE);
    return true;
}

static bool test_all_two_byte_inputs(void) {
    uint8_t data[2];
    for (unsigned value = 0; value < 65536; ++value) {
        data[0] = (uint8_t)value; data[1] = (uint8_t)(value >> 8);
        size_t count;
        Matter_Tlv_Result_T result = scan(data,sizeof(data),&count);
        CHECK(result == MATTER_TLV_DONE || result == MATTER_TLV_TRUNCATED || result == MATTER_TLV_INVALID_ENCODING);
    }
    return true;
}

int main(void) {
    const struct { const char* name; bool (*run)(void); } tests[] = {
        {"synthetic matrix and every prefix",test_reference_vectors_and_all_prefixes},
        {"all tag forms and container values",test_tags_and_values},
        {"length widths and integer boundaries",test_lengths_and_integer_boundaries},
        {"framing and arguments",test_invalid_framing_and_arguments},
        {"skip/depth/two readers",test_skip_depth_and_two_readers},
        {"UTF-8 validation",test_utf8},
        {"all 65536 two-byte inputs",test_all_two_byte_inputs},
    };
    unsigned failures = 0;
    for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); ++i) {
        bool passed = tests[i].run();
        printf("%s tlv: %s\n",passed ? "PASS" : "FAIL",tests[i].name);
        if (!passed) ++failures;
    }
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
