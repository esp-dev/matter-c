#include <matter.h>
#include <crypto/matter_crypto_mbedtls.h>
#include <codec/matter_tlv_writer.h>

/* Uses only installed headers; force linkage of lifecycle, codec and crypto. */
int main(void) {
    Matter_T first = matter_new(NULL), second = matter_new(NULL);
    if (!first || !second) {
        matter_delete(first); matter_delete(second); return 1;
    }
    int result = matter_start(first) != MATTER_OK || matter_start(second) != MATTER_OK;
    Matter_Crypto_Mbedtls_T crypto = matter_crypto_mbedtls_new(NULL);
    uint8_t output[32];
    Matter_Tlv_Writer_T writer;
    if (!crypto || matter_tlv_writer_init(&writer, output, sizeof(output), 4) != MATTER_TLV_OK) result = 1;
    if (matter_crypto_mbedtls_delete(crypto) != MATTER_OK) result = 1;
    if (matter_stop(first) != MATTER_OK || matter_stop(second) != MATTER_OK) result = 1;
    if (matter_delete(first) != MATTER_OK || matter_delete(second) != MATTER_OK) result = 1;
    return result;
}
