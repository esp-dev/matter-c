#include "crypto/matter_crypto_mbedtls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"privacy:%d: %s\n",__LINE__,#x);abort();}}while(0)
int main(void){
    /* Independent Python cryptography AES-CTR oracle: IV01||nonce13||0000. */
    const uint8_t expected[]={0x04,0x07,0x43,0x7f,0x79,0xad,0x7a,0xcd,0x99,0x80,0x42,0x5c,0xf5,0x1f,0xd1,0x99,0x06,0x25,0xa6,0x9b};
    uint8_t key[16],nonce[13],plain[20],encrypted[20],decrypted[20];
    for(unsigned i=0;i<16;++i)key[i]=(uint8_t)i;
    for(unsigned i=0;i<13;++i)nonce[i]=(uint8_t)i;
    for(unsigned i=0;i<20;++i)plain[i]=(uint8_t)i;
    Matter_Crypto_Mbedtls_T c=matter_crypto_mbedtls_new(NULL);CHECK(c);
    for(size_t n=0;n<=20;++n){
        memset(encrypted,0x55,sizeof(encrypted));
        CHECK(matter_crypto_mbedtls_privacy(c,key,nonce,plain,n,encrypted)==MATTER_OK);
        CHECK(!memcmp(encrypted,expected,n));for(size_t i=n;i<20;++i)CHECK(encrypted[i]==0x55);
        CHECK(matter_crypto_mbedtls_privacy(c,key,nonce,encrypted,n,decrypted)==MATTER_OK&&!memcmp(decrypted,plain,n));
    }
    CHECK(matter_crypto_mbedtls_privacy(c,key,nonce,NULL,0,NULL)==MATTER_OK);
    memset(encrypted,0x55,sizeof(encrypted));
    CHECK(matter_crypto_mbedtls_privacy(c,key,nonce,plain,21,encrypted)==MATTER_INVALID_ARGUMENT);
    CHECK(matter_crypto_mbedtls_privacy(c,NULL,nonce,plain,20,encrypted)==MATTER_INVALID_ARGUMENT);
    for(unsigned i=0;i<20;++i)CHECK(encrypted[i]==0x55);
    CHECK(matter_crypto_mbedtls_delete(c)==MATTER_OK);
    puts("PASS group privacy: independent AES-CTR oracle, all header lengths, roundtrip and invalid-output preservation");
    return 0;
}
