/* Independent TEST oracle, linked only with OpenSSL (never Matter/mbedTLS).
 * Input files: key, nonce, aad, ciphertext||tag; output plaintext. */
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
static unsigned char* read_file(const char* path,int* size) {
    FILE* f=fopen(path,"rb"); if(!f) return NULL;
    if(fseek(f,0,SEEK_END)) { fclose(f); return NULL; }
    long n=ftell(f); if(n<0 || n>4096 || fseek(f,0,SEEK_SET)) { fclose(f); return NULL; }
    unsigned char* p=malloc((size_t)n+1); if(!p) { fclose(f); return NULL; }
    if(fread(p,1,(size_t)n,f)!=(size_t)n) { free(p); fclose(f); return NULL; }
    fclose(f); *size=(int)n; return p;
}
int main(int argc,char** argv) {
    if(argc!=6) return 2;
    unsigned char* b[5]={0}; int n[4]={0}; EVP_CIPHER_CTX* ctx=NULL; int rc=1,len=0;
    for(int i=0;i<4;++i) if(!(b[i]=read_file(argv[i+1],&n[i]))) goto done;
    if(n[0]!=16 || n[1]!=13 || n[3]<16) goto done;
    b[4]=malloc((size_t)n[3]); ctx=EVP_CIPHER_CTX_new(); if(!b[4] || !ctx) goto done;
    if(EVP_DecryptInit_ex(ctx,EVP_aes_128_ccm(),NULL,NULL,NULL)!=1 ||
       EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_CCM_SET_IVLEN,13,NULL)!=1 ||
       EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_CCM_SET_TAG,16,b[3]+n[3]-16)!=1 ||
       EVP_DecryptInit_ex(ctx,NULL,NULL,b[0],b[1])!=1 ||
       EVP_DecryptUpdate(ctx,NULL,&len,NULL,n[3]-16)!=1 ||
       (n[2] && EVP_DecryptUpdate(ctx,NULL,&len,b[2],n[2])!=1) ||
       EVP_DecryptUpdate(ctx,b[4],&len,b[3],n[3]-16)!=1) goto done;
    FILE* out=fopen(argv[5],"wb"); if(!out) goto done;
    rc=fwrite(b[4],1,(size_t)len,out)==(size_t)len?0:1; if(fclose(out)) rc=1;
done:
    EVP_CIPHER_CTX_free(ctx); for(int i=0;i<5;++i) free(b[i]); return rc;
}
