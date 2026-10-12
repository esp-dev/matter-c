/* Linux host file backend. Same TLV blob, no schema or serializer changes. */
#include "matter_store_file.h"
#include "storage/matter_store_tlv.h"
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct Matter_Store_File { char *path,*temp,*lock_path; int lock,dir; unsigned fault; bool busy; };
Matter_Store_File_T matter_store_file_new(const char* path) {
    if(!path || !*path || strlen(path)>32000) return NULL;
    Matter_Store_File_T f=calloc(1,sizeof(*f)); if(!f) return NULL;
    f->lock=f->dir=-1; size_t n=strlen(path);
    f->path=calloc(n+6,1); f->temp=calloc(n+6,1); f->lock_path=calloc(n+6,1);
    if(!f->path || !f->temp || !f->lock_path) goto fail;
    memcpy(f->path,path,n+1); snprintf(f->temp,n+6,"%s.tmp",path); snprintf(f->lock_path,n+6,"%s.lock",path);
    /* Open directory before committing anything; failures remain recoverable. */
    char* slash=strrchr(f->path,'/');
    if(slash) { char saved=slash[1]; slash[1]=0; f->dir=open(f->path,O_RDONLY|O_DIRECTORY|O_CLOEXEC); slash[1]=saved; }
    else f->dir=open(".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    if(f->dir<0) goto fail;
    f->lock=open(f->lock_path,O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW,0600);
    if(f->lock<0 || flock(f->lock,LOCK_EX|LOCK_NB)) goto fail;
    return f;
fail: matter_store_file_delete(f); return NULL;
}
Matter_Result_T matter_store_file_delete(Matter_Store_File_T f) {
    if(!f) return MATTER_INVALID_ARGUMENT;
    if(f->busy) return MATTER_BUSY;
    if(f->lock>=0) close(f->lock);
    if(f->dir>=0) close(f->dir);
    free(f->path); free(f->temp); free(f->lock_path); free(f); return MATTER_OK;
}
static Matter_Result_T read_blob(void* u,uint8_t* out,size_t cap,size_t* n) {
    Matter_Store_File_T f=u; if(!f || !out || !n || cap>MATTER_STORE_BLOB_MAX) return MATTER_INVALID_ARGUMENT;
    if(f->busy) return MATTER_BUSY;
    *n=0; f->busy=true; Matter_Result_T r=MATTER_PORT_ERROR;
    int fd=open(f->path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if(fd<0) { if(errno==ENOENT) r=MATTER_OFFLINE; }
    else {
        struct stat st;
        if(!fstat(fd,&st) && S_ISREG(st.st_mode) && st.st_size>0 && (uint64_t)st.st_size<=cap) {
            size_t done=0,length=(size_t)st.st_size;
            while(done<length) {
                ssize_t got=read(fd,out+done,length-done);
                if(got<0 && errno==EINTR) continue;
                if(got<=0) break;
                done+=(size_t)got;
            }
            if(done==length) { *n=done; r=MATTER_OK; }
        }
        if(close(fd)) r=MATTER_PORT_ERROR;
    }
    f->busy=false; return r;
}
static int sync_file(int fd) {
    int result; do { result=fsync(fd); } while(result && errno==EINTR);
    return result;
}
static Matter_Result_T replace_blob(void* u,const uint8_t* data,size_t n) {
    Matter_Store_File_T f=u; if(!f || !data || !n || n>MATTER_STORE_BLOB_MAX) return MATTER_INVALID_ARGUMENT;
    if(f->busy) return MATTER_BUSY;
    f->busy=true; bool ok=false;
    if(f->fault==1) goto done;
    /* Under the lifetime lock, discard only our staging name. Never follow a
     * stale symlink/hardlink and truncate someone else's file. */
    if(unlink(f->temp) && errno!=ENOENT) goto done;
    int fd=open(f->temp,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    if(fd<0) goto done;
    size_t done=0,target=f->fault==2?n/2:n;
    while(done<target) {
        ssize_t wrote=write(fd,data+done,target-done);
        if(wrote<0 && errno==EINTR) continue;
        if(wrote<=0) break;
        done+=(size_t)wrote;
    }
    ok=done==n && f->fault!=3 && !sync_file(fd);
    if(close(fd)) ok=false;
    if(ok) ok=f->fault!=4 && !rename(f->temp,f->path);
    if(ok && (f->fault==5 || sync_file(f->dir))) {
        /* Rename already committed. Returning an ordinary error would violate
         * blob.replace and allow stale RAM to overwrite the new disk state.
         * Fail-stop this TEST HOST on uncertain directory durability. On restart
         * load only the old/new complete blob; never reuse this in-memory state. */
        fputs("Fatal: store directory sync after rename failed; restart required.\n",stderr);
        abort();
    }
done:
    if(!ok) (void)unlink(f->temp);
    f->busy=false; return ok?MATTER_OK:MATTER_PORT_ERROR;
}
Matter_Store_Blob_Port_T matter_store_file_port(Matter_Store_File_T f) { return (Matter_Store_Blob_Port_T){f,read_blob,replace_blob}; }
void matter_store_file_fault(Matter_Store_File_T f,unsigned stage) { if(f && !f->busy) f->fault=stage; }
