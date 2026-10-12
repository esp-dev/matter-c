#include "matter_store_file.h"
#include "storage/matter_store_tlv.h"
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
struct Matter_Store_File { wchar_t *path,*temp,*lock_path; HANDLE lock; unsigned fault; bool busy; };
Matter_Store_File_T matter_store_file_new(const char* path) {
    if(!path || !*path) return NULL;
    int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,path,-1,NULL,0); if(!n || n>32000) return NULL;
    Matter_Store_File_T f=calloc(1,sizeof(*f)); if(!f) return NULL;
    f->lock=INVALID_HANDLE_VALUE;
    f->path=calloc((size_t)n+5,sizeof(wchar_t)); f->temp=calloc((size_t)n+5,sizeof(wchar_t)); f->lock_path=calloc((size_t)n+5,sizeof(wchar_t));
    if(!f->path || !f->temp || !f->lock_path || !MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,path,-1,f->path,n)) goto fail;
    memcpy(f->temp,f->path,(size_t)n*sizeof(wchar_t)); memcpy(f->lock_path,f->path,(size_t)n*sizeof(wchar_t));
    wcscat(f->temp,L".tmp"); wcscat(f->lock_path,L".lock");
    f->lock=CreateFileW(f->lock_path,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(f->lock==INVALID_HANDLE_VALUE) goto fail;
    return f;
fail: matter_store_file_delete(f); return NULL;
}
Matter_Result_T matter_store_file_delete(Matter_Store_File_T f) {
    if(!f) return MATTER_INVALID_ARGUMENT;
    if(f->busy) return MATTER_BUSY;
    if(f->lock!=INVALID_HANDLE_VALUE) CloseHandle(f->lock);
    free(f->path); free(f->temp); free(f->lock_path); free(f); return MATTER_OK;
}
static Matter_Result_T read_blob(void* u,uint8_t* out,size_t cap,size_t* n) {
    Matter_Store_File_T f=u; if(!f || !out || !n || cap>MATTER_STORE_BLOB_MAX) return MATTER_INVALID_ARGUMENT;
    if(f->busy) return MATTER_BUSY;
    *n=0; f->busy=true; Matter_Result_T r=MATTER_PORT_ERROR;
    HANDLE h=CreateFileW(f->path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(h==INVALID_HANDLE_VALUE) { if(GetLastError()==ERROR_FILE_NOT_FOUND) r=MATTER_OFFLINE; }
    else {
        LARGE_INTEGER z; DWORD got;
        if(GetFileSizeEx(h,&z) && z.QuadPart>0 && (uint64_t)z.QuadPart<=cap && ReadFile(h,out,(DWORD)z.QuadPart,&got,NULL) && got==(DWORD)z.QuadPart) {
            *n=got; r=MATTER_OK;
        }
        if(!CloseHandle(h)) r=MATTER_PORT_ERROR;
    }
    f->busy=false; return r;
}
static bool publish_staging(Matter_Store_File_T f) {
    /* The synchronous host port already waits for disk I/O. Bound additional
     * waiting to 250 ms (six attempts); never retry a write or delete the live
     * blob. Readers/scanners may briefly deny deletion of either file. */
    static const DWORD delays[]={10,20,40,80,100};
    for(unsigned attempt=0;;++attempt) {
        if(MoveFileExW(f->temp,f->path,MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)) {
            if(attempt) fprintf(stderr,"STORE replace recovered after %u retries\n",attempt);
            return true;
        }
        DWORD error=GetLastError();
        bool retry=error==ERROR_ACCESS_DENIED || error==ERROR_SHARING_VIOLATION || error==ERROR_LOCK_VIOLATION;
        if(!retry || attempt==sizeof(delays)/sizeof(delays[0])) {
            fprintf(stderr,"STORE replace failed winerr=%lu attempts=%u\n",(unsigned long)error,attempt+1);
            return false;
        }
        Sleep(delays[attempt]);
    }
}
static Matter_Result_T replace_blob(void* u,const uint8_t* data,size_t n) {
    Matter_Store_File_T f=u; if(!f || !data || !n || n>MATTER_STORE_BLOB_MAX) return MATTER_INVALID_ARGUMENT;
    if(f->busy) return MATTER_BUSY;
    f->busy=true; bool ok=false;
    if(f->fault==1) goto done;
    HANDLE h=CreateFileW(f->temp,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(h==INVALID_HANDLE_VALUE) goto done;
    DWORD wrote,bytes=(DWORD)(f->fault==2?n/2:n);
    ok=WriteFile(h,data,bytes,&wrote,NULL) && wrote==n && f->fault!=3 && FlushFileBuffers(h);
    if(!CloseHandle(h)) ok=false;
    if(ok) ok=f->fault!=4 && publish_staging(f);
done:
    if(!ok) DeleteFileW(f->temp);
    f->busy=false; return ok?MATTER_OK:MATTER_PORT_ERROR;
}
Matter_Store_Blob_Port_T matter_store_file_port(Matter_Store_File_T f) { return (Matter_Store_Blob_Port_T){f,read_blob,replace_blob}; }
void matter_store_file_fault(Matter_Store_File_T f,unsigned stage) { if(f && !f->busy) f->fault=stage; }
