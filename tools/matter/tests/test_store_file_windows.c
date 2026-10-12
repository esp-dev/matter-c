#include "matter_store_file.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"file:%d: %s (winerr=%lu)\n",__LINE__,#x,(unsigned long)GetLastError()); exit(1); } } while(0)
/* Small byte payloads exercise publication, not TLV encoding. No node secrets. */
static void expect(Matter_Store_Blob_Port_T p,uint8_t value) {
    uint8_t b=0; size_t n=0; CHECK(p.read(p.user,&b,1,&n)==MATTER_OK && n==1 && b==value);
}
static DWORD WINAPI release_lock(void* handle) {
    Sleep(100); return CloseHandle((HANDLE)handle)?0:1;
}
int main(int argc,char** argv) {
    CHECK(argc==2);
    size_t len=strlen(argv[1]); char* tmp=malloc(len+6); char* lock=malloc(len+6);
    CHECK(tmp && lock); snprintf(tmp,len+6,"%s.tmp",argv[1]); snprintf(lock,len+6,"%s.lock",argv[1]);
    /* Caller provides a fresh path in a disposable test directory. */
    CHECK(GetFileAttributesA(argv[1])==INVALID_FILE_ATTRIBUTES && GetLastError()==ERROR_FILE_NOT_FOUND);
    Matter_Store_File_T f=matter_store_file_new(argv[1]); CHECK(f && !matter_store_file_new(argv[1]));
    Matter_Store_Blob_Port_T p=matter_store_file_port(f); uint8_t a=17,b=42; size_t n=9;
    CHECK(p.read(p.user,&a,1,&n)==MATTER_OFFLINE && n==0);
    CHECK(p.replace(p.user,&a,1)==MATTER_OK); expect(p,17);
    for(unsigned stage=1;stage<=4;++stage) {
        matter_store_file_fault(f,stage); CHECK(p.replace(p.user,&b,1)==MATTER_PORT_ERROR); expect(p,17);
        CHECK(GetFileAttributesA(tmp)==INVALID_FILE_ATTRIBUTES);
    }
    matter_store_file_fault(f,0);
    /* An ordinary reader without FILE_SHARE_DELETE blocks atomic replacement. */
    HANDLE h=CreateFileA(argv[1],GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    CHECK(h!=INVALID_HANDLE_VALUE);
    HANDLE worker=CreateThread(NULL,0,release_lock,h,0,NULL); CHECK(worker);
    Matter_Result_T result=p.replace(p.user,&b,1);
    CHECK(WaitForSingleObject(worker,5000)==WAIT_OBJECT_0);
    DWORD code=1; CHECK(GetExitCodeThread(worker,&code) && code==0 && CloseHandle(worker));
    CHECK(result==MATTER_OK); expect(p,42);
    /* A persistent reader must not cause unbounded waits or loss of old data. */
    h=CreateFileA(argv[1],GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL); CHECK(h!=INVALID_HANDLE_VALUE);
    ULONGLONG start=GetTickCount64();
    CHECK(p.replace(p.user,&a,1)==MATTER_PORT_ERROR);
    CHECK(GetTickCount64()-start<5000); expect(p,42); CHECK(CloseHandle(h));
    CHECK(GetFileAttributesA(tmp)==INVALID_FILE_ATTRIBUTES);
    /* Genuine access denial is still an error; do not change file attributes. */
    CHECK(SetFileAttributesA(argv[1],FILE_ATTRIBUTE_READONLY));
    CHECK(p.replace(p.user,&a,1)==MATTER_PORT_ERROR); expect(p,42);
    CHECK(GetFileAttributesA(argv[1])&FILE_ATTRIBUTE_READONLY);
    CHECK(SetFileAttributesA(argv[1],FILE_ATTRIBUTE_NORMAL));
    CHECK(p.replace(p.user,&a,1)==MATTER_OK); expect(p,17);
    CHECK(matter_store_file_delete(f)==MATTER_OK);
    f=matter_store_file_new(argv[1]); CHECK(f); p=matter_store_file_port(f); expect(p,17);
    CHECK(matter_store_file_delete(f)==MATTER_OK);
    CHECK(DeleteFileA(argv[1]) && DeleteFileA(lock)); free(tmp); free(lock);
    puts("PASS Windows file: transient/persistent locks, readonly, atomic faults, reopen, cleanup");
    return 0;
}
