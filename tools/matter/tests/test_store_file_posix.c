#include "matter_store_file.h"
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"file:%d: %s\n",__LINE__,#x); exit(1); } } while(0)
static void expect(Matter_Store_Blob_Port_T p,uint8_t value) {
    uint8_t b=0; size_t n=0; CHECK(p.read(p.user,&b,1,&n)==MATTER_OK && n==1 && b==value);
}
int main(void) {
    char dir[]="/tmp/matter-file-XXXXXX"; CHECK(mkdtemp(dir));
    char path[96],tmp[104],lock[104]; snprintf(path,sizeof(path),"%s/state",dir);
    snprintf(tmp,sizeof(tmp),"%s.tmp",path); snprintf(lock,sizeof(lock),"%s.lock",path);
    Matter_Store_File_T f=matter_store_file_new(path); CHECK(f && !matter_store_file_new(path));
    Matter_Store_Blob_Port_T p=matter_store_file_port(f); uint8_t a=17,b=42; size_t n=9;
    CHECK(p.read(p.user,&a,1,&n)==MATTER_OFFLINE && !n);
    CHECK(p.replace(p.user,&a,1)==MATTER_OK); expect(p,17);
    struct stat st; CHECK(!stat(path,&st) && (st.st_mode&0777)==0600);
    for(unsigned i=1;i<=4;++i) {
        matter_store_file_fault(f,i); CHECK(p.replace(p.user,&b,1)==MATTER_PORT_ERROR); expect(p,17);
    }
    matter_store_file_fault(f,0);
    /* Never truncate a stale staging symlink to the live file. */
    CHECK(!symlink(path,tmp)); CHECK(p.replace(p.user,&b,1)==MATTER_OK); expect(p,42);
    pid_t child=fork(); CHECK(child>=0);
    if(!child) {
        struct rlimit limit={0,0}; (void)setrlimit(RLIMIT_CORE,&limit);
        matter_store_file_fault(f,5); (void)p.replace(p.user,&a,1); _exit(7);
    }
    int status; CHECK(waitpid(child,&status,0)==child && WIFSIGNALED(status) && WTERMSIG(status)==SIGABRT);
    CHECK(matter_store_file_delete(f)==MATTER_OK);
    f=matter_store_file_new(path); CHECK(f); p=matter_store_file_port(f); expect(p,17);
    CHECK(matter_store_file_delete(f)==MATTER_OK);
    /* Corrupt/empty input is not 'missing'. */
    FILE* file=fopen(path,"wb"); CHECK(file && !fclose(file));
    f=matter_store_file_new(path); CHECK(f); p=matter_store_file_port(f);
    CHECK(p.read(p.user,&a,1,&n)==MATTER_PORT_ERROR);
    CHECK(matter_store_file_delete(f)==MATTER_OK);
    CHECK(!unlink(path) && !unlink(lock) && !rmdir(dir));
    puts("PASS POSIX file: lock, mode0600, atomic faults, staging symlink, post-rename fail-stop/reopen, corrupt input");
    return 0;
}
