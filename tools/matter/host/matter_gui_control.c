#include "matter_gui_control.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <poll.h>
#include <unistd.h>
#endif
#define GUI_POLL_BYTE_BUDGET 256
static void command(Matter_Gui_Control_T* c) {
    c->line[c->used]=0;
    if(!strcmp(c->line,"stop")) { c->stop=true; return; }
    if(c->allow_ota_query && !strcmp(c->line,"ota-query") && c->query_generation<UINT64_MAX) {
        ++c->query_generation; return;
    }
    if(!strncmp(c->line,"power ",6)) {
        const char* value=c->line+6; char* end;
        errno=0; long long power=strtoll(value,&end,10);
        if((*value=='-'?value[1]>='0' && value[1]<='9':*value>='0' && *value<='9') &&
            !errno && !*end && power>=-MATTER_GUI_POWER_LIMIT_MW && power<=MATTER_GUI_POWER_LIMIT_MW &&
            c->generation<UINT64_MAX) {
            c->power_mw=(int64_t)power; ++c->generation; return;
        }
    }
    puts("GUI_ERROR invalid-command");
}
bool matter_gui_control_poll(Matter_Gui_Control_T* c) {
    for(unsigned i=0;i<GUI_POLL_BYTE_BUDGET && !c->stop;++i) {
        unsigned char b;
#ifdef _WIN32
        HANDLE pipe=GetStdHandle(STD_INPUT_HANDLE); DWORD ready=0,got=0;
        if(!PeekNamedPipe(pipe,NULL,0,NULL,&ready,NULL)) {
            if(GetLastError()==ERROR_BROKEN_PIPE) { c->stop=true; break; }
            return false;
        }
        if(!ready) break;
        if(!ReadFile(pipe,&b,1,&got,NULL)) return false;
        if(!got) { c->stop=true; break; }
#else
        struct pollfd fd={.fd=STDIN_FILENO,.events=POLLIN};
        int r=poll(&fd,1,0);
        if(r<0) { if(errno==EINTR) break; return false; }
        if(!r) break;
        ssize_t got=read(STDIN_FILENO,&b,1);
        if(got<0) { if(errno==EINTR) break; return false; }
        if(!got) { c->stop=true; break; }
#endif
        if(b=='\n') {
            if(c->dropping) puts("GUI_ERROR command-too-long");
            else command(c);
            c->used=0; c->dropping=false;
        } else if(b=='\r') { /* Accept CRLF from Windows launchers. */
        } else if(b<32 || b>126 || c->used==sizeof(c->line)-1) c->dropping=true;
        else if(!c->dropping) c->line[c->used++]=(char)b;
    }
    return true;
}
