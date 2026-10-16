/* Native Windows application. The same EXE runs each isolated C node worker.
 * GUI and pipe polling are driven by the Windows message loop, without threads.
 * Node keys remain opaque files owned by the existing atomic TLV backend.
 */
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlobj.h>
#include <shellapi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <string.h>
#include <inttypes.h>
#include "matter_host_platform.h"
#include "matter_gui_pairing.h"
#include "matter_gui_resources.h"
#include "qrcodegen.h"

#define GUI_PORT_FIRST 5546
#define GUI_PORT_LAST 5599
#define GUI_POWER_W 10000
#define GUI_POLL_MS 100
#define GUI_STATUS_STALE_MS 3000
#define GUI_STOP_NOTICE_MS 20000
#define GUI_LINE_BYTES 2048
#define GUI_POLL_BYTES 8192
#define GUI_INI_MAX_CHARS 32768
#define GUI_QR_VERSION 4
#define GUI_QR_MARGIN 4
enum { ID_NEW=101,ID_OPEN,ID_SETTINGS,ID_LIST,ID_SIMULATOR,ID_SLIDER,ID_START,ID_STOP,ID_REMOVE,
    ID_SAVE,ID_CREDENTIALS,ID_INTERFACE,ID_VALIDITY,ID_BROWSE };
typedef struct App App;
typedef struct Node {
    struct Node* next; App* app; unsigned index;
    wchar_t id[17]; uint32_t pin; unsigned discriminator,port; int watts; bool simulator;
    HWND window,status,power,applied,legend,slider,choose,start,stop,remove,qr,note;
    HANDLE process,input,output; bool stopping,detach,ready,show_qr,published,line_drop,qr_displayed;
    DWORD exit_code; uint64_t stop_at,status_at,generation; unsigned mode,fabrics; long long actual_mw;
    char line[GUI_LINE_BYTES]; size_t used; wchar_t error[256];
    uint8_t* qr_bits;
} Node;
struct App {
    HINSTANCE instance; HWND window,list,settings,credentials_edit,interface_edit,validity_edit;
    HFONT font,title_font,power_font; HANDLE lock,job;
    wchar_t* home; wchar_t* ini; wchar_t* credentials; wchar_t* exe;
    unsigned interface_id,count; bool chip,closing; Node* nodes;
};
static LRESULT CALLBACK node_proc(HWND,UINT,WPARAM,LPARAM);
static LRESULT CALLBACK qr_proc(HWND,UINT,WPARAM,LPARAM);
static LRESULT CALLBACK settings_proc(HWND,UINT,WPARAM,LPARAM);
static App* application;
static int message_box(HWND owner,const wchar_t* message,const wchar_t* title,UINT type) {
    return MessageBoxExW(owner,message,title,type,MAKELANGID(LANG_ENGLISH,SUBLANG_ENGLISH_US));
}
static void error(HWND owner,const wchar_t* message) { message_box(owner,message,L"Matter C",MB_ICONERROR|MB_OK); }
static void os_error(HWND owner,const wchar_t* action) {
    wchar_t* detail=NULL;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,GetLastError(),MAKELANGID(LANG_ENGLISH,SUBLANG_ENGLISH_US),(wchar_t*)&detail,0,NULL);
    message_box(owner,detail?detail:action,action,MB_ICONERROR|MB_OK); LocalFree(detail);
}
static wchar_t* join(const wchar_t* base,const wchar_t* name) {
    size_t size=wcslen(base)+wcslen(name)+2; wchar_t* out=calloc(size,sizeof(*out));
    if(out) swprintf(out,size,L"%ls\\%ls",base,name);
    return out;
}
static wchar_t* read_ini(App* a,const wchar_t* section,const wchar_t* key,const wchar_t* fallback) {
    for(DWORD size=128;size<=GUI_INI_MAX_CHARS;size*=2) {
        wchar_t* out=calloc(size,sizeof(*out)); if(!out) return NULL;
        DWORD used=GetPrivateProfileStringW(section,key,fallback,out,size,a->ini);
        if(used<size-1) return out;
        free(out);
    }
    return NULL;
}
static bool number(const wchar_t* text,unsigned max,unsigned* out) {
    if(!text || !*text || *text<L'0' || *text>L'9') return false;
    wchar_t* end; unsigned long value=wcstoul(text,&end,10);
    if(*end || value>max) return false;
    *out=(unsigned)value; return true;
}
static bool ini_number(App* a,const wchar_t* section,const wchar_t* key,unsigned max,unsigned* out) {
    wchar_t* str=read_ini(a,section,key,L""); bool ok=number(str,max,out); free(str); return ok;
}
static bool write_num(const wchar_t* ini,const wchar_t* section,const wchar_t* key,long long value) {
    wchar_t text[32]; swprintf(text,32,L"%lld",value); return WritePrivateProfileStringW(section,key,text,ini)!=0;
}
static bool save(App* a) {
    wchar_t* temp=join(a->home,L"settings.pending.ini"); if(!temp) return false;
    /* Exclusive manager lock serializes this same-directory transaction. */
    HANDLE file=CreateFileW(temp,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(file==INVALID_HANDLE_VALUE) { free(temp); return false; }
    const WORD bom=0xfeff; DWORD written=0;
    bool ok=WriteFile(file,&bom,sizeof(bom),&written,NULL) && written==sizeof(bom); CloseHandle(file);
    ok=ok && WritePrivateProfileStringW(L"app",L"credentials",a->credentials,temp) &&
        write_num(temp,L"app",L"version",1) && write_num(temp,L"app",L"count",a->count) &&
        write_num(temp,L"app",L"interface",a->interface_id) && write_num(temp,L"app",L"chip",a->chip);
    for(Node* n=a->nodes;ok && n;n=n->next) {
        wchar_t section[32]; swprintf(section,32,L"node%u",n->index);
        ok=WritePrivateProfileStringW(section,L"id",n->id,temp) &&
            write_num(temp,section,L"pin",n->pin) && write_num(temp,section,L"discriminator",n->discriminator) &&
            write_num(temp,section,L"port",n->port) && write_num(temp,section,L"watts",n->watts) &&
            write_num(temp,section,L"simulator",n->simulator);
    }
    /* Win32 explicitly returns zero when this operation flushes its cache. */
    if(ok) (void)WritePrivateProfileStringW(NULL,NULL,NULL,temp);
    if(ok) {
        file=CreateFileW(temp,GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
        ok=file!=INVALID_HANDLE_VALUE;
        if(ok) { ok=FlushFileBuffers(file)!=0; CloseHandle(file); }
    }
    if(ok) ok=MoveFileExW(temp,a->ini,MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)!=0;
    if(!ok) DeleteFileW(temp);
    free(temp); return ok;
}
static bool load(App* a) {
    DWORD attributes=GetFileAttributesW(a->ini);
    if(attributes==INVALID_FILE_ATTRIBUTES) {
        if(GetLastError()!=ERROR_FILE_NOT_FOUND) return false;
        a->credentials=_wcsdup(L""); return a->credentials!=NULL;
    }
    unsigned version,chip,count;
    if(!ini_number(a,L"app",L"version",1,&version) || version!=1 ||
        !ini_number(a,L"app",L"count",GUI_PORT_LAST-GUI_PORT_FIRST+1,&count) ||
        !ini_number(a,L"app",L"interface",UINT32_MAX,&a->interface_id) ||
        !ini_number(a,L"app",L"chip",1,&chip)) return false;
    a->chip=chip!=0; a->credentials=read_ini(a,L"app",L"credentials",L""); if(!a->credentials) return false;
    Node** tail=&a->nodes;
    for(unsigned i=0;i<count;++i) {
        Node* n=calloc(1,sizeof(*n)); if(!n) return false;
        *tail=n; tail=&n->next; n->app=a; n->index=i; ++a->count;
        wchar_t section[32]; swprintf(section,32,L"node%u",i);
        wchar_t* id=read_ini(a,section,L"id",L"");
        if(!id) return false;
        bool valid=wcslen(id)==16 && wcsspn(id,L"0123456789abcdef")==16;
        if(valid) wcscpy(n->id,id);
        free(id); if(!valid) return false;
        unsigned pin,sim;
        if(!ini_number(a,section,L"pin",99999998,&pin) || !matter_gui_pin_valid(pin) ||
            !ini_number(a,section,L"discriminator",4095,&n->discriminator) ||
            !ini_number(a,section,L"port",GUI_PORT_LAST,&n->port) || n->port<GUI_PORT_FIRST ||
            !ini_number(a,section,L"simulator",1,&sim)) return false;
        n->pin=pin; n->simulator=sim!=0;
        wchar_t* watts=read_ini(a,section,L"watts",L"");
        if(!watts) return false;
        wchar_t* end; long power=wcstol(watts,&end,10);
        valid=*watts && !*end && power>=-GUI_POWER_W && power<=GUI_POWER_W; free(watts);
        if(!valid) return false;
        n->watts=(int)power;
        for(Node* p=a->nodes;p!=n;p=p->next)
            if(p->port==n->port || p->discriminator==n->discriminator || !wcscmp(p->id,n->id)) return false;
    }
    return true;
}
static HWND widget(App* a,HWND parent,const wchar_t* cls,const wchar_t* text,DWORD style,int x,int y,int w,int h,int id) {
    HWND result=CreateWindowExW(0,cls,text,WS_CHILD|WS_VISIBLE|style,x,y,w,h,parent,(HMENU)(INT_PTR)id,a->instance,NULL);
    if(result) SendMessageW(result,WM_SETFONT,(WPARAM)a->font,TRUE);
    return result;
}
static void refresh_list(App* a) {
    SendMessageW(a->list,LB_RESETCONTENT,0,0);
    for(Node* n=a->nodes;n;n=n->next) {
        wchar_t text[120]; swprintf(text,120,L"Sensor %u     ·     %ls     ·     UDP %u",n->index+1,n->simulator?L"Simulator":L"Choose integration",n->port);
        LRESULT row=SendMessageW(a->list,LB_ADDSTRING,0,(LPARAM)text);
        SendMessageW(a->list,LB_SETITEMDATA,(WPARAM)row,(LPARAM)n);
    }
}
/* Quote each argument using the Windows CRT escaping rules (including trailing
 * backslashes); no shell, command substitution or command interpreter. */
static wchar_t* quote(const wchar_t* value) {
    size_t len=wcslen(value); wchar_t* out=calloc(len*2+3,sizeof(*out)); if(!out) return NULL;
    size_t at=0,slashes=0; out[at++]=L'"';
    for(size_t i=0;i<=len;++i) {
        wchar_t ch=value[i];
        if(ch==L'\\') { ++slashes; continue; }
        size_t repeat=(ch==L'"' || !ch)?slashes*2:slashes;
        while(repeat--) out[at++]=L'\\';
        slashes=0;
        if(ch==L'"') out[at++]=L'\\';
        if(!ch) break;
        out[at++]=ch;
    }
    out[at++]=L'"'; out[at]=0; return out;
}
static bool send_line(Node* n,const char* line) {
    DWORD written=0; size_t size=strlen(line);
    return n->input && WriteFile(n->input,line,(DWORD)size,&written,NULL) && written==size;
}
static bool send_power(Node* n) {
    char line[40]; snprintf(line,sizeof(line),"power %d\n",n->watts*1000); return send_line(n,line);
}
static void close_process(Node* n) {
    if(n->input) CloseHandle(n->input);
    if(n->output) CloseHandle(n->output);
    if(n->process) CloseHandle(n->process);
    n->input=n->output=n->process=NULL; n->ready=n->show_qr=false;
}
static void start(Node* n) {
    App* a=n->app; if(n->process || !n->simulator || a->closing) return;
    if(!a->interface_id || !*a->credentials) { error(n->window,L"First select the credentials folder and IPv6 interface index in Settings."); return; }
    const wchar_t* required[]={L"dac.der",L"pai.der",L"paa.der",L"cd.der",L"dac-key.bin"};
    for(unsigned i=0;i<sizeof(required)/sizeof(required[0]);++i) {
        wchar_t* file=join(a->credentials,required[i]);
        DWORD attributes=file?GetFileAttributesW(file):INVALID_FILE_ATTRIBUTES; free(file);
        if(attributes==INVALID_FILE_ATTRIBUTES || (attributes&FILE_ATTRIBUTE_DIRECTORY)) {
            error(n->window,L"The credentials folder must contain dac.der, pai.der, paa.der, cd.der and dac-key.bin."); return;
        }
    }
    wchar_t* nodes=join(a->home,L"nodes"); wchar_t* directory=nodes?join(nodes,n->id):NULL;
    wchar_t* state=directory?join(directory,L"state.tlv"):NULL;
    if(!nodes || !directory || !state) { free(nodes); free(directory); free(state); error(n->window,L"Out of memory."); return; }
    bool ok=(CreateDirectoryW(nodes,NULL) || GetLastError()==ERROR_ALREADY_EXISTS) &&
        (CreateDirectoryW(directory,NULL) || GetLastError()==ERROR_ALREADY_EXISTS);
    free(nodes); free(directory);
    wchar_t port[16],iface[16],pin[16],disc[16];
    swprintf(port,16,L"%u",n->port); swprintf(iface,16,L"%u",a->interface_id);
    swprintf(pin,16,L"%u",n->pin); swprintf(disc,16,L"%u",n->discriminator);
    const wchar_t* args[]={a->exe,L"--interface",iface,L"--seconds",L"0",L"--port",port,
        L"--credentials",a->credentials,L"--state",state,L"--pin",pin,L"--discriminator",disc,
        L"--instance-id",n->id,L"--power-sensor-only",L"--gui-control",L"--certificate-validity",a->chip?L"chip":L"strict"};
    wchar_t* command=calloc(GUI_INI_MAX_CHARS,sizeof(*command)); size_t used=0;
    if(!command) ok=false;
    for(unsigned i=0;ok && i<sizeof(args)/sizeof(args[0]);++i) {
        wchar_t* part=quote(args[i]); if(!part) { ok=false; break; }
        size_t len=wcslen(part); if(used+len+2>=GUI_INI_MAX_CHARS) ok=false;
        else { if(used) command[used++]=L' '; memcpy(command+used,part,(len+1)*sizeof(*part)); used+=len; }
        free(part);
    }
    free(state);
    SECURITY_ATTRIBUTES inherit={sizeof(inherit),NULL,TRUE}; HANDLE input=NULL,output=NULL;
    if(ok) ok=CreatePipe(&input,&n->input,&inherit,0) && SetHandleInformation(n->input,HANDLE_FLAG_INHERIT,0);
    if(ok) ok=CreatePipe(&n->output,&output,&inherit,0) && SetHandleInformation(n->output,HANDLE_FLAG_INHERIT,0);
    STARTUPINFOW si={0}; si.cb=sizeof(si); si.dwFlags=STARTF_USESTDHANDLES;
    si.hStdInput=input; si.hStdOutput=output; si.hStdError=output;
    PROCESS_INFORMATION pi={0};
    if(ok) ok=CreateProcessW(a->exe,command,NULL,NULL,TRUE,CREATE_NO_WINDOW|CREATE_SUSPENDED,NULL,NULL,&si,&pi)!=0;
    if(ok) {
        ok=AssignProcessToJobObject(a->job,pi.hProcess)!=0;
        if(ok) { n->process=pi.hProcess; ok=ResumeThread(pi.hThread)!=(DWORD)-1; }
        if(!ok) { TerminateProcess(pi.hProcess,1); WaitForSingleObject(pi.hProcess,5000); if(!n->process) CloseHandle(pi.hProcess); }
        CloseHandle(pi.hThread);
    }
    DWORD failure=GetLastError();
    if(input) CloseHandle(input);
    if(output) CloseHandle(output);
    free(command);
    if(!ok) { close_process(n); SetLastError(failure); os_error(n->window,L"Starting node"); return; }
    n->stopping=n->detach=n->ready=n->show_qr=n->published=n->line_drop=false; n->used=0; n->error[0]=0;
    n->mode=n->fabrics=0; n->status_at=GetTickCount64();
    if(!send_power(n)) wcscpy(n->error,L"Could not send the initial measurement.");
    SetWindowTextW(n->status,L"Starting node and publishing mDNS…");
}
static void stop(Node* n,bool detach) {
    if(!n->process) { if(detach) { n->simulator=false; if(!save(n->app)) { n->simulator=true; error(n->window,L"Could not save settings."); } refresh_list(n->app); } return; }
    n->detach|=detach;
    if(n->stopping) return;
    n->stopping=true; n->show_qr=false; n->stop_at=GetTickCount64();
    (void)send_line(n,"stop\n"); CloseHandle(n->input); n->input=NULL;
    SetWindowTextW(n->status,L"Closing sessions and mDNS advertisements…");
}
static void received_line(Node* n) {
    n->line[n->used]=0;
    unsigned mode,fabrics; long long mw; uint64_t generation; char published[6];
    if(sscanf(n->line,"GUI_STATUS {\"commissioning\":%u,\"fabrics\":%u,\"published\":%5[a-z],\"power_mw\":%lld,\"generation\":%" SCNu64 "}",
        &mode,&fabrics,published,&mw,&generation)==5 && mode<=2 && fabrics<=5 && mw>=-10000000 && mw<=10000000) {
        n->mode=mode; n->fabrics=fabrics; n->actual_mw=mw; n->generation=generation;
        n->published=!strcmp(published,"true"); n->ready=true; n->status_at=GetTickCount64();
    } else if(strstr(n->line,"failed") || strstr(n->line,"Failed") || strstr(n->line,"ERROR") || strstr(n->line,"RESET ")) {
        if(!strncmp(n->line,"RESET ",6)) { n->fabrics=0; n->mode=0; }
        MultiByteToWideChar(CP_UTF8,0,n->line,-1,n->error,(int)(sizeof(n->error)/sizeof(n->error[0]))-1);
        n->error[sizeof(n->error)/sizeof(n->error[0])-1]=0;
    }
}
static void poll_node(Node* n) {
    if(!n->process) return;
    for(unsigned i=0;i<GUI_POLL_BYTES;++i) {
        DWORD available=0,got=0; char byte;
        if(!PeekNamedPipe(n->output,NULL,0,NULL,&available,NULL) || !available || !ReadFile(n->output,&byte,1,&got,NULL) || !got) break;
        if(byte=='\n') { if(!n->line_drop) received_line(n); n->used=0; n->line_drop=false; }
        else if(byte!='\r') { if(n->used==sizeof(n->line)-1) n->line_drop=true; else if(!n->line_drop) n->line[n->used++]=byte; }
    }
    if(WaitForSingleObject(n->process,0)==WAIT_OBJECT_0) {
        GetExitCodeProcess(n->process,&n->exit_code); close_process(n);
        if(n->detach && n->exit_code==0) {
            n->simulator=false;
            if(!save(n->app)) { n->simulator=true; error(n->window,L"Could not save integration removal; pairing state is unchanged."); }
            refresh_list(n->app);
        }
        n->stopping=false;
        wchar_t text[340]; swprintf(text,340,L"Stopped · exit code %lu. %ls",n->exit_code,n->error);
        SetWindowTextW(n->status,text); return;
    }
    uint64_t now=GetTickCount64();
    if(n->stopping) {
        if(now-n->stop_at>GUI_STOP_NOTICE_MS) SetWindowTextW(n->status,L"The node is still shutting down. Its state is retained.");
        return;
    }
    if(now-n->status_at>GUI_STATUS_STALE_MS) { n->show_qr=false; SetWindowTextW(n->status,L"Waiting for node status…"); return; }
    if(n->ready) {
        wchar_t text[180]; swprintf(text,180,L"%ls · fabrics: %u · %ls",n->published?L"Running":L"Publishing mDNS",n->fabrics,n->mode?L"pairing window open":L"pairing window closed");
        SetWindowTextW(n->status,text);
        swprintf(text,180,L"Confirmed: %+.3f W · update #%llu",(double)n->actual_mw/1000,(unsigned long long)n->generation);
        SetWindowTextW(n->applied,text);
        n->show_qr=n->mode==1 && n->published;
    }
}
static void preview(Node* n) {
    int watts=(int)SendMessageW(n->slider,TBM_GETPOS,0,0);
    wchar_t text[100]; swprintf(text,100,L"%+d W · %ls",watts,watts>0?L"import":watts<0?L"export":L"no power flow");
    SetWindowTextW(n->power,text);
}
static void show_controls(Node* n) {
    HWND controls[]={n->power,n->applied,n->legend,n->slider,n->start,n->stop,n->remove,n->qr,n->note};
    for(unsigned i=0;i<sizeof(controls)/sizeof(controls[0]);++i) ShowWindow(controls[i],n->simulator?SW_SHOW:SW_HIDE);
    ShowWindow(n->choose,n->simulator?SW_HIDE:SW_SHOW);
    EnableWindow(n->start,!n->process); EnableWindow(n->stop,n->process && !n->stopping);
    EnableWindow(n->slider,!n->stopping && !n->app->closing); EnableWindow(n->remove,!n->stopping && !n->app->closing);
    if(n->simulator) {
        SetWindowTextW(n->note,n->show_qr?L"Scan with Apple Home or Google Home.":n->fabrics?
            L"Paired. Add another ecosystem from the app managing this device.":
            L"The QR code appears while pairing is open. After expiry, stop and restart the node.");
    }
    if(n->show_qr!=n->qr_displayed) { InvalidateRect(n->qr,NULL,FALSE); n->qr_displayed=n->show_qr; }
}
static bool build_qr(Node* n) {
    char id[MATTER_GUI_QR_TEXT_BYTES];
    if(!matter_gui_pairing(n->pin,(uint16_t)n->discriminator,0xfff1,0x8001,id)) return false;
    size_t size=qrcodegen_BUFFER_LEN_FOR_VERSION(GUI_QR_VERSION);
    uint8_t* scratch=malloc(size); n->qr_bits=malloc(size);
    bool ok=scratch && n->qr_bits && qrcodegen_encodeText(id,scratch,n->qr_bits,qrcodegen_Ecc_MEDIUM,
        qrcodegen_VERSION_MIN,GUI_QR_VERSION,qrcodegen_Mask_AUTO,true);
    free(scratch); if(!ok) { free(n->qr_bits); n->qr_bits=NULL; } return ok;
}
static void open_node(Node* n) {
    if(!n->window) {
        wchar_t title[70]; swprintf(title,70,L"Sensor %u — Matter C",n->index+1);
        n->window=CreateWindowExW(0,L"MatterCNode",title,WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,
            CW_USEDEFAULT,CW_USEDEFAULT,660,770,n->app->window,NULL,n->app->instance,n);
    }
    ShowWindow(n->window,SW_SHOW); SetForegroundWindow(n->window);
}
static void add_node(App* a) {
    if(a->closing) return;
    if(a->count>=GUI_PORT_LAST-GUI_PORT_FIRST+1) { error(a->window,L"No free ports in the application range."); return; }
    Node* n=calloc(1,sizeof(*n)); if(!n) return;
    n->app=a; n->index=a->count;
    for(n->port=GUI_PORT_FIRST;n->port<=GUI_PORT_LAST;++n->port) {
        bool used=false; for(Node* p=a->nodes;p;p=p->next) used|=p->port==n->port;
        if(!used) break;
    }
    uint8_t bytes[8]; bool unique=false;
    do {
        if(!matter_host_random(bytes,sizeof(bytes))) { free(n); return; }
        for(unsigned i=0;i<8;++i) swprintf(n->id+i*2,3,L"%02x",bytes[i]);
        unique=true; for(Node* p=a->nodes;p;p=p->next) if(!wcscmp(n->id,p->id)) unique=false;
    } while(!unique);
    /* Uniform sampling of the 27-bit onboarding field, rejecting invalid PINs. */
    do { if(!matter_host_random(&n->pin,sizeof(n->pin))) { free(n); return; } n->pin&=UINT32_C(0x07ffffff); } while(!matter_gui_pin_valid(n->pin));
    do {
        if(!matter_host_random(bytes,2)) { free(n); return; }
        n->discriminator=((unsigned)bytes[0]|((unsigned)bytes[1]<<8))&4095; unique=true;
        for(Node* p=a->nodes;p;p=p->next) if(p->discriminator==n->discriminator) unique=false;
    } while(!unique);
    Node** tail=&a->nodes; while(*tail) tail=&(*tail)->next;
    *tail=n; ++a->count;
    if(!save(a)) { *tail=NULL; --a->count; free(n); error(a->window,L"Could not save the new node."); return; }
    refresh_list(a); open_node(n);
}
static LRESULT CALLBACK node_proc(HWND window,UINT message,WPARAM w,LPARAM l) {
    Node* n=(Node*)GetWindowLongPtrW(window,GWLP_USERDATA);
    if(message==WM_NCCREATE) { n=((CREATESTRUCTW*)l)->lpCreateParams; n->window=window; SetWindowLongPtrW(window,GWLP_USERDATA,(LONG_PTR)n); }
    if(!n) return DefWindowProcW(window,message,w,l);
    App* a=n->app;
    switch(message) {
    case WM_CTLCOLORSTATIC: SetBkColor((HDC)w,RGB(255,255,255)); return (LRESULT)GetStockObject(WHITE_BRUSH);
    case WM_CREATE: {
        HWND title=widget(a,window,L"STATIC",L"Power sensor",0,24,20,590,34,0); SendMessageW(title,WM_SETFONT,(WPARAM)a->title_font,TRUE);
        n->status=widget(a,window,L"STATIC",L"Choose an integration before starting the node.",0,24,65,590,46,0);
        n->choose=widget(a,window,L"BUTTON",L"Integration: Power simulator",WS_TABSTOP,24,135,350,44,ID_SIMULATOR);
        n->power=widget(a,window,L"STATIC",L"",SS_CENTER,24,118,590,46,0); SendMessageW(n->power,WM_SETFONT,(WPARAM)a->power_font,TRUE);
        n->slider=widget(a,window,TRACKBAR_CLASSW,L"",TBS_HORZ|WS_TABSTOP,24,176,590,44,ID_SLIDER);
        SendMessageW(n->slider,TBM_SETRANGE,TRUE,MAKELPARAM(-GUI_POWER_W,GUI_POWER_W));
        SendMessageW(n->slider,TBM_SETPAGESIZE,0,500); SendMessageW(n->slider,TBM_SETPOS,TRUE,n->watts);
        n->legend=widget(a,window,L"STATIC",L"−10 kW export / +10 kW import · release to apply",SS_CENTER,24,222,590,22,0);
        n->applied=widget(a,window,L"STATIC",L"",SS_CENTER,24,247,590,22,0);
        n->start=widget(a,window,L"BUTTON",L"Start",WS_TABSTOP,24,274,120,34,ID_START);
        n->stop=widget(a,window,L"BUTTON",L"Stop",WS_TABSTOP,154,274,120,34,ID_STOP);
        n->remove=widget(a,window,L"BUTTON",L"Remove integration",WS_TABSTOP,414,274,200,34,ID_REMOVE);
        n->qr=CreateWindowExW(0,L"MatterCQR",L"",WS_CHILD|WS_VISIBLE,175,325,290,290,window,NULL,a->instance,n);
        n->note=widget(a,window,L"STATIC",L"",SS_CENTER,24,635,590,66,0);
        preview(n); show_controls(n); if(n->simulator) start(n); return 0;
    }
    case WM_HSCROLL:
        if((HWND)l==n->slider) {
            preview(n);
            if(LOWORD(w)==TB_ENDTRACK && !n->stopping) {
                int value=(int)SendMessageW(n->slider,TBM_GETPOS,0,0),old=n->watts;
                if(value!=old) {
                    n->watts=value;
                    if(!save(a)) { n->watts=old; SendMessageW(n->slider,TBM_SETPOS,TRUE,old); preview(n); error(window,L"Could not save power; the measurement was not sent."); }
                    else if(n->process && !send_power(n)) error(window,L"Could not send the measurement to the node.");
                }
            }
        } return 0;
    case WM_COMMAND:
        if(a->closing) return 0;
        switch(LOWORD(w)) {
        case ID_SIMULATOR: n->simulator=true; if(!save(a)) { n->simulator=false; error(window,L"Could not save the integration."); } else { refresh_list(a); show_controls(n); start(n); } break;
        case ID_START: start(n); break;
        case ID_STOP: stop(n,false); break;
        case ID_REMOVE:
            if(message_box(window,L"Stop the simulator and remove its integration? Pairing and node files will be retained.",L"Remove integration",MB_YESNO|MB_ICONQUESTION)==IDYES) stop(n,true);
            break;
        } show_controls(n); return 0;
    case WM_CLOSE: ShowWindow(window,SW_HIDE); return 0;
    }
    return DefWindowProcW(window,message,w,l);
}
static LRESULT CALLBACK qr_proc(HWND window,UINT message,WPARAM w,LPARAM l) {
    Node* n=(Node*)GetWindowLongPtrW(window,GWLP_USERDATA);
    if(message==WM_NCCREATE) { n=((CREATESTRUCTW*)l)->lpCreateParams; SetWindowLongPtrW(window,GWLP_USERDATA,(LONG_PTR)n); }
    if(message==WM_PAINT) {
        PAINTSTRUCT paint; HDC dc=BeginPaint(window,&paint); RECT rect; GetClientRect(window,&rect);
        FillRect(dc,&rect,(HBRUSH)GetStockObject(WHITE_BRUSH));
        if(n && n->show_qr && (n->qr_bits || build_qr(n))) {
            int size=qrcodegen_getSize(n->qr_bits),total=size+2*GUI_QR_MARGIN;
            int scale=(rect.right<rect.bottom?rect.right:rect.bottom)/total;
            int x0=(rect.right-total*scale)/2+GUI_QR_MARGIN*scale,y0=(rect.bottom-total*scale)/2+GUI_QR_MARGIN*scale;
            for(int y=0;y<size;++y) for(int x=0;x<size;++x) if(qrcodegen_getModule(n->qr_bits,x,y)) {
                RECT cell={x0+x*scale,y0+y*scale,x0+(x+1)*scale,y0+(y+1)*scale}; FillRect(dc,&cell,(HBRUSH)GetStockObject(BLACK_BRUSH));
            }
        } else {
            SetBkMode(dc,TRANSPARENT); SelectObject(dc,n?n->app->font:GetStockObject(DEFAULT_GUI_FONT));
            DrawTextW(dc,n && n->fabrics?L"Node paired":L"QR code shown during pairing",-1,&rect,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        }
        EndPaint(window,&paint); return 0;
    }
    return DefWindowProcW(window,message,w,l);
}
static wchar_t* field_text(HWND field) {
    int size=GetWindowTextLengthW(field)+1; wchar_t* text=calloc((size_t)size,sizeof(*text));
    if(text) GetWindowTextW(field,text,size);
    return text;
}
static LRESULT CALLBACK settings_proc(HWND window,UINT message,WPARAM w,LPARAM l) {
    App* a=application;
    switch(message) {
    case WM_CTLCOLORSTATIC: SetBkColor((HDC)w,RGB(255,255,255)); return (LRESULT)GetStockObject(WHITE_BRUSH);
    case WM_CREATE: {
        widget(a,window,L"STATIC",L"Test credentials folder: DAC / PAI / PAA / CD and DAC key",0,24,20,650,26,0);
        a->credentials_edit=widget(a,window,L"EDIT",a->credentials,WS_BORDER|ES_AUTOHSCROLL|WS_TABSTOP,24,52,510,28,ID_CREDENTIALS);
        widget(a,window,L"BUTTON",L"Browse…",WS_TABSTOP,546,52,110,28,ID_BROWSE);
        widget(a,window,L"STATIC",L"IPv6 interface index (Windows: Get-NetAdapter)",0,24,104,630,26,0);
        wchar_t iface[16]; swprintf(iface,16,L"%u",a->interface_id);
        a->interface_edit=widget(a,window,L"EDIT",iface,WS_BORDER|ES_NUMBER|WS_TABSTOP,24,137,130,28,ID_INTERFACE);
        widget(a,window,L"STATIC",L"Operational certificate validity policy",0,24,190,630,26,0);
        a->validity_edit=widget(a,window,L"COMBOBOX",L"",CBS_DROPDOWNLIST|WS_TABSTOP,24,223,400,100,ID_VALIDITY);
        SendMessageW(a->validity_edit,CB_ADDSTRING,0,(LPARAM)L"strict — validate dates");
        SendMessageW(a->validity_edit,CB_ADDSTRING,0,(LPARAM)L"chip — controller compatibility");
        SendMessageW(a->validity_edit,CB_SETCURSEL,a->chip?1:0,0);
        widget(a,window,L"STATIC",L"Test product: VID 0xFFF1 / PID 0x8001.\r\nMust match the credentials and Google Home Developer Console integration.\r\nNo Google account ID is required in this application.",0,24,280,630,72,0);
        widget(a,window,L"STATIC",L"Changes take effect after restarting the nodes.",0,24,367,630,28,0);
        widget(a,window,L"BUTTON",L"Save",WS_TABSTOP,526,420,130,36,ID_SAVE); return 0;
    }
    case WM_COMMAND:
        if(LOWORD(w)==ID_BROWSE) {
            BROWSEINFOW info={0}; info.hwndOwner=window; info.lpszTitle=L"Matter test credentials"; info.ulFlags=BIF_RETURNONLYFSDIRS|BIF_NEWDIALOGSTYLE;
            PIDLIST_ABSOLUTE item=SHBrowseForFolderW(&info);
            if(item) {
                wchar_t* path=calloc(GUI_INI_MAX_CHARS,sizeof(*path));
                if(path && SHGetPathFromIDListEx(item,path,GUI_INI_MAX_CHARS,0)) SetWindowTextW(a->credentials_edit,path);
                free(path); CoTaskMemFree(item);
            }
        } else if(LOWORD(w)==ID_SAVE) {
            wchar_t* path=field_text(a->credentials_edit); wchar_t* iface=field_text(a->interface_edit); unsigned index=0;
            if(!path || !iface || !number(iface,UINT32_MAX,&index) || !index || GetFileAttributesW(path)==INVALID_FILE_ATTRIBUTES) {
                free(path); free(iface); error(window,L"Select an existing credentials folder and a positive interface index."); return 0;
            }
            free(iface); wchar_t* old=a->credentials; unsigned old_index=a->interface_id; bool old_chip=a->chip;
            a->credentials=path; a->interface_id=index; a->chip=SendMessageW(a->validity_edit,CB_GETCURSEL,0,0)==1;
            if(save(a)) { free(old); DestroyWindow(window); }
            else { free(path); a->credentials=old; a->interface_id=old_index; a->chip=old_chip; error(window,L"Could not save settings."); }
        } return 0;
    case WM_DESTROY: a->settings=NULL; EnableWindow(a->window,TRUE); SetForegroundWindow(a->window); return 0;
    }
    return DefWindowProcW(window,message,w,l);
}
static LRESULT CALLBACK manager_proc(HWND window,UINT message,WPARAM w,LPARAM l) {
    App* a=application;
    switch(message) {
    case WM_CTLCOLORSTATIC: SetBkColor((HDC)w,RGB(255,255,255)); return (LRESULT)GetStockObject(WHITE_BRUSH);
    case WM_CREATE: {
        a->window=window;
        HWND title=widget(a,window,L"STATIC",L"Matter power sensors",0,24,20,680,38,0); SendMessageW(title,WM_SETFONT,(WPARAM)a->title_font,TRUE);
        widget(a,window,L"STATIC",L"One executable · independent nodes and pairings",0,24,68,680,28,0);
        a->list=widget(a,window,L"LISTBOX",L"",LBS_NOTIFY|WS_BORDER|WS_VSCROLL|WS_TABSTOP,24,115,680,200,ID_LIST);
        widget(a,window,L"BUTTON",L"+ New node",WS_TABSTOP,24,340,170,38,ID_NEW);
        widget(a,window,L"BUTTON",L"Open",WS_TABSTOP,210,340,130,38,ID_OPEN);
        widget(a,window,L"BUTTON",L"Settings",WS_TABSTOP,540,340,164,38,ID_SETTINGS);
        widget(a,window,L"STATIC",a->home,0,24,400,680,48,0);
        refresh_list(a); SetTimer(window,1,GUI_POLL_MS,NULL); return 0;
    }
    case WM_COMMAND:
        if(a->closing) return 0;
        if(LOWORD(w)==ID_NEW) add_node(a);
        else if(LOWORD(w)==ID_OPEN || (LOWORD(w)==ID_LIST && HIWORD(w)==LBN_DBLCLK)) {
            LRESULT row=SendMessageW(a->list,LB_GETCURSEL,0,0);
            if(row!=LB_ERR) open_node((Node*)SendMessageW(a->list,LB_GETITEMDATA,(WPARAM)row,0));
        } else if(LOWORD(w)==ID_SETTINGS && !a->settings) {
            a->settings=CreateWindowExW(WS_EX_DLGMODALFRAME,L"MatterCSettings",L"Settings — Matter C",WS_CAPTION|WS_SYSMENU,
                CW_USEDEFAULT,CW_USEDEFAULT,700,520,window,NULL,a->instance,NULL);
            EnableWindow(window,FALSE); ShowWindow(a->settings,SW_SHOW);
        } return 0;
    case WM_TIMER: {
        bool alive=false;
        for(Node* n=a->nodes;n;n=n->next) { poll_node(n); if(n->window) show_controls(n); alive|=n->process!=NULL; }
        if(a->closing && !alive) DestroyWindow(window);
        return 0;
    }
    case WM_CLOSE:
        a->closing=true;
        if(a->settings) DestroyWindow(a->settings);
        SetWindowTextW(window,L"Matter C — shutting down nodes…");
        for(Node* n=a->nodes;n;n=n->next) stop(n,false);
        return 0;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(window,message,w,l);
}
extern int matter_node_main(int,char**);
int WINAPI WinMain(HINSTANCE instance,HINSTANCE previous,LPSTR cmd,int show) {
    (void)previous; (void)cmd;
    for(int i=1;i<__argc;++i) if(!strcmp(__argv[i],"--gui-control")) return matter_node_main(__argc,__argv);
    SetProcessDPIAware(); HRESULT com=CoInitializeEx(NULL,COINIT_APARTMENTTHREADED);
    INITCOMMONCONTROLSEX controls={sizeof(controls),ICC_BAR_CLASSES}; InitCommonControlsEx(&controls);
    App* a=calloc(1,sizeof(*a)); if(!a) return 1;
    application=a; a->instance=instance; int result=1;
    int argc=0; wchar_t** argv=CommandLineToArgvW(GetCommandLineW(),&argc);
    if(argc==3 && !wcscmp(argv[1],L"--data-dir")) a->home=_wcsdup(argv[2]);
    else if(argc!=1) { error(NULL,L"Usage: matter-desktop [--data-dir DIRECTORY]"); goto done; }
    else {
        wchar_t* local=NULL;
        if(SHGetKnownFolderPath(&FOLDERID_LocalAppData,KF_FLAG_CREATE,NULL,&local)!=S_OK) goto done;
        a->home=join(local,L"MatterC"); CoTaskMemFree(local);
    }
    if(!a->home || (!CreateDirectoryW(a->home,NULL) && GetLastError()!=ERROR_ALREADY_EXISTS)) goto done;
    a->ini=join(a->home,L"settings.ini"); wchar_t* lock=join(a->home,L"manager.lock"); if(!a->ini || !lock) { free(lock); goto done; }
    a->lock=CreateFileW(lock,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL); free(lock);
    if(a->lock==INVALID_HANDLE_VALUE) { error(NULL,L"This profile is already open or its folder is inaccessible."); a->lock=NULL; goto done; }
    if(!load(a)) { error(NULL,L"Invalid or unsupported settings file. It has been left unchanged."); goto done; }
    a->exe=calloc(GUI_INI_MAX_CHARS,sizeof(*a->exe));
    if(!a->exe || !GetModuleFileNameW(NULL,a->exe,GUI_INI_MAX_CHARS)) goto done;
    a->job=CreateJobObjectW(NULL,NULL); if(!a->job) goto done;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits={0}; limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if(!SetInformationJobObject(a->job,JobObjectExtendedLimitInformation,&limits,sizeof(limits))) goto done;
    a->font=CreateFontW(-17,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,L"Segoe UI");
    a->title_font=CreateFontW(-26,0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,L"Segoe UI");
    a->power_font=CreateFontW(-32,0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,L"Segoe UI");
    const wchar_t* names[]={L"MatterCManager",L"MatterCNode",L"MatterCQR",L"MatterCSettings"};
    WNDPROC procedures[]={manager_proc,node_proc,qr_proc,settings_proc};
    /* Resource-owned shared handles: no DestroyIcon; both sizes use the
     * matching frame from the embedded multi-resolution ICO. */
    HICON icon=(HICON)LoadImageW(instance,MAKEINTRESOURCEW(IDI_MATTER_DESKTOP),IMAGE_ICON,
        GetSystemMetrics(SM_CXICON),GetSystemMetrics(SM_CYICON),LR_SHARED);
    HICON small_icon=(HICON)LoadImageW(instance,MAKEINTRESOURCEW(IDI_MATTER_DESKTOP),IMAGE_ICON,
        GetSystemMetrics(SM_CXSMICON),GetSystemMetrics(SM_CYSMICON),LR_SHARED);
    if(!icon || !small_icon) { error(NULL,L"Could not load the application icon."); goto done; }
    for(unsigned i=0;i<4;++i) {
        WNDCLASSEXW cls={0}; cls.cbSize=sizeof(cls); cls.lpfnWndProc=procedures[i]; cls.hInstance=instance; cls.lpszClassName=names[i];
        cls.hCursor=LoadCursorW(NULL,IDC_ARROW); cls.hIcon=icon; cls.hIconSm=small_icon; cls.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);
        if(!RegisterClassExW(&cls)) goto done;
    }
    a->window=CreateWindowExW(0,names[0],L"Matter C — power sensors",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,
        CW_USEDEFAULT,CW_USEDEFAULT,750,500,NULL,NULL,instance,NULL);
    if(!a->window) goto done;
    ShowWindow(a->window,show);
    for(Node* n=a->nodes;n;n=n->next) if(n->simulator) open_node(n);
    MSG message; BOOL message_result;
    while((message_result=GetMessageW(&message,NULL,0,0))>0) {
        HWND dialog=a->settings?a->settings:GetAncestor(message.hwnd,GA_ROOT);
        if(!IsDialogMessageW(dialog,&message)) { TranslateMessage(&message); DispatchMessageW(&message); }
    }
    result=message_result==0?0:1;
done:
    if(a->job) CloseHandle(a->job);
    while(a->nodes) { Node* n=a->nodes; a->nodes=n->next; close_process(n); free(n->qr_bits); SecureZeroMemory(n,sizeof(*n)); free(n); }
    if(a->lock) CloseHandle(a->lock);
    if(a->font) DeleteObject(a->font);
    if(a->title_font) DeleteObject(a->title_font);
    if(a->power_font) DeleteObject(a->power_font);
    free(a->home); free(a->ini); free(a->credentials); free(a->exe); free(a); LocalFree(argv);
    if(SUCCEEDED(com)) CoUninitialize();
    return result;
}
