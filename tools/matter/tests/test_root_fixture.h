/* RAM persistence simulates an application port; no production identity or
 * assertion that the PASE fixture meets advertised per-fabric capabilities. */
#include "clusters/matter_root.h"
#include "codec/matter_tlv_writer.h"
#define ROOT_CHECK(c) do { if(!(c)) { fprintf(stderr,"Root:%d: %s\n",__LINE__,#c); abort(); } } while(0)
typedef struct {
    Matter_Root_Config_T durable;
    Matter_Root_T root;
    Matter_Im_Read_Port_T read;
    Matter_Im_Write_Port_T write;
    Matter_Tlv_Writer_T writer;
    Matter_Tlv_Reader_T reader;
    Matter_Tlv_Element_T token;
    uint8_t request[256], expected[128];
    size_t request_size;
    unsigned stores, loads, auths, received;
    uint64_t seen;
    uint8_t denied;
    bool fail_load, fail_store, reenter;
    Matter_Exchange_Session_T session;
    Matter_Im_Privilege_T last_privilege;
} RootFixture;
static const uint32_t root_descriptor_ids[]={0,1,2,3,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};
static const uint32_t root_basic_ids[]={0,1,2,3,4,5,6,7,8,9,10,18,19,21,22,24,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};
static Matter_Result_T root_load(void* u,Matter_Root_Config_T* c) {
    RootFixture* f=u; ++f->loads; if(f->fail_load) return MATTER_PORT_ERROR;
    *c=f->durable; return MATTER_OK;
}
static uint8_t root_authorize(void* u,Matter_Exchange_Session_T session,const Matter_Im_Path_T* p,Matter_Im_Privilege_T privilege) {
    RootFixture* f=u; ROOT_CHECK(p && session==f->session); ++f->auths; f->last_privilege=privilege;
    if(f->reenter) ROOT_CHECK(matter_root_delete(f->root)==MATTER_BUSY);
    return f->denied;
}
static Matter_Result_T root_store(void* u,const Matter_Root_Settings_T* s) {
    RootFixture* f=u; ++f->stores;
    if(f->reenter) {
        ROOT_CHECK(matter_root_delete(f->root)==MATTER_BUSY);
        ROOT_CHECK(matter_root_ports(f->root,&f->read,&f->write)==MATTER_BUSY);
        Matter_Im_Value_T value; Matter_Im_Path_T p={0,0x28,5};
        ROOT_CHECK(f->read.read(f->root,&p,true,&value)==MATTER_IM_FAILURE);
        Matter_Cluster_Request_T q={0};
        ROOT_CHECK(matter_cluster_read(matter_root_cluster(f->root,0x1d),0,&q,&value)==MATTER_IM_FAILURE);
    }
    if(f->fail_store) return MATTER_PORT_ERROR;
    f->durable.settings=*s; return MATTER_OK;
}
static Matter_Root_Port_T root_port(RootFixture* f) {
    return (Matter_Root_Port_T){f,root_load,root_authorize,root_store};
}
static void root_text(Matter_Root_Text_T* t,const char* value) {
    t->size=strlen(value); ROOT_CHECK(t->size<=sizeof(t->data)); memcpy(t->data,value,t->size);
}
static RootFixture* root_fixture(void) {
    RootFixture* f=calloc(1,sizeof(*f)); ROOT_CHECK(f); f->session=1;
    root_text(&f->durable.vendor_name,"Matter C"); root_text(&f->durable.product_name,"Matter C (simulation)");
    root_text(&f->durable.hardware_string,"host"); root_text(&f->durable.software_string,"M10a");
    root_text(&f->durable.unique_id,"simulated-reset-identity-1");
    f->durable.vendor_id=0xfff1; f->durable.product_id=0x8001; f->durable.hardware_version=1;
    f->durable.software_version=10; f->durable.configuration_version=1;
    f->durable.capabilities=(Matter_Root_Capabilities_T){3,3,1,1,9,3};
    f->durable.settings.location[0]='X'; f->durable.settings.location[1]='X';
    f->durable.descriptor_version=11; f->durable.basic_version=7;
    return f;
}
static void root_open(RootFixture* f) {
    Matter_Root_Port_T p=root_port(f); f->root=matter_root_new(&p); ROOT_CHECK(f->root);
    ROOT_CHECK(matter_root_ports(f->root,&f->read,&f->write)==MATTER_OK);
}
static void root_release(RootFixture* f) {
    if(f->root) ROOT_CHECK(matter_root_delete(f->root)==MATTER_OK);
    free(f);
}
static void root_put(RootFixture* f,Matter_Tlv_Type_T type,int tag,uint64_t n,const uint8_t* data,size_t size) {
    f->token=(Matter_Tlv_Element_T){.type=type,.tag={.control=tag<0?0:1,.number=tag<0?0:(uint32_t)tag},.unsigned_value=n,.data=data,.size=size};
    ROOT_CHECK(matter_tlv_write(&f->writer,&f->token,0)==MATTER_TLV_OK);
}
static void root_read_request(RootFixture* f,bool filter) {
    ROOT_CHECK(matter_tlv_writer_init(&f->writer,f->request,sizeof(f->request),6)==MATTER_TLV_OK);
    root_put(f,MATTER_TLV_STRUCTURE,-1,0,NULL,0); root_put(f,MATTER_TLV_ARRAY,0,0,NULL,0);
    root_put(f,MATTER_TLV_LIST,-1,0,NULL,0); root_put(f,MATTER_TLV_UNSIGNED,2,0,NULL,0);
    root_put(f,MATTER_TLV_END,-1,0,NULL,0); root_put(f,MATTER_TLV_END,-1,0,NULL,0);
    if(filter) {
        root_put(f,MATTER_TLV_ARRAY,4,0,NULL,0);
        for(unsigned i=0;i<2;++i) {
            root_put(f,MATTER_TLV_STRUCTURE,-1,0,NULL,0); root_put(f,MATTER_TLV_LIST,0,0,NULL,0);
            root_put(f,MATTER_TLV_UNSIGNED,1,0,NULL,0); root_put(f,MATTER_TLV_UNSIGNED,2,i?0x28:0x1d,NULL,0);
            root_put(f,MATTER_TLV_END,-1,0,NULL,0); root_put(f,MATTER_TLV_UNSIGNED,1,i?f->durable.basic_version:f->durable.descriptor_version,NULL,0);
            root_put(f,MATTER_TLV_END,-1,0,NULL,0);
        }
        root_put(f,MATTER_TLV_END,-1,0,NULL,0);
    }
    root_put(f,MATTER_TLV_BOOL,3,1,NULL,0); root_put(f,MATTER_TLV_UNSIGNED,255,13,NULL,0);
    root_put(f,MATTER_TLV_END,-1,0,NULL,0); ROOT_CHECK(matter_tlv_writer_finish(&f->writer,&f->request_size)==MATTER_TLV_OK);
}
static void root_write_request(RootFixture* f,uint32_t attribute,const uint8_t* data,size_t size,uint32_t version) {
    ROOT_CHECK(matter_tlv_writer_init(&f->writer,f->request,sizeof(f->request),6)==MATTER_TLV_OK);
    root_put(f,MATTER_TLV_STRUCTURE,-1,0,NULL,0); root_put(f,MATTER_TLV_BOOL,1,0,NULL,0);
    root_put(f,MATTER_TLV_ARRAY,2,0,NULL,0); root_put(f,MATTER_TLV_STRUCTURE,-1,0,NULL,0);
    root_put(f,MATTER_TLV_UNSIGNED,0,version,NULL,0); root_put(f,MATTER_TLV_LIST,1,0,NULL,0);
    root_put(f,MATTER_TLV_UNSIGNED,2,0,NULL,0); root_put(f,MATTER_TLV_UNSIGNED,3,0x28,NULL,0);
    root_put(f,MATTER_TLV_UNSIGNED,4,attribute,NULL,0); root_put(f,MATTER_TLV_END,-1,0,NULL,0);
    root_put(f,MATTER_TLV_UTF8,2,0,data,size); root_put(f,MATTER_TLV_END,-1,0,NULL,0);
    root_put(f,MATTER_TLV_END,-1,0,NULL,0); root_put(f,MATTER_TLV_UNSIGNED,255,13,NULL,0);
    root_put(f,MATTER_TLV_END,-1,0,NULL,0); ROOT_CHECK(matter_tlv_writer_finish(&f->writer,&f->request_size)==MATTER_TLV_OK);
}
/* Independent expected semantic values and literal container encodings. */
static void root_expect(RootFixture* f,uint32_t cluster,uint32_t attr,const Matter_Im_Value_T* v) {
    if(attr==0xfffd || attr==0xfffc) {
        ROOT_CHECK(v->type==MATTER_TLV_UNSIGNED && v->unsigned_value==(attr==0xfffc?0:cluster==0x1d?3:6)); return;
    }
    if(cluster==0x1d || attr>=0xfff8 || attr==19) {
        static const uint8_t device[]={0x16,0x15,0x24,0,0x16,0x24,1,5,0x18,0x18};
        static const uint8_t servers[]={0x16,4,0x1d,4,0x28,0x18}, empty[]={0x16,0x18};
        static const uint8_t caps[]={0x15,0x24,0,3,0x24,1,3,0x24,2,1,0x24,3,1,0x24,4,9,0x24,5,3,0x18};
        const uint8_t* expected=empty; size_t n=sizeof(empty);
        ROOT_CHECK(v->type==(attr==19?MATTER_TLV_STRUCTURE:MATTER_TLV_ARRAY));
        if(attr==0) { expected=device; n=sizeof(device); }
        if(attr==1) { expected=servers; n=sizeof(servers); }
        if(attr==19) { expected=caps; n=sizeof(caps); }
        if(attr==0xfffb) {
            const uint32_t* ids=cluster==0x1d?root_descriptor_ids:root_basic_ids;
            unsigned count=cluster==0x1d?9:21; n=0; f->expected[n++]=0x16;
            for(unsigned i=0;i<count;++i) {
                f->expected[n++]=ids[i]>255?5:4; f->expected[n++]=(uint8_t)ids[i];
                if(ids[i]>255) f->expected[n++]=(uint8_t)(ids[i]>>8);
            }
            f->expected[n++]=0x18; expected=f->expected;
        }
        ROOT_CHECK(v->size==n && !memcmp(v->data,expected,n)); return;
    }
    const Matter_Root_Text_T* text=NULL; uint64_t number=0;
    switch(attr) {
    case 0: number=21; break; case 1: text=&f->durable.vendor_name; break; case 2: number=0xfff1; break;
    case 3: text=&f->durable.product_name; break; case 4: number=0x8001; break;
    case 5: ROOT_CHECK(v->type==MATTER_TLV_UTF8 && v->size==f->durable.settings.node_label_size && !memcmp(v->data,f->durable.settings.node_label,v->size)); return;
    case 6: ROOT_CHECK(v->type==MATTER_TLV_UTF8 && v->size==2 && !memcmp(v->data,f->durable.settings.location,2)); return;
    case 7: number=1; break; case 8: text=&f->durable.hardware_string; break; case 9: number=10; break;
    case 10: text=&f->durable.software_string; break; case 18: text=&f->durable.unique_id; break;
    case 21: number=0x01060100; break; case 22: number=1; break; case 24: number=1; break;
    default: ROOT_CHECK(false);
    }
    if(text) ROOT_CHECK(v->type==MATTER_TLV_UTF8 && v->size==text->size && !memcmp(v->data,text->data,v->size));
    else ROOT_CHECK(v->type==MATTER_TLV_UNSIGNED && v->unsigned_value==number);
}
static bool root_report(RootFixture* f,const uint8_t* data,size_t size,uint32_t basic_version) {
    ROOT_CHECK(matter_tlv_init(&f->reader,data,size,8)==MATTER_TLV_OK);
    unsigned depth=0; uint32_t cluster=0,attribute=0,version=0; bool more=false,suppress=false;
    Matter_Tlv_Result_T result;
    while((result=matter_tlv_next(&f->reader,&f->token))==MATTER_TLV_OK) {
        Matter_Tlv_Element_T* e=&f->token;
        if(e->type==MATTER_TLV_END) { ROOT_CHECK(depth); --depth; continue; }
        ROOT_CHECK(!(depth==3 && e->tag.number==0)); /* No AttributeStatusIB. */
        if(depth==4 && e->tag.number==0) version=(uint32_t)e->unsigned_value;
        if(depth==5 && e->tag.number==2) ROOT_CHECK(e->unsigned_value==0);
        if(depth==5 && e->tag.number==3) cluster=(uint32_t)e->unsigned_value;
        if(depth==5 && e->tag.number==4) attribute=(uint32_t)e->unsigned_value;
        if(depth==5 && e->tag.number==5) ROOT_CHECK(false); /* These small lists fit one IB. */
        if(depth==4 && e->tag.number==2) {
            ROOT_CHECK(cluster==0x1d || cluster==0x28);
            ROOT_CHECK(version==(cluster==0x1d?11:basic_version));
            Matter_Im_Value_T v={.type=e->type,.unsigned_value=e->unsigned_value,.data=e->data,.size=e->size};
            if(e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_STRUCTURE) {
                size_t start=e->offset; ROOT_CHECK(matter_tlv_skip_container(&f->reader)==MATTER_TLV_OK);
                size_t bytes=f->reader.offset-start; ROOT_CHECK(bytes>1 && bytes-1<=sizeof(f->expected));
                /* Value tag is context-specific: remove its one tag byte. */
                uint8_t* normalized=f->request; normalized[0]=data[start]&31;
                memcpy(normalized+1,data+start+2,bytes-2); v.data=normalized; v.size=bytes-1;
            }
            root_expect(f,cluster,attribute,&v);
            const uint32_t* ids=cluster==0x1d?root_descriptor_ids:root_basic_ids; unsigned count=cluster==0x1d?9:21,i=0;
            while(i<count && ids[i]!=attribute) ++i;
            ROOT_CHECK(i<count);
            uint64_t bit=UINT64_C(1)<<(i+(cluster==0x1d?0:9)); ROOT_CHECK(!(f->seen&bit)); f->seen|=bit; ++f->received;
            continue;
        }
        if(depth==1 && e->tag.number==3) more=e->unsigned_value!=0;
        if(depth==1 && e->tag.number==4) suppress=e->unsigned_value!=0;
        if(e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_LIST) ++depth;
    }
    ROOT_CHECK(result==MATTER_TLV_DONE && !depth && more!=suppress); return more;
}
