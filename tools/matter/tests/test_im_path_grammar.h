/* Wire-level grammar matrix, compiled independently for Read and Subscribe.
 * No production validation helpers are called by the oracle. */
#include "codec/matter_tlv_writer.h"
typedef struct {
    unsigned enumerations,auths,reads,reserves,releases;
    uint32_t attribute;
    Matter_Tlv_Writer_T writer;
    uint8_t input[128];
} PathGrammar;
static Matter_Im_Status_T grammar_allow(void* u,Matter_Exchange_Session_T session,
    const Matter_Im_Path_T* p,Matter_Im_Privilege_T privilege) {
    PathGrammar* g=u; CHECK(session==1 && p->endpoint==0 && p->cluster==0x28 && privilege==MATTER_IM_VIEW);
    ++g->auths; return MATTER_IM_SUCCESS;
}
static Matter_Im_Status_T grammar_describe(void* u,const Matter_Im_Path_T* p,Matter_Im_Attribute_T* a) {
    PathGrammar* g=u; CHECK(p->attribute==g->attribute);
    *a=(Matter_Im_Attribute_T){MATTER_IM_VIEW,false}; return MATTER_IM_SUCCESS;
}
static Matter_Im_Status_T grammar_read(void* u,const Matter_Im_Path_T* p,bool filtered,Matter_Im_Value_T* v) {
    PathGrammar* g=u; CHECK(filtered && p->attribute==g->attribute); ++g->reads;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.unsigned_value=42,.data_version=1}; return MATTER_IM_SUCCESS;
}
static Matter_Result_T grammar_enumerate(void* u,const Matter_Im_Selector_T* q,
    const Matter_Im_Path_T* after,Matter_Im_Path_T* p,bool* found) {
    PathGrammar* g=u; ++g->enumerations;
    CHECK(!(q->present & MATTER_IM_ATTRIBUTE) || q->path.attribute==g->attribute);
    *found=!after; *p=(Matter_Im_Path_T){0,0x28,g->attribute}; return MATTER_OK;
}
#ifdef TEST_PATH_SUB
static uint8_t grammar_reserve(void* u,Matter_Exchange_Session_T session,bool keep,uint32_t* id) {
    PathGrammar* g=u; CHECK(session==1 && keep); ++g->reserves; *id=42; return MATTER_OK;
}
static void grammar_release(void* u,uint32_t id) { PathGrammar* g=u; CHECK(id==42); ++g->releases; }
#endif
static void grammar_put(PathGrammar* g,Matter_Tlv_Type_T type,int tag,uint32_t value) {
    Matter_Tlv_Element_T e={.type=type,.tag={.control=tag<0?0:1,.number=tag<0?0:(uint32_t)tag},.unsigned_value=value};
    CHECK(!matter_tlv_write(&g->writer,&e,0));
}
static void grammar_path(PathGrammar* g,unsigned mask,uint32_t attribute) {
    grammar_put(g,MATTER_TLV_LIST,-1,0);
    if(mask&1) grammar_put(g,MATTER_TLV_UNSIGNED,2,0);
    if(mask&2) grammar_put(g,MATTER_TLV_UNSIGNED,3,0x28);
    if(mask&4) grammar_put(g,MATTER_TLV_UNSIGNED,4,attribute);
    grammar_put(g,MATTER_TLV_END,-1,0);
}
static void path_grammar_tests(void) {
    static const struct { uint32_t id; bool global; } ids[]={
        {0,false},{2,false},{0x4fff,false},{0x5000,false},{0xefff,false},
        {0xf000,true},{0xfff8,true},{0xfffb,true},{0xfffc,true},{0xfffd,true},{0xfffe,true},
        {0xffff,false},{0x10000,false},{0x0001f000,false},{0xfff1fffd,false},{UINT32_MAX,false}
    };
    for(size_t i=0;i<sizeof(ids)/sizeof(ids[0]);++i) for(unsigned mask=0;mask<8;++mask)
    for(unsigned mixed=0;mixed<2;++mixed) {
        bool valid=mask!=4 && mask!=5; valid|=ids[i].global;
        PathGrammar* g=calloc(1,sizeof(*g)); CHECK(g); g->attribute=ids[i].id;
        CHECK(!matter_tlv_writer_init(&g->writer,g->input,sizeof(g->input),4));
        grammar_put(g,MATTER_TLV_STRUCTURE,-1,0);
#ifdef TEST_PATH_SUB
        grammar_put(g,MATTER_TLV_BOOL,0,1); grammar_put(g,MATTER_TLV_UNSIGNED,1,1); grammar_put(g,MATTER_TLV_UNSIGNED,2,5);
        grammar_put(g,MATTER_TLV_ARRAY,3,0);
#else
        grammar_put(g,MATTER_TLV_ARRAY,0,0);
#endif
        /* A later bad path must reject the entire request before reading or
         * reserving resources for an earlier valid path. */
        if(mixed) grammar_path(g,7,g->attribute);
        grammar_path(g,mask,g->attribute); grammar_put(g,MATTER_TLV_END,-1,0);
#ifdef TEST_PATH_SUB
        grammar_put(g,MATTER_TLV_BOOL,7,1);
#else
        grammar_put(g,MATTER_TLV_BOOL,3,1);
#endif
        grammar_put(g,MATTER_TLV_UNSIGNED,255,13); grammar_put(g,MATTER_TLV_END,-1,0);
        size_t n=0; CHECK(!matter_tlv_writer_finish(&g->writer,&n));
        Matter_Im_Read_Port_T port={g,grammar_allow,grammar_describe,grammar_read,grammar_enumerate,NULL};
        Matter_Rx_Decision_T d={.action=MATTER_RX_NEW_RESPONDER,.session=1,
            .header={.protocol_id=1,.exchange_id=12,.exchange_flags=1},.payload=g->input,.payload_size=n};
#ifdef TEST_PATH_SUB
        Matter_Im_Subscribe_Port_T sub={.attributes=port,.reserve=grammar_reserve,.release=grammar_release};
        Matter_Im_Subscribe_Config_T c={{1,12,false},1000,512,true};
        Matter_Im_Subscribe_T s=matter_im_subscribe_new(&sub,&c,0); CHECK(s); d.header.opcode=3;
        CHECK(!matter_im_subscribe_receive(s,&d)); Matter_Im_Subscribe_Message_T out;
        for(unsigned step=0;;++step) {
            CHECK(step<8 && matter_im_subscribe_process(s,0)==MATTER_PENDING);
            if(!matter_im_subscribe_output(s,&out)) break;
        }
#else
        Matter_Im_Read_Config_T c={{1,12,false},1000,512,true};
        Matter_Im_Read_T s=matter_im_read_new(&port,&c,0); CHECK(s); d.header.opcode=2;
        CHECK(!matter_im_read_receive(s,&d)); Matter_Im_Read_Message_T out;
        for(unsigned step=0;;++step) {
            CHECK(step<8 && matter_im_read_process(s,0)==MATTER_PENDING);
            if(!matter_im_read_output(s,&out)) break;
        }
#endif
        if(valid) CHECK(out.opcode==5 && g->reads==1+mixed && g->auths);
        else CHECK(out.opcode==1 && out.size==8 && out.data[3]==MATTER_IM_INVALID_ACTION &&
            !g->reads && !g->auths && !g->enumerations && !g->reserves);
#ifdef TEST_PATH_SUB
        CHECK(g->reserves==(valid?1u:0u)); CHECK(!matter_im_subscribe_delete(s)); CHECK(g->releases==g->reserves);
#else
        CHECK(!matter_im_read_delete(s));
#endif
        free(g);
    }
    puts("PASS path grammar: 256 wire requests, all masks, global range/prefix boundaries, mixed valid/invalid paths before callbacks");
}
