/* Volatile, per-fabric MRU cache, allocated after authenticated handoff.
 * Restart safely falls back to full CASE; durable fabric schema is unchanged. */
static bool resume_live(Matter_Fabric_Host_T h,unsigned slot,const Matter_Case_Resumption_T* r) {
    const Matter_Fabric_Record_T* f=&h->image->data.view.records[slot];
    return f->index && r->identity.fabric_index==f->index && r->revision==h->case_revision[slot] &&
        r->identity.fabric_id==f->fabric_id && r->identity.local_node_id==f->node_id;
}
static Matter_Result_T resume_find(void* u,uint8_t index,uint64_t peer,const uint8_t* id,Matter_Case_Resumption_T* out) {
    Matter_Fabric_Host_T h=u;
    if(!h || !out || (!id && (!index || !peer))) return MATTER_INVALID_ARGUMENT;
    if(h->busy) return MATTER_BUSY;
    const Matter_Case_Resumption_T* found=NULL;
    for(Resumption_Node* node=h->resumption;node;node=node->next) {
        const Matter_Case_Resumption_T* r=&node->value;
        unsigned j=slot(h,r->identity.fabric_index);
        if(j==5 || !resume_live(h,j,r)) continue;
        bool match=id?h->crypto.equal(id,r->id,16):(index==r->identity.fabric_index && peer==r->identity.peer_node_id);
        if(match) { if(found) return MATTER_INVALID_STATE; found=r; }
    }
    if(!found) return MATTER_INVALID_STATE;
    *out=*found; return MATTER_OK;
}
static Matter_Result_T resume_save(void* u,const Matter_Case_Resumption_T* r) {
    Matter_Fabric_Host_T h=u;
    if(!h || !r || !r->identity.peer_node_id || r->identity.peer_node_id>UINT64_C(0xffffffefffffffff) || r->identity.cat_count>3) return MATTER_INVALID_ARGUMENT;
    if(h->busy) return MATTER_BUSY;
    unsigned j=slot(h,r->identity.fabric_index);
    if(j==5 || !resume_live(h,j,r)) return MATTER_INVALID_STATE;
    /* A collision must never make an ID select another authenticated identity. */
    Resumption_Node **same=NULL,**oldest=NULL;
    size_t count=0;
    for(Resumption_Node** link=&h->resumption;*link;link=&(*link)->next) {
        const Matter_Case_Resumption_T* old=&(*link)->value;
        unsigned a=slot(h,old->identity.fabric_index);
        if(a==5 || !resume_live(h,a,old)) continue;
        bool match=a==j && old->identity.peer_node_id==r->identity.peer_node_id;
        if(match) same=link;
        else if(h->crypto.equal(old->id,r->id,16)) return MATTER_INVALID_STATE;
        if(a==j) { ++count; oldest=link; }
    }
    /* Recency changes only after authenticated handoff, never on a cache hit
     * from unauthenticated Sigma1. Eviction cannot consume another fabric. */
    Resumption_Node* node;
    Resumption_Node** reuse=same?same:count==MATTER_HOST_CASE_PER_FABRIC?oldest:NULL;
    if(reuse) { node=*reuse; *reuse=node->next; }
    else { node=calloc(1,sizeof(*node)); if(!node) return MATTER_LIMIT_REACHED; }
    erase(&node->value,sizeof(node->value)); node->value=*r;
    node->next=h->resumption; h->resumption=node; return MATTER_OK;
}
