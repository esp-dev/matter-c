/* Volatile, per-fabric MRU cache in the owning adapter's heap allocation.
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
    for(unsigned j=0;j<5;++j) for(unsigned k=0;k<MATTER_HOST_CASE_PER_FABRIC;++k) {
        const Matter_Case_Resumption_T* r=&h->resumption[j][k];
        if(!resume_live(h,j,r)) continue;
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
    unsigned target=MATTER_HOST_CASE_PER_FABRIC-1;
    for(unsigned a=0;a<5;++a) for(unsigned b=0;b<MATTER_HOST_CASE_PER_FABRIC;++b) {
        const Matter_Case_Resumption_T* old=&h->resumption[a][b];
        if(!resume_live(h,a,old)) continue;
        bool same=a==j && old->identity.peer_node_id==r->identity.peer_node_id;
        if(same) target=b;
        else if(h->crypto.equal(old->id,r->id,16)) return MATTER_INVALID_STATE;
    }
    /* Recency changes only after authenticated handoff, never on a cache hit
     * from unauthenticated Sigma1. Eviction cannot consume another fabric. */
    for(unsigned k=target;k>0;--k) h->resumption[j][k]=h->resumption[j][k-1];
    h->resumption[j][0]=*r; return MATTER_OK;
}
