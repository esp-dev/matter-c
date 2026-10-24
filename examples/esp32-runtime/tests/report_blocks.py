"""Generate owner-only Read/Subscribe block inventory in an isolated source copy.

The intrusive registry adds one pointer per interaction and small static counters.
No allocation, data reads or production API changes; normal images stay untouched.
The owner samples at process boundaries, so maxima are observed lower bounds.
"""
import argparse
import hashlib
import json
from pathlib import Path


def generate_app(source):
    """Wire periodic/coincident sampling on the app owner, outside core hooks.

    The separate allocator observer must also be generated with allocation_trace.
    """
    if 'static void block_sample(' in source:
        raise ValueError('app already instrumented')
    replacements=(
        ('#include "matter_idf_memory.h"', '''#include "matter_idf_memory.h"
extern void matter_alloc_audit_dump(const char*);
extern void matter_im_read_blocks_sample(void);
extern void matter_im_subscribe_blocks_sample(void);
extern size_t matter_im_read_blocks_bytes(void);
extern size_t matter_im_subscribe_blocks_bytes(void);
extern void matter_im_read_blocks_joint(void);
extern void matter_im_subscribe_blocks_joint(void);
extern void matter_im_read_blocks_dump(const char*);
extern void matter_im_subscribe_blocks_dump(const char*);
static void block_sample(void) {
    static size_t peak; matter_im_read_blocks_sample(); matter_im_subscribe_blocks_sample();
    size_t total=matter_im_read_blocks_bytes()+matter_im_subscribe_blocks_bytes();
    if(total>peak) { peak=total; matter_im_read_blocks_joint(); matter_im_subscribe_blocks_joint(); }
}
static void block_dump(const char* phase) {
    block_sample(); matter_alloc_audit_dump(phase); matter_im_read_blocks_dump(phase); matter_im_subscribe_blocks_dump(phase);
}'''),
        ('    advertisements(a,false); vTaskDelay(pdMS_TO_TICKS(10));', '''    static uint64_t audit_last;
    if(now()-audit_last>=100) { audit_last=now(); block_sample(); }
    advertisements(a,false); vTaskDelay(pdMS_TO_TICKS(10));'''),
        ('sample("runtime-created");', 'sample("runtime-created"); block_dump("runtime-created");'),
        ('if(c==\'m\') { COMPARE_REPORT("checkpoint"); tasks(); }', 'if(c==\'m\') { block_dump("checkpoint"); COMPARE_REPORT("checkpoint"); tasks(); }'),
        ('sample("complete"); tasks(); HEAP_SETTLE();', 'block_dump("complete"); sample("complete"); tasks(); HEAP_SETTLE();'),
    )
    for old,new in replacements:
        if source.count(old)!=1:
            raise ValueError('expected one app owner pattern: '+old)
        source=source.replace(old,new)
    return source


def generate(source, kind):
    if kind=='app':return generate_app(source)
    if kind=='allocator':
        from allocation_trace import generate as allocator
        return allocator(source).replace('AUDIT_SITES=128','AUDIT_SITES=160')
    if kind not in ('read', 'subscribe'):
        raise ValueError('unknown interaction')
    if 'BlockAudit' in source:
        raise ValueError('source already instrumented')
    name = 'Matter_Im_Read' if kind == 'read' else 'Matter_Im_Subscribe'
    prefix = 'read' if kind == 'read' else 'sub'
    item = 'ReadItem' if kind == 'read' else 'SubItem'
    def replace(old, new):
        nonlocal source
        if source.count(old) != 1:
            raise ValueError('Expected exactly one ' + old)
        source = source.replace(old, new)
    replace('#include <string.h>', '#include <string.h>\n#include <stdio.h>')
    marker = ('Matter_Im_Output_Pool* output_pool;' if kind == 'read' else '    bool output_copied;')
    replace(marker, marker+'\n    struct '+name+'* audit_next;')
    at = source.index('static uint64_t add(' if kind == 'subscribe' else 'static Matter_Result_T check(')
    support = r'''
typedef struct {
    size_t instances,logical,slots,blocks,headers,padding,retired;
    size_t value_slots,value_selected,value_headers,value_padding,value_retired;
} BlockAudit;
static HANDLE audit_head;
static BlockAudit audit_peak,audit_slack,audit_current,audit_joint;
static size_t audit_samples;
static size_t audit_bytes(const BlockAudit* a) { return a->headers+a->slots*sizeof(ITEM)+a->value_headers+a->value_slots*sizeof(Matter_Im_Snapshot_Value); }
void matter_im_KIND_blocks_sample(void) {
    BlockAudit a={0}; ++audit_samples;
    for(HANDLE s=audit_head;s;s=s->audit_next) {
        ++a.instances; a.logical+=s->count;
        for(Matter_Im_Block* b=s->items.head;b;b=b->next) {
            ++a.blocks; a.slots+=b->count; a.headers+=offsetof(PREFIX_items_Block,data);
            size_t used=s->count>b->start?s->count-b->start:0; if(used>b->count) used=b->count;
            a.padding+=(b->count-used)*sizeof(ITEM);
            size_t retired=s->released>b->start?s->released-b->start:0; if(retired>used) retired=used;
            a.retired+=retired*sizeof(ITEM);
        }
VALUE_SCAN
    }
    audit_current=a;
    if(audit_bytes(&a)>audit_bytes(&audit_peak)) audit_peak=a;
    if(a.padding+a.value_padding>audit_slack.padding+audit_slack.value_padding) audit_slack=a;
}
size_t matter_im_KIND_blocks_bytes(void) { return audit_bytes(&audit_current); }
void matter_im_KIND_blocks_joint(void) { audit_joint=audit_current; }
static void audit_print(const char* phase,const char* mode,const BlockAudit* a) {
    printf("BLOCK_AUDIT {\"kind\":\"KIND\",\"phase\":\"%s\",\"mode\":\"%s\",\"samples\":%u,\"item_size\":%u,\"value_size\":%u,\"instances\":%u,\"logical\":%u,\"slots\":%u,\"blocks\":%u,\"headers\":%u,\"padding\":%u,\"retired\":%u,\"value_slots\":%u,\"value_selected\":%u,\"value_headers\":%u,\"value_padding\":%u,\"value_retired\":%u,\"requested_bytes\":%u}\n",
      phase,mode,(unsigned)audit_samples,(unsigned)sizeof(ITEM),(unsigned)sizeof(Matter_Im_Snapshot_Value),
      (unsigned)a->instances,(unsigned)a->logical,(unsigned)a->slots,(unsigned)a->blocks,(unsigned)a->headers,(unsigned)a->padding,(unsigned)a->retired,
      (unsigned)a->value_slots,(unsigned)a->value_selected,(unsigned)a->value_headers,(unsigned)a->value_padding,(unsigned)a->value_retired,(unsigned)audit_bytes(a));
}
void matter_im_KIND_blocks_dump(const char* phase) {
    matter_im_KIND_blocks_sample(); audit_print(phase,"peak-bytes",&audit_peak); audit_print(phase,"peak-padding",&audit_slack); audit_print(phase,"peak-joint",&audit_joint); audit_print(phase,"current",&audit_current);
    printf("BLOCK_REGISTRY {\"kind\":\"KIND\",\"phase\":\"%s\",\"empty\":%s}\n",phase,audit_head?"false":"true");
}
static void audit_remove(HANDLE s) {
    HANDLE* link=&audit_head; while(*link && *link!=s) link=&(*link)->audit_next;
    if(*link) *link=s->audit_next;
}
'''
    value_scan = r'''        Matter_Im_Blocks items=s->items;
        for(Matter_Im_Block* b=s->values.head;b;b=b->next) {
            a.value_slots+=b->count; a.value_headers+=offsetof(sub_values_Block,data);
            for(size_t j=0;j<b->count;++j) {
                size_t i=b->start+j;
                SubItem* v=sub_items_at(&items,i);
                bool selected=i<s->collected && v && v->included && !v->status;
                if(selected) ++a.value_selected; else a.value_padding+=sizeof(Matter_Im_Snapshot_Value);
                if(selected && i<s->released) a.value_retired+=sizeof(Matter_Im_Snapshot_Value);
            }
        }'''
    support = support.replace('VALUE_SCAN',value_scan if kind=='subscribe' else '').replace('HANDLE',name+'_T').replace('PREFIX',prefix).replace('KIND',kind).replace('ITEM',item)
    source=source[:at]+support+'\n'+source[at:]
    # Register only a fully constructed interaction; failed constructors retain no link.
    a=source.index(name+'_T matter_im_'+kind+'_new(')
    b=source.index('\n}',a)
    part=source[a:b]
    if part.count('return s;')!=1:raise ValueError('constructor changed')
    source=source[:a]+part.replace('return s;', 'if(s) { s->audit_next=audit_head; audit_head=s; } return s;')+source[b:]
    a=source.index('Matter_Result_T matter_im_'+kind+'_delete(')
    part=source[a:]
    check='if (r != MATTER_OK) return r;' if kind=='read' else 'if(r) return r;'
    if part.count(check)!=1:raise ValueError('destructor guard changed')
    part=part.replace(check,check+' matter_im_'+kind+'_blocks_sample();',1)
    if part.count('memset(s,0,sizeof(*s));')!=1:raise ValueError('destructor changed')
    source=source[:a]+part.replace('memset(s,0,sizeof(*s));','audit_remove(s); memset(s,0,sizeof(*s));')
    return source


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',required=True,type=Path)
    p.add_argument('--output',required=True,type=Path)
    p.add_argument('--kind',required=True,choices=('read','subscribe','app','allocator'))
    args=p.parse_args()
    if args.source.resolve()==args.output.resolve():p.error('use a separate output copy')
    original=args.source.read_text()
    result=generate(original,args.kind)
    args.output.write_text(result,encoding='utf-8',newline='\n')
    print(json.dumps(dict(kind=args.kind,source_lf_sha256=hashlib.sha256(original.encode()).hexdigest(),output_lf_sha256=hashlib.sha256(result.encode()).hexdigest())))

if __name__=='__main__':main()
