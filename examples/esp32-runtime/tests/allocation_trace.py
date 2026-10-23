"""Generate an owner-thread allocation-site observer in an isolated lab copy.

Tracks 2048 live allocations and 128 call sites, with explicit overflow counts.
Metadata is static and changes RAM/layout/timing: use a separate normal image
for headline heap measurements. No allocation, formatting or payload inspection
inside the allocation hooks. Public allocator semantics/OOM ordinals are retained.
Call matter_alloc_audit_dump on the owner at selected phase boundaries.
"""
import argparse
import hashlib
import json
from pathlib import Path


def generate(source):
    def replace(a, b):
        nonlocal source
        if source.count(a) != 1:
            raise ValueError('Expected one allocator pattern: ' + a)
        source = source.replace(a, b)

    replace('static size_t fail_at;', '''#include <stdio.h>
static size_t fail_at;
enum { AUDIT_LIVE=2048, AUDIT_SITES=128 };
/* Eight bytes/record on C6. A block above65535 bytes is explicitly untracked
 * and invalidates attribution through overflows; allocation itself is intact. */
typedef struct { void* pointer; uint16_t site,size; } Audit_Live;
typedef struct { uintptr_t caller; size_t size,count,peak_size,peak_count; } Audit_Site;
static Audit_Live audit[AUDIT_LIVE];
static Audit_Site sites[AUDIT_SITES];
static unsigned overflows,site_count;
static size_t peak_live;
void matter_alloc_audit_dump(const char* phase) {
    printf("ALLOC_AUDIT %s live%u bytes%u peak%u overflows%u metadata%u peaklive%u sites%u\\n",phase,
        (unsigned)memory.live,(unsigned)memory.live_bytes,(unsigned)memory.peak_bytes,overflows,
        (unsigned)(sizeof(audit)+sizeof(sites)+sizeof(overflows)+sizeof(site_count)+sizeof(peak_live)),(unsigned)peak_live,site_count);
    for(unsigned j=0;j<site_count;++j) {
        if(sites[j].count) printf("ALLOC_SITE live %08lx %u %u\\n",(unsigned long)sites[j].caller,(unsigned)sites[j].size,(unsigned)sites[j].count);
        if(sites[j].peak_count) printf("ALLOC_SITE peak %08lx %u %u\\n",(unsigned long)sites[j].caller,(unsigned)sites[j].peak_size,(unsigned)sites[j].peak_count);
    }
}''')
    replace('    ++memory.live; memory.live_bytes+=heap_caps_get_allocated_size(result);', '''    uintptr_t caller=(uintptr_t)__builtin_return_address(0);
    size_t bytes=heap_caps_get_allocated_size(result);
    unsigned i,j; for(i=0;i<AUDIT_LIVE;++i) if(!audit[i].pointer) break;
    for(j=0;j<site_count;++j) if(sites[j].caller==caller) break;
    if(i==AUDIT_LIVE || j==AUDIT_SITES || bytes>UINT16_MAX) ++overflows;
    else {
        if(j==site_count) { sites[j].caller=caller; ++site_count; }
        audit[i]=(Audit_Live){result,(uint16_t)j,(uint16_t)bytes};
        sites[j].size+=bytes; ++sites[j].count;
    }
    ++memory.live; memory.live_bytes+=bytes;
    if(memory.live>peak_live) peak_live=memory.live;''')
    replace('    if(memory.live_bytes>memory.peak_bytes) memory.peak_bytes=memory.live_bytes;', '''    if(memory.live_bytes>memory.peak_bytes) {
        memory.peak_bytes=memory.live_bytes;
        for(unsigned j=0;j<site_count;++j) { sites[j].peak_size=sites[j].size; sites[j].peak_count=sites[j].count; }
    }''')
    replace('    if(pointer) { --memory.live;', '''    if(pointer) {
        unsigned i; for(i=0;i<AUDIT_LIVE;++i) if(audit[i].pointer==pointer) break;
        if(i<AUDIT_LIVE) {
            sites[audit[i].site].size-=audit[i].size; --sites[audit[i].site].count; audit[i].pointer=NULL;
        } else ++overflows;
        --memory.live;''')
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.source.resolve() == args.output.resolve():
        parser.error('output must differ from input; use an isolated source copy')
    original = args.source.read_text(encoding='utf-8')
    result = generate(original)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('w', encoding='utf-8', newline='\n') as output:
        output.write(result)
    print(json.dumps(dict(source_lf_sha256=hashlib.sha256(original.encode()).hexdigest(),
                         output_lf_sha256=hashlib.sha256(result.encode()).hexdigest(),
                         live_records=2048,site_records=128,max_tracked_block_bytes=65535)))


if __name__ == '__main__':
    main()
