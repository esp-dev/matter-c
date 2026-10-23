"""Generate a lab-only UDP RX drop observer in an isolated source copy.

No logging/allocation in the lwIP callback. A per-adapter 32-record FIFO keeps
only timestamp, drop reason, occupancy and the unencrypted wire header prefix.
The owner prints records after releasing the TCP/IP lock. Overflow is explicit.
This observer changes layout/timing; do not use it for headline RAM comparisons.
It never decrypts payloads or changes admission, queue growth, ACKs or limits.
"""
import argparse
import hashlib
import json
from pathlib import Path


def generate(source):
    def replace(a, b):
        nonlocal source
        if source.count(a) != 1:
            raise ValueError('Expected one UDP adapter pattern: ' + a)
        source = source.replace(a, b)

    replace('enum { RX_MAX=8 };', '''#include <stdio.h>
enum { RX_MAX=8, TRACE_RX_RECORDS=32 };
typedef struct {
    uint64_t us; uint32_t counter;
    uint16_t session,size;
    uint8_t reason,queued,slots,prefix;
} Trace_Rx;
typedef char TraceRxStackBudget[(sizeof(Trace_Rx)<=24)?1:-1];''')
    replace('    uint64_t pending,idle_until; bool busy; Matter_Idf_Udp_Stats_T stats;',
            '''    uint64_t pending,idle_until; bool busy; Matter_Idf_Udp_Stats_T stats;
    Trace_Rx trace[TRACE_RX_RECORDS]; unsigned trace_head,trace_count,trace_overflow;''')
    marker='static Matter_Result_T error(err_t e) {'
    replace(marker, '''/* Called only under the TCP/IP core lock, never formats or allocates. */
static void trace_rx_drop(Matter_Idf_Udp_T s,const struct pbuf* p,unsigned reason) {
    if(s->trace_count==TRACE_RX_RECORDS) { ++s->trace_overflow; return; }
    Trace_Rx* r=&s->trace[(s->trace_head+s->trace_count++)%TRACE_RX_RECORDS];
    *r=(Trace_Rx){.us=(uint64_t)esp_timer_get_time(),.size=p->tot_len,.reason=reason,.slots=s->count};
    for(const Rx* rx=s->head;rx;rx=rx->next) ++r->queued;
    uint8_t header[8];
    if(p->tot_len>=sizeof(header) && pbuf_copy_partial(p,header,sizeof(header),0)==sizeof(header)) {
        r->prefix=1; r->session=(uint16_t)(header[1]|((uint16_t)header[2]<<8));
        r->counter=(uint32_t)header[4]|((uint32_t)header[5]<<8)|((uint32_t)header[6]<<16)|((uint32_t)header[7]<<24);
    }
}
static void trace_rx_dump(Matter_Idf_Udp_T s) {
    for(;;) {
        Trace_Rx r; unsigned overflow;
        LOCK_TCPIP_CORE();
        if(!s->trace_count) { UNLOCK_TCPIP_CORE(); break; }
        r=s->trace[s->trace_head]; s->trace_head=(s->trace_head+1)%TRACE_RX_RECORDS; --s->trace_count;
        overflow=s->trace_overflow;
        UNLOCK_TCPIP_CORE();
        printf("RX_DROP {\\"us\\":%llu,\\"reason\\":%u,\\"queued\\":%u,\\"slots\\":%u,\\"size\\":%u,\\"prefix\\":%u,\\"wire_session\\":%u,\\"wire_counter\\":%lu,\\"overflow\\":%u}\\n",
            (unsigned long long)r.us,r.reason,r.queued,r.slots,r.size,r.prefix,r.session,(unsigned long)r.counter,overflow);
    }
}
''' + marker)
    replace('    if(!s->epoch || !IP_IS_V6(peer) || ip_current_input_netif()!=s->iface || !p->tot_len) goto drop;',
            '''    unsigned reason=0;
    if(!s->epoch) { reason=1; goto drop; }
    if(!IP_IS_V6(peer)) { reason=2; goto drop; }
    if(ip_current_input_netif()!=s->iface) { reason=3; goto drop; }
    if(!p->tot_len) { reason=4; goto drop; }''')
    replace('        ++s->stats.oversize; goto drop;', '        ++s->stats.oversize; reason=5; goto drop;')
    replace('        ++s->stats.extensions; goto drop;', '        ++s->stats.extensions; reason=6; goto drop;')
    replace('    if(!s->free) { ++s->pressure; goto drop; }',
            '    if(!s->free) { ++s->pressure; reason=7; goto drop; }')
    replace('    ++s->stats.dropped; pbuf_free(p);', '    trace_rx_drop(s,p,reason); ++s->stats.dropped; pbuf_free(p);')
    replace('    rx_capacity(s,(uint64_t)esp_timer_get_time()/1000);',
            '    trace_rx_dump(s); rx_capacity(s,(uint64_t)esp_timer_get_time()/1000);')
    return source


def generate_core(source):
    """Owner-only backpressure metadata; no wire plaintext or application data."""
    def replace(a, b):
        nonlocal source
        if source.count(a) != 1:
            raise ValueError('Expected one core RX pattern: ' + a)
        source = source.replace(a, b)

    replace('#include <string.h>', '#include <string.h>\n#include <stdio.h>')
    replace('uint32_t im_received;', 'uint32_t im_received;\n    uint32_t trace_counter; unsigned trace_result;')
    replace('\tif (rx->queued || rx->delivery == HELD_DELIVERY) return MATTER_WOULD_BLOCK;', '''\tif (rx->queued || rx->delivery == HELD_DELIVERY) {
        printf("RX_BLOCK {\\"event\\":\\"admit\\",\\"ms\\":%llu,\\"counter\\":%lu,\\"token\\":%llu,\\"held\\":%u,\\"queued\\":%u,\\"waiting_counter\\":%lu,\\"waiting_token\\":%llu,\\"waiting_ex\\":%u,\\"waiting_init\\":%u}\\n",
            (unsigned long long)received_ms,(unsigned long)input->message_counter,(unsigned long long)input->session,rx->delivery,rx->queued,
            (unsigned long)rx->input.message_counter,(unsigned long long)rx->input.session,rx->queued_key.exchange_id,rx->queued_key.initiator);
        return MATTER_WOULD_BLOCK;
    }''')
    replace('\t\tresult = receive_queued(rx);', '''\t\tresult = receive_queued(rx);
        if(result!=MATTER_OK && (rx->trace_counter!=rx->input.message_counter || rx->trace_result!=(unsigned)result)) {
            printf("RX_BLOCK {\\"event\\":\\"queue\\",\\"ms\\":%llu,\\"counter\\":%lu,\\"token\\":%llu,\\"ex\\":%u,\\"init\\":%u,\\"result\\":%u,\\"action\\":%u,\\"ack\\":%u,\\"ack_processed\\":%u,\\"ephemeral_token\\":%llu,\\"ephemeral_ex\\":%u,\\"ephemeral_init\\":%u}\\n",
                (unsigned long long)now_ms,(unsigned long)rx->input.message_counter,(unsigned long long)rx->input.session,rx->queued_key.exchange_id,rx->queued_key.initiator,
                result,rx->decision.action,rx->decision.ack,rx->ack_processed,(unsigned long long)rx->ephemeral.session,rx->ephemeral.exchange_id,rx->ephemeral.initiator);
            rx->trace_counter=rx->input.message_counter; rx->trace_result=(unsigned)result;
        } else if(result==MATTER_OK) rx->trace_result=0;''')
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--layer', choices=['udp', 'core'], default='udp')
    args = parser.parse_args()
    if args.source.resolve() == args.output.resolve():
        parser.error('output must differ from input; use an isolated source copy')
    original = args.source.read_text(encoding='utf-8')
    result = generate(original) if args.layer == 'udp' else generate_core(original)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('w', encoding='utf-8', newline='\n') as output:
        output.write(result)
    print(json.dumps(dict(source_lf_sha256=hashlib.sha256(original.encode()).hexdigest(),
                         output_lf_sha256=hashlib.sha256(result.encode()).hexdigest(),
                         reasons={'inactive':1,'not_ipv6':2,'interface':3,'empty':4,'oversize':5,'extensions':6,'no_slot':7},
                         records=32 if args.layer == 'udp' else 0,layer=args.layer)))


if __name__ == '__main__':
    main()
