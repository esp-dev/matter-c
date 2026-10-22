"""Generate a diagnostic dispatcher copy; never modify the input source.

Use only in an isolated laboratory checkout. Synchronous metadata logging changes
timing/stack/layout; this is not production firmware or a memory benchmark.
No packets, keys, node identities or application payloads are printed. TRACE26
records contain ephemeral session tokens, exchange/subscription IDs, counters,
MRP attempts/deadlines/results and source locations in the generated file.
Keep captures private. Input patterns are checked against the current dispatcher;
review adaptations whenever production sources change.
"""
import argparse,hashlib,json,re
from pathlib import Path

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--source',required=True,type=Path)
p.add_argument('--output',required=True,type=Path)
p.add_argument('--failures-only',action='store_true',help='Reduce timing perturbation: subscription errors/closes plus session lifecycle only')
args=p.parse_args()
if args.source.resolve()==args.output.resolve(): p.error('output must differ from input; use a laboratory source copy')
s=args.source.read_text(); original=s
def replace(a,b):
    global s
    if s.count(a)!=1: raise ValueError('Expected one dispatcher pattern: '+a)
    s=s.replace(a,b)
helpers='''#include <stdio.h>
static void trace26(Transaction* t,const char* event,unsigned line,unsigned a,unsigned b) {
 printf("TRACE26 %s ms=%llu token=%llu fabric=%u sub=%u ex=%u init=%u line=%u state=%u pending=%u notified=%u ack=%u a=%u b=%u\\n",
 event,(unsigned long long)t->owner->now,(unsigned long long)t->key.session,t->fabric_index,(unsigned)t->subscription_id,t->key.exchange_id,t->key.initiator,line,
 t->sub?matter_im_subscribe_state(t->sub):0,t->pending,t->notified,t->acknowledged,a,b);
}
static bool trace26_close(Transaction* t,unsigned line) {
 if(!t->closing) trace26(t,"CLOSE",line,0,0);
 return t->closing=true;
}
static bool trace26_retire(Connection* c,unsigned line) {
 if(c->token && !c->retiring) printf("TRACE26 RETIRE token=%llu fabric=%u line=%u\\n",(unsigned long long)c->token,c->fabric_index,line);
 return c->retiring=true;
}
'''
at=s.index('/* Stable, per-instance nodes:')
# Replace every direct assignment, including non-t aliases. Helpers inserted afterwards.
s=re.sub(r'((?:\w+->)*\w+)->closing=true',r'trace26_close(\1,__LINE__)',s)
s=re.sub(r'((?:\w+->)*\w+)->retiring=true',r'trace26_retire(\1,__LINE__)',s)
s=s.replace('c->retiring|=closed;','if(closed) trace26_retire(c,__LINE__);')
replace('    return matter_retransmission_sender_ack(((Matter_Dispatch_T)u)->tx,k,counter);', '''    Matter_Dispatch_T d=u; Transaction* t=transaction(d,k);
    Matter_Result_T result=matter_retransmission_sender_ack(d->tx,k,counter);
    if(t) trace26(t,"ACK_RX",__LINE__,counter,result);
    else printf("TRACE26 ACK_ORPHAN ms=%llu token=%llu ex=%u init=%u counter=%lu result=%u\\n",(unsigned long long)d->now,(unsigned long long)k->session,k->exchange_id,k->initiator,(unsigned long)counter,result);
    return result;''')
replace('    if(result!=MATTER_PENDING) return result==MATTER_BUSY', '    trace26(t,"TX",__LINE__,r->message.counter,(r->attempt<<16)|result);\n    if(result!=MATTER_PENDING) return result==MATTER_BUSY')
replace('    t->notified=true; t->acknowledged=', '    trace26(t,"MRP_END",__LINE__,result->message.counter,(result->attempts<<16)|result->outcome);\n    t->notified=true; t->acknowledged=')
replace('    count_sent(d,d->sending_message,d->outcome);', '    if(d->sending_message) trace26(d->sending_message,"TX_DONE",__LINE__,(unsigned)d->producer,d->outcome);\n    count_sent(d,d->sending_message,d->outcome);')
replace('        t->sub_established=true;', '        trace26(t,"ESTABLISHED",__LINE__,0,0); t->sub_established=true;')
replace('    if(r!=MATTER_OK) trace26_close(t,__LINE__);\n}\nstatic void confirm', '    trace26(t,"RX",__LINE__,in->message_counter,(in->header.opcode<<16)|r);\n    if(r!=MATTER_OK) trace26_close(t,__LINE__);\n}\nstatic void confirm')
replace('static void dispose(Transaction* t) {', 'static void dispose(Transaction* t) {\n    trace26(t,"DISPOSE",__LINE__,0,0);')
replace('    if(r!=MATTER_OK && r!=MATTER_PENDING && r!=MATTER_WOULD_BLOCK) { trace26_close(t,__LINE__); return; }', '    if(r!=MATTER_OK && r!=MATTER_PENDING && r!=MATTER_WOULD_BLOCK) { trace26(t,"PROCESS_FAIL",__LINE__,r,0); trace26_close(t,__LINE__); return; }')
replace('    t->pending=true; t->sent=false; t->final=out.opcode==0x40;', '    trace26(t,"QUEUED",__LINE__,counter,out.opcode);\n    t->pending=true; t->sent=false; t->final=out.opcode==0x40;')
replace('    c->reserved=false; t->slot=NULL; return true;', '''    Matter_Secure_Info_T info; (void)matter_secure_info(c->secure,&info);
    printf("TRACE26 SESSION ms=%llu token=%llu fabric=%u local=%u peer=%u\\n",(unsigned long long)d->now,(unsigned long long)c->token,c->fabric_index,info.local_session_id,info.peer_session_id);
    c->reserved=false; t->slot=NULL; return true;''')
replace('                    (void)matter_secure_channel_receive(c->channel,d->rx,&packet,now,now);', '''                    Matter_Result_T received=matter_secure_channel_receive(c->channel,d->rx,&packet,now,now);
                    printf("TRACE26 UDP_RX ms=%llu token=%llu counter=%lu result=%u\\n",(unsigned long long)now,(unsigned long long)c->token,(unsigned long)header.message_counter,received);''')
replace('    trace26(t,"TX",__LINE__,r->message.counter,(r->attempt<<16)|result);', '    trace26(t,"TX",__LINE__,r->message.counter,(r->attempt<<16)|result);\n    printf("TRACE26 TIMER ms=%llu token=%llu ex=%u counter=%lu attempt=%u deadline=%llu result=%u\\n",(unsigned long long)d->now,(unsigned long long)t->key.session,t->key.exchange_id,(unsigned long)r->message.counter,r->attempt,(unsigned long long)r->deadline_ms,result);')
replace('    count_sent(d,d->sending_message,d->outcome);', '    if(d->ack_token) printf("TRACE26 ACK_DONE ms=%llu token=%llu result=%u\\n",(unsigned long long)d->now,(unsigned long long)d->ack_token,d->outcome);\n    count_sent(d,d->sending_message,d->outcome);')
s=s[:at]+helpers+s[at:]
if args.failures_only:
    s=s.replace('static void trace26(Transaction* t,const char* event,unsigned line,unsigned a,unsigned b) {',
        '''static void trace26(Transaction* t,const char* event,unsigned line,unsigned a,unsigned b) {
 if(!t->sub) return;
 if(strcmp(event,"CLOSE") && strcmp(event,"PROCESS_FAIL") &&
    (strcmp(event,"MRP_END") || (b&65535)==MATTER_RETRANSMISSION_ACKNOWLEDGED) &&
    (strcmp(event,"TX") || (b&65535)==MATTER_PENDING) &&
    (strcmp(event,"RX") || (b&65535)==MATTER_OK)) return;''')
    for event in ('TIMER','ACK_DONE','UDP_RX','ACK_ORPHAN'):
        s=s.replace('printf("TRACE26 '+event+' ', 'if(0) printf("TRACE26 '+event+' ')

args.output.parent.mkdir(parents=True,exist_ok=True)
args.output.write_bytes(s.encode('utf-8'))
print(json.dumps({'source_sha256':hashlib.sha256(original.encode()).hexdigest(),
    'trace_sha256':hashlib.sha256(s.encode()).hexdigest()}))
