/* Include the real dispatcher; hooks exist only in runtime-wire-host. */
#include <stdbool.h>
#include <stdio.h>
#include "wire_faults.h"
#include "codec/matter_message_header.h"
#define matter_retransmission_sender_ack wire_sender_ack
#define matter_dispatch_process wire_inner_process
#include "../../../main/apps/matter/runtime/matter_dispatch.c"
#undef matter_retransmission_sender_ack
#undef matter_dispatch_process
Matter_Result_T matter_retransmission_sender_ack(Matter_Retransmission_Sender_T,
    const Matter_Exchange_Info_T*,uint32_t);
static bool fault;
static Matter_Exchange_Info_T target;
static uint32_t target_counter;
static Matter_Dispatch_T active;
void wire_ack_fault(bool enabled) { fault=enabled; target_counter=0; memset(&target,0,sizeof(target)); }
Matter_Result_T wire_sender_ack(Matter_Retransmission_Sender_T sender,const Matter_Exchange_Info_T* key,uint32_t counter) {
    Transaction* t=active?transaction(active,key):NULL; Matter_Message_Header_T header; size_t size;
    if(t && t->packet && matter_message_header_read(t->packet,t->size,&header,&size)==MATTER_MESSAGE_OK && header.message_counter==counter) {
        if(active->sending_message==t && active->request && wire_completion_pending) ++wire_stats.ack_before_completion;
        else ++wire_stats.ack_after_completion;
    }
    if(fault && target.session && counter==target_counter && target.session==key->session && target.exchange_id==key->exchange_id && target.initiator==key->initiator) {
        ++wire_stats.ack_dropped; return MATTER_OK;
    }
    return matter_retransmission_sender_ack(sender,key,counter);
}
Matter_Result_T matter_dispatch_process(Matter_Dispatch_T d,uint64_t now) {
    if(!d) return wire_inner_process(d,now);
    for(Transaction* t=d->transactions;t;t=t->next) {
        Matter_Message_Header_T header; size_t size;
        if(fault && !target.session && !t->closing && t->sub_response && t->sub && t->fabric_index==2 &&
            t->packet && matter_message_header_read(t->packet,t->size,&header,&size)==MATTER_MESSAGE_OK) {
            target=t->key;
            target_counter=header.message_counter;
            printf("WIRE_ACK_TARGET session=%llu exchange=%u subscription=%u counter=%u\n",
                (unsigned long long)t->key.session,t->key.exchange_id,t->subscription_id,target_counter);
        }
        if(fault && t->key.session==target.session && t->key.exchange_id==target.exchange_id &&
            t->key.initiator==target.initiator && t->notified && !t->acknowledged) {
            ++wire_stats.unacknowledged;
            printf("WIRE_UNACKNOWLEDGED session=%llu subscription=%u\n",
                (unsigned long long)t->key.session,t->subscription_id);
        }
    }
    active=d; Matter_Result_T result=wire_inner_process(d,now); active=NULL; return result;
}
