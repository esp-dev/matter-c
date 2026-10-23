/* Include the real dispatcher; hooks exist only in runtime-wire-host. */
#include <stdbool.h>
#include <stdio.h>
#include "wire_faults.h"
#include "codec/matter_message_header.h"
#define matter_retransmission_sender_ack wire_sender_ack
#define matter_retransmission_sender_new wire_sender_new
#define matter_dispatch_process wire_inner_process
#include "../../../main/apps/matter/runtime/matter_dispatch.c"
#undef matter_retransmission_sender_ack
#undef matter_retransmission_sender_new
#undef matter_dispatch_process
Matter_Result_T matter_retransmission_sender_ack(Matter_Retransmission_Sender_T,
    const Matter_Exchange_Info_T*,uint32_t);
Matter_Retransmission_Sender_T matter_retransmission_sender_new(uint8_t,const Matter_Retransmission_Port_T*);
static unsigned fault,dropped;
static uint8_t primary_fabric;
static Matter_Exchange_Info_T target;
static uint32_t target_counter;
static Matter_Dispatch_T active;
void wire_ack_fault(unsigned mode) {
    fault=mode; dropped=0; primary_fabric=0; target_counter=0; memset(&target,0,sizeof(target));
    wire_stats.target_outcome=wire_stats.target_attempts=0;
}
static bool target_key(const Matter_Exchange_Info_T* key,uint32_t counter) {
    return target.session && counter==target_counter && target.session==key->session && target.exchange_id==key->exchange_id;
}
static void wire_finished(void* user,const Matter_Retransmission_Result_T* result) {
    if(target_key(&result->message.exchange,result->message.counter) && result->message.exchange.initiator==target.initiator) {
        wire_stats.target_outcome=(unsigned)result->outcome; wire_stats.target_attempts=result->attempts;
        printf("WIRE_TARGET_END outcome=%u attempts=%u\n",wire_stats.target_outcome,wire_stats.target_attempts);
    }
    finished(user,result);
}
Matter_Retransmission_Sender_T wire_sender_new(uint8_t attempts,const Matter_Retransmission_Port_T* port) {
    Matter_Retransmission_Port_T copy=*port; copy.finished=wire_finished;
    return matter_retransmission_sender_new(attempts,&copy);
}
Matter_Result_T wire_sender_ack(Matter_Retransmission_Sender_T sender,const Matter_Exchange_Info_T* key,uint32_t counter) {
    Transaction* t=active?transaction(active,key):NULL; Matter_Message_Header_T header; size_t size;
    if(t && t->packet && matter_message_header_read(t->packet,t->size,&header,&size)==MATTER_MESSAGE_OK && header.message_counter==counter) {
        if(active->sending_message==t && active->request && wire_completion_pending) ++wire_stats.ack_before_completion;
        else ++wire_stats.ack_after_completion;
    }
    if(target_key(key,counter)) {
        if(target.initiator!=key->initiator) ++wire_stats.wrong_role_acks;
        else if(fault && (fault==1 || !dropped)) {
            ++dropped; ++wire_stats.ack_dropped; return MATTER_OK;
        }
    }
    return matter_retransmission_sender_ack(sender,key,counter);
}
Matter_Result_T matter_dispatch_process(Matter_Dispatch_T d,uint64_t now) {
    if(!d) return wire_inner_process(d,now);
    for(Transaction* t=d->transactions;t;t=t->next) {
        Matter_Message_Header_T header; size_t size;
        if(!primary_fabric && !t->closing && t->sub_response && t->sub) primary_fabric=t->fabric_index;
        if(fault && !target.session && !t->closing && t->sub_response && t->sub && t->fabric_index!=primary_fabric &&
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
