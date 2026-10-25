#ifndef MATTER_BTP_H_INCLUDED
#define MATTER_BTP_H_INCLUDED 1
#include "../matter.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Core 4.19, peripheral BTP v4. One owner, no callbacks/tasks. Allocated only
 * for a physical BLE connection. MTU is the negotiated ATT MTU, including its
 * 3-byte header. Messages retain the existing 1232-byte transport ceiling.
 * Reassembly allocates the announced bounded length; OOM terminates the link.
 * All errors except BUSY/WOULD_BLOCK/INVALID_ARGUMENT from send are terminal:
 * disconnect the physical link and destroy the engine, never skip a frame. */
typedef struct Matter_Btp* Matter_Btp_T;
Matter_Btp_T matter_btp_new(uint16_t att_mtu,uint64_t now);
void matter_btp_delete(Matter_Btp_T);
Matter_Result_T matter_btp_receive(Matter_Btp_T,const uint8_t*,size_t,uint64_t now);
/* Whole RX is borrowed until release. Do not receive the next data fragment
 * while a complete message is retained. ACK-only packets remain admissible. */
Matter_Result_T matter_btp_received(Matter_Btp_T,const uint8_t**,size_t*);
void matter_btp_received_release(Matter_Btp_T);
/* TX borrows immutable message bytes until take completes or delete. One TX.
 * Completion requires BTP acknowledgment of the final data fragment. */
Matter_Result_T matter_btp_send(Matter_Btp_T,const uint8_t*,size_t);
Matter_Result_T matter_btp_send_take(Matter_Btp_T);
/* output borrows a stable proposal. sent commits it only after GATT accepted
 * its copied indication; rejection may retry the same proposal. The adapter
 * separately waits for ATT confirmation before submitting another indication
 * or publishing message completion. ACK may arrive before ATT confirmation. */
Matter_Result_T matter_btp_output(Matter_Btp_T,const uint8_t**,size_t*,uint64_t now);
Matter_Result_T matter_btp_sent(Matter_Btp_T,uint64_t now);
Matter_Result_T matter_btp_process(Matter_Btp_T,uint64_t now);
bool matter_btp_ready(Matter_Btp_T);
#endif
