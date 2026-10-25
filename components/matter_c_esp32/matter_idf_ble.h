#ifndef MATTER_IDF_BLE_H_INCLUDED
#define MATTER_IDF_BLE_H_INCLUDED 1
#include "matter_udp.h"
typedef struct Matter_Idf_Ble* Matter_Idf_Ble_T;
/* One physical NimBLE host per ESP controller. The engine, reassembly, GATT
 * queue, host and controller are demand-owned by the commissioning phase.
 * No SDK callback enters Matter; process marshals events onto its owner.
 * Existing accepted sends survive window closure until BTP/ATT confirmation.
 * No SMP pairing/bonds: Matter PASE authenticates and encrypts commissioning. */
Matter_Idf_Ble_T matter_idf_ble_new(Matter_T,uint16_t vendor,uint16_t product,const Matter_Udp_Listener_T*);
Matter_Udp_T matter_idf_ble_module(Matter_Idf_Ble_T);
void matter_idf_ble_window(Matter_Idf_Ble_T,bool enabled,uint16_t discriminator);
void matter_idf_ble_receive_enabled(Matter_Idf_Ble_T,bool);
Matter_Result_T matter_idf_ble_process(Matter_Idf_Ble_T,uint64_t now);
/* Owner must deliver this barrier to runtime before another link's RX. */
uint32_t matter_idf_ble_closed_take(Matter_Idf_Ble_T);
Matter_Result_T matter_idf_ble_delete(Matter_Idf_Ble_T);
#endif
