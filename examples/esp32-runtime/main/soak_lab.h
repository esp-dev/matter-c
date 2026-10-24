#ifndef MATTER_LAB_SOAK_H
#define MATTER_LAB_SOAK_H 1
#include "wifi_port.h"
typedef struct Matter_Lab_Soak* Matter_Lab_Soak_T;
/* Application-installed SDK hook. Uses only process-lifetime atomic counters;
 * no allocation, logging or observer pointer, including after observer delete. */
void matter_lab_soak_heap_failed(size_t,uint32_t,const char*);
/* Optional laboratory observer; all calls run on the application owner.
 * Runtime/radio outlive deletion; a held completion MUST drain before delete. */
Matter_Lab_Soak_T matter_lab_soak_new(void);
bool matter_lab_soak_received(Matter_Lab_Soak_T);
bool matter_lab_soak_sent(Matter_Lab_Soak_T,uint64_t,Matter_Operation_Result_T);
void matter_lab_soak_process(Matter_Lab_Soak_T,Matter_Runtime_T);
bool matter_lab_soak_control(Matter_Lab_Soak_T,char,Lab_Wifi_T,Matter_Runtime_T);
Matter_Result_T matter_lab_soak_delete(Matter_Lab_Soak_T);
#endif
