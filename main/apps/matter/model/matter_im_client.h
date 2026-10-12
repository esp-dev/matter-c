#ifndef MATTER_IM_CLIENT_H_INCLUDED
#define MATTER_IM_CLIENT_H_INCLUDED 1
#include "matter_im_invoke.h"
/* One untimed, unicast Invoke on an authenticated CASE exchange. Owner supplies
 * routing, deadline, MRP/deduplication and cancellation. No callbacks or OS.
 * One heap allocation, bounded 1024-byte messages. No chunked/multiple response
 * commands. Fields are copied; response body is borrowed until delete. */
typedef struct Matter_Im_Client* Matter_Im_Client_T;
/* Select commands whose successful reply is CommandStatusIB, e.g. OTA Notify.
 * Ordinary response commands still require response data for success. */
#define MATTER_IM_CLIENT_STATUS_ONLY UINT32_MAX
Matter_Im_Client_T matter_im_client_new(const Matter_Im_Command_Path_T*,uint32_t response_command,
    const uint8_t* anonymous_fields,size_t size);
Matter_Result_T matter_im_client_output(Matter_Im_Client_T,Matter_Im_Read_Message_T*);
Matter_Result_T matter_im_client_sent(Matter_Im_Client_T);
Matter_Result_T matter_im_client_receive(Matter_Im_Client_T,uint8_t opcode,const uint8_t*,size_t);
/* PENDING until response validated and any required StatusResponse submitted.
 * OK includes an IM status (success=0) and optional anonymous structure body. */
Matter_Result_T matter_im_client_result(Matter_Im_Client_T,uint8_t* status,const uint8_t** body,size_t* size);
void matter_im_client_delete(Matter_Im_Client_T);
#endif
