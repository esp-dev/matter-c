/* Internal factory boundary. Only completed handshake modules may use this.
 * No public raw-key/session cloning API. Callback atomically consumes a handoff
 * AFTER all fallible allocation/RNG work; success must provide authenticated IDs.
 */
#include "matter_secure.h"
Matter_Secure_T matter_secure_from_case(const Matter_Crypto_Port_T*,void*,
    Matter_Result_T (*take)(void*,Matter_Pase_Keys_T*,Matter_Secure_Identity_T*),uint64_t);
