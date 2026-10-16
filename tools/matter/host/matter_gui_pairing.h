#ifndef MATTER_GUI_PAIRING_H
#define MATTER_GUI_PAIRING_H 1
#include <stdbool.h>
#include <stdint.h>
#define MATTER_GUI_QR_TEXT_BYTES 23
bool matter_gui_pin_valid(uint32_t pin);
/* Standard flow, on-network only, no optional TLV. Core 5.1.3. */
bool matter_gui_pairing(uint32_t pin,uint16_t discriminator,uint16_t vendor,uint16_t product,
    char out[MATTER_GUI_QR_TEXT_BYTES]);
#endif
