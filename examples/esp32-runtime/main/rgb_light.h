#ifndef MATTER_LAB_RGB_LIGHT_H
#define MATTER_LAB_RGB_LIGHT_H 1
#include "clusters/matter_root.h"
typedef struct Matter_Lab_Rgb* Matter_Lab_Rgb_T;
/* Experimental EP1 RGB light: standard OnOff/LevelControl/ColorControl wire
 * commands, not a complete Extended Color Light device-type implementation.
 * Root borrows the three clusters; delete Root before deleting this owner.
 * Values are volatile. Hardware is application-owned and updated outside IM. */
Matter_Lab_Rgb_T matter_lab_rgb_new(uint32_t version,uint64_t now);
Matter_Result_T matter_lab_rgb_attach(Matter_Lab_Rgb_T,Matter_Root_T);
/* Application scheduler advances attached custom clusters explicitly. */
Matter_Result_T matter_lab_rgb_process(Matter_Lab_Rgb_T,uint64_t now);
Matter_Result_T matter_lab_rgb_delete(Matter_Lab_Rgb_T);
bool matter_lab_rgb_pixels(Matter_Lab_Rgb_T,uint8_t rgb[3],uint32_t* generation);
#endif
