#ifndef MATTER_LIGHT_INTERNAL_H_INCLUDED
#define MATTER_LIGHT_INTERNAL_H_INCLUDED 1
#include "matter_light.h"
/* Borrow registration used by the Groups/Scenes composition. The owner
 * releases only after its root pins and all callbacks are gone. */
Matter_Result_T matter_light_pin(Matter_Light_T);
Matter_Result_T matter_light_unpin(Matter_Light_T);
typedef struct {
    void* user;
    uint8_t (*save)(void*,uint8_t,const Matter_Light_State_T* snapshot,const Matter_Light_State_T* next);
    uint8_t (*load)(void*,uint8_t,Matter_Light_State_T* inout,bool* found);
    void (*recalled)(void*,uint8_t);
} Matter_Light_Scenes_Port;
Matter_Result_T matter_light_bind_scenes(Matter_Light_T,const Matter_Light_Scenes_Port*);
/* Color-space conversion shared by live state, scene capture/recall and pixels.
 * No allocation. XY is 16-bit fixed point; HS uses the specification's 254
 * scale. Scene recall preserves the exact stored XY instead of round-tripping
 * it a second time through quantized eight-bit hue. */
void matter_light_color_rgb(const Matter_Light_State_T*,double rgb[3]);
void matter_light_color_normalize(Matter_Light_State_T*);
void matter_light_color_hue_from_xy(Matter_Light_State_T*);
#endif
