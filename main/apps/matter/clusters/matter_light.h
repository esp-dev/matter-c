#ifndef MATTER_LIGHT_H_INCLUDED
#define MATTER_LIGHT_H_INCLUDED 1
#include "matter_root.h"

/* Application-owned lighting state. Port load/store are serialized, atomic,
 * bounded, and never retain pointers. Store failure has no visible effects.
 * The hardware consumes pixels outside IM callbacks; no task or SDK dependency.
 * Optional enhanced hue/color loop/frequency features are not advertised. */
typedef struct {
    uint16_t x,y,temperature,start_temperature;
    uint16_t on_level,start_level,start_on;
    uint8_t level,hue,saturation,mode,options_level,options_color;
    bool on;
} Matter_Light_State_T;
typedef struct {
    void* user;
    Matter_Result_T (*load)(void*,Matter_Light_State_T*);
    Matter_Result_T (*store)(void*,const Matter_Light_State_T*);
} Matter_Light_Port_T;
typedef struct Matter_Light* Matter_Light_T;
void matter_light_defaults(Matter_Light_State_T*);
Matter_Light_T matter_light_new(const Matter_Light_Port_T*,uint32_t seed,uint64_t now,bool ota_restart);
/* Adds EP1 as Extended Color Light rev5 and its basic lighting/Identify
 * servers. Groups/Scenes/Groupcast composition must be attached separately
 * before serving; this helper alone is not complete device conformance. */
Matter_Result_T matter_light_attach(Matter_Light_T,Matter_Root_T,uint16_t endpoint);
Matter_Cluster_T matter_light_cluster(Matter_Light_T,uint32_t);
Matter_Result_T matter_light_process(Matter_Light_T,uint64_t now);
Matter_Result_T matter_light_state(Matter_Light_T,Matter_Light_State_T*);
Matter_Result_T matter_light_recall(Matter_Light_T,const Matter_Light_State_T*,uint32_t transition_ms);
bool matter_light_identifying(Matter_Light_T);
void matter_light_pixels(Matter_Light_T,uint8_t rgb[3]);
Matter_Result_T matter_light_delete(Matter_Light_T);
#endif
