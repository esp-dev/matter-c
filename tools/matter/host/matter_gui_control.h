/* Application-local pipe protocol; never exposed on a network socket. */
#ifndef MATTER_GUI_CONTROL_H
#define MATTER_GUI_CONTROL_H 1
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#define MATTER_GUI_POWER_LIMIT_MW INT64_C(10000000)
#define MATTER_GUI_COMMAND_BYTES 64
typedef struct {
    char line[MATTER_GUI_COMMAND_BYTES]; size_t used;
    bool dropping,stop; int64_t power_mw; uint64_t generation;
    bool allow_ota_query; uint64_t query_generation;
} Matter_Gui_Control_T;
/* Nonblocking, bounded work on the owner's thread. EOF requests clean stop.
 * An invalid/oversize line changes neither power nor generation. */
bool matter_gui_control_poll(Matter_Gui_Control_T*);
#endif
