#ifndef MATTER_IM_PATHS_INTERNAL_H
#define MATTER_IM_PATHS_INTERNAL_H 1
#include "matter_im_read.h"

#define MATTER_IM_GLOBAL_ATTRIBUTE_FIRST UINT32_C(0x0000f000)
#define MATTER_IM_GLOBAL_ATTRIBUTE_LAST UINT32_C(0x0000fffe)

/* Core 1.6.1 8.9.2.6 applies to both Read and Subscribe. A concrete
 * attribute with a wildcard cluster must be global. Section 7.21.2.2
 * requires a Standard (zero) prefix, not just a global-looking MEI suffix.
 * This checks path grammar, not whether the model implements the ID. */
static inline bool matter_im_read_path_valid(const Matter_Im_Selector_T* q) {
    return !(q->present & MATTER_IM_ATTRIBUTE) || (q->present & MATTER_IM_CLUSTER) ||
        (q->path.attribute >= MATTER_IM_GLOBAL_ATTRIBUTE_FIRST &&
         q->path.attribute <= MATTER_IM_GLOBAL_ATTRIBUTE_LAST);
}
#endif
