/* SPDX-License-Identifier: Apache-2.0 */
#ifndef MATTER_HOST_IDENTITY_H
#define MATTER_HOST_IDENTITY_H

/* Host-only build settings. Applications using the library supply their own
 * Matter_Root_Config_T through the existing runtime API. Values are UTF-8. */
#ifndef MATTER_HOST_VENDOR_NAME
#define MATTER_HOST_VENDOR_NAME "Matter C"
#endif
#ifndef MATTER_HOST_PRODUCT_NAME
#define MATTER_HOST_PRODUCT_NAME "Matter C host simulation"
#endif

/* Basic Information limits are bytes, excluding the terminating NUL. */
typedef char Matter_Host_Vendor_Name_Length[
    sizeof(MATTER_HOST_VENDOR_NAME)>1 && sizeof(MATTER_HOST_VENDOR_NAME)<=33 ? 1 : -1];
typedef char Matter_Host_Product_Name_Length[
    sizeof(MATTER_HOST_PRODUCT_NAME)>1 && sizeof(MATTER_HOST_PRODUCT_NAME)<=33 ? 1 : -1];
#endif
