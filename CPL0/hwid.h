#ifndef H_HWID
#define H_HWID

#include <ntifs.h>
#include "sha256.h"

NTSTATUS HWID_GetBootUUID(_Out_ UCHAR Hash[32]);
NTSTATUS HWID_GetMonitorEDID(_Out_ UCHAR Hash[32]);

#pragma alloc_text(PAGE, HWID_GetBootUUID)
#pragma alloc_text(PAGE, HWID_GetMonitorEDID)

#endif