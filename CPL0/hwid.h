#ifndef H_HWID
#define H_HWID

#include <ntifs.h>

NTSTATUS HWID_GetBootUUID(_Out_ UCHAR Hash[32]);
NTSTATUS HWID_GetMonitorEDID(_Out_ UCHAR Hash[32]);

#endif