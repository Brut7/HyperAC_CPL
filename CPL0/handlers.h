#ifndef H_HANDLERS
#define H_HANDLERS

#include <ntifs.h>

NTSTATUS IOCTL_GetHWID(_Inout_ PVOID Buffer, _Out_ SIZE_T* pSize);
NTSTATUS IOCTL_GetReportsSize(_Inout_ PVOID Buffer, _Out_ SIZE_T* pSize);
NTSTATUS IOCTL_GetReports(_Inout_ PVOID Buffer, _Out_ SIZE_T* pSize);

#pragma alloc_text(PAGE, IOCTL_GetHWID)
#pragma alloc_text(PAGE, IOCTL_GetReportsSize)
#pragma alloc_text(PAGE, IOCTL_GetReports)

#endif // H_HANDLERS