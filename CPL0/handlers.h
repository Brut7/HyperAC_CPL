#ifndef H_HANDLERS
#define H_HANDLERS

#include <ntifs.h>

NTSTATUS IOCTL_GetHWID(_Inout_ PVOID Buffer, _Out_ SIZE_T* pSize);

#pragma alloc_text(PAGE, IOCTL_GetHWID)

#endif // H_HANDLERS