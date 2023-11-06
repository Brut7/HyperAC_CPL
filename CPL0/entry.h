#ifndef H_ENTRY
#define H_ENTRY

#include <ntifs.h>

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);

#pragma alloc_text(PAGE, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)

#endif // H_ENTRY