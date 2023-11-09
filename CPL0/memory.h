#ifndef H_MEMORY
#define H_MEMORY

#include <ntifs.h>
#include "ia32.h"

NTSTATUS SafeVirtualCopy(_Out_ PVOID Dst, _In_ CONST PVOID Src, _In_ SIZE_T Size);
NTSTATUS SafePhysicalCopy(_Out_ PVOID Dst, _In_ CONST PVOID Src, _In_ SIZE_T Size);
ULONG64 FindSignature(_In_ UCHAR* Data, _In_ SIZE_T Size, _In_ CONST CHAR* Pattern, _In_ CONST CHAR* Mask);
ULONG64 ToVirtual(_In_ LONG64 PhysicalAddress);
LONG64 ToPhysical(_In_ ULONG64 VirtualAddress);

#pragma alloc_text(PAGE, SafeVirtualCopy)
#pragma alloc_text(PAGE, SafePhysicalCopy)
#pragma alloc_text(PAGE, FindSignature)
#pragma alloc_text(PAGE, ToVirtual)
#pragma alloc_text(PAGE, ToPhysical)

#endif