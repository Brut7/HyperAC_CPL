#ifndef H_MEMORY
#define H_MEMORY

#include <ntifs.h>
#include "ia32.h"

NTSTATUS SafeCopy(_Out_ PVOID Dst, _In_ CONST PVOID Src, _In_ SIZE_T Size);
ULONG64 FindSignature(_In_ UCHAR* Data, _In_ SIZE_T Size, _In_ CONST CHAR* Pattern, _In_ CONST CHAR* Mask);
NTSTATUS FindBacker(_In_ ULONG64 Address, _Out_opt_ CHAR* ModuleName);

#pragma alloc_text(PAGE, SafeCopy)

#endif