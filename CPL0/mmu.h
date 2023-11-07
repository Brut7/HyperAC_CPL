#ifndef H_MMU
#define H_MMU

#include <ntifs.h>
#include <ntddk.h>

PVOID MMU_Alloc(_In_ SIZE_T Size);
VOID MMU_Free(_In_ PVOID Pool);

#pragma alloc_text(PAGE, MMU_Alloc)
#pragma alloc_text(PAGE, MMU_Free)

#endif // H_MMU