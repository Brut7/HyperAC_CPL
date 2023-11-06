#ifndef H_MEMORY
#define H_MEMORY

#include <ntifs.h>
#include "ia32.h"

ULONG64 GetVirtualAddress(_In_ LONG64 Address);
BOOLEAN IsValidAddress(_In_ ULONG64 Address);

VOID OnEachPDE(_In_ PDE_64 pde, _In_ VOID(*OnEachPage)(ULONG64, SIZE_T, PVOID), _In_opt_ PVOID Context);
VOID OnEachPDPTE(_In_ PDPTE_64 pdpte, _In_ VOID(*OnEachPage)(ULONG64, SIZE_T, PVOID), _In_opt_ PVOID Context);
VOID OnEachPML4E(_In_ PML4E_64 pml4e, _In_ VOID(*OnEachPage)(ULONG64, SIZE_T, PVOID), _In_opt_ PVOID Context);
VOID WalkPageTables(_In_ CR3 cr3, _In_ VOID(*OnEachPage)(ULONG64, SIZE_T, PVOID), _In_opt_ PVOID Context);

#endif