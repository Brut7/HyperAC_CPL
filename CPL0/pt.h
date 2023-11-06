#ifndef H_PT
#define H_PT

#include <ntifs.h>
#include "ia32.h"

#define PAGE_EXECUTABLE (1 << 0)
#define PAGE_READABLE (1 << 1)
#define PAGE_WRITABLE (1 << 2)
#define PAGE_SUPERIVSOR (1 << 3)

ULONG GetPTEFlags(_In_ PTE_64 pte);
ULONG GetPDEFlags(_In_ PDE_64 pde);
ULONG GetPDPTEFlags(_In_ PDPTE_64 pdpte);

VOID OnEachPDE(_In_ PDE_64 pde, _In_ VOID(*OnEachPage)(ULONG64, ULONG, PVOID), _In_opt_ PVOID Context);
VOID OnEachPDPTE(_In_ PDPTE_64 pdpte, _In_ VOID(*OnEachPage)(ULONG64, ULONG, PVOID), _In_opt_ PVOID Context);
VOID OnEachPML4E(_In_ PML4E_64 pml4e, _In_ VOID(*OnEachPage)(ULONG64, ULONG, PVOID), _In_opt_ PVOID Context);
VOID WalkPageTables(_In_ CR3 cr3, _In_ VOID(*OnEachPage)(ULONG64, ULONG, PVOID), _In_opt_ PVOID Context);

#pragma alloc_text(PAGE, GetPTEFlags)
#pragma alloc_text(PAGE, GetPDEFlags)
#pragma alloc_text(PAGE, GetPDPTEFlags)

#pragma alloc_text(PAGE, OnEachPDE)
#pragma alloc_text(PAGE, OnEachPDPTE)
#pragma alloc_text(PAGE, OnEachPML4E)
#pragma alloc_text(PAGE, WalkPageTables)

#endif