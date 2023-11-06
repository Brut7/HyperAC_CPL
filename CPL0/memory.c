#include "memory.h"
#include "ia32.h"
#include "common.h"
#include "config.h"
#include "mmu.h"
#include <intrin.h>

ULONG64 GetVirtualAddress(_In_ LONG64 Address)
{
	return MmGetVirtualForPhysical(*(PHYSICAL_ADDRESS*)&Address);
}

BOOLEAN IsValidAddress(_In_ ULONG64 Address)
{
	return MmIsAddressValid((PVOID)Address);
}

VOID OnEachPDE(_In_ PDE_64 pde, _In_ VOID(*OnEachPage)(ULONG64, SIZE_T, PVOID), _In_opt_ PVOID Context)
{
	PTE_64* ptes = NULL;
	PTE_64 pte = { 0 };

	ptes = (PTE_64*)GetVirtualAddress(pde.PageFrameNumber << PAGE_SHIFT);
	if (!IsValidAddress(ptes))
	{
		return 0;
	}

	for (USHORT i = 0; i < TABLE_SIZE; ++i)
	{
		pte = ptes[i];
		if (!pte.Present)
		{
			continue;
		}

		ULONG64 PageStart = GetVirtualAddress(pte.PageFrameNumber << PAGE_SHIFT);
		if (!IsValidAddress(PageStart))
		{
			continue;
		}

		OnEachPage(PageStart, PAGE_SIZE, Context);
	}
}

VOID OnEachPDPTE(_In_ PDPTE_64 pdpte, _In_ VOID(*OnEachPage)(ULONG64, SIZE_T, PVOID), _In_opt_ PVOID Context)
{
	PDE_64* pdes = NULL;
	PDE_64 pde = { 0 };

	pdes = (PDPTE_64*)GetVirtualAddress(pdpte.PageFrameNumber << PAGE_SHIFT);
	if (!IsValidAddress(pdes))
	{
		return 0;
	}

	for (USHORT i = 0; i < TABLE_SIZE; ++i)
	{
		pde = pdes[i];
		if (!pdpte.Present)
		{
			continue;
		}

		if (pde.LargePage)
		{
			ULONG64 PageStart = GetVirtualAddress(pde.PageFrameNumber << PAGE_SHIFT);
			if (!IsValidAddress(PageStart))
			{
				continue;
			}

			OnEachPage(PageStart, PAGE_SIZE * TABLE_SIZE, Context);
			continue;
		}

		OnEachPDE(pde, OnEachPage, Context);
	}
}

VOID OnEachPML4E(_In_ PML4E_64 pml4e, _In_ VOID(*OnEachPage)(ULONG64, SIZE_T, PVOID), _In_opt_ PVOID Context)
{
	PDPTE_64* pdptes = NULL;
	PDPTE_64 pdpte = { 0 };

	pdptes = (PDPTE_64*)GetVirtualAddress(pml4e.PageFrameNumber << PAGE_SHIFT);
	if (!IsValidAddress(pdptes))
	{
		return 0;
	}

	for (USHORT i = 0; i < TABLE_SIZE; ++i)
	{
		pdpte = pdptes[i];
		if (!pdpte.Present)
		{
			continue;
		}

		if (pdpte.LargePage)
		{
			ULONG64 PageStart = GetVirtualAddress(pdpte.PageFrameNumber << PAGE_SHIFT);
			if (!IsValidAddress(PageStart))
			{
				continue;
			}

			OnEachPage(PageStart, PAGE_SIZE * TABLE_SIZE * TABLE_SIZE, Context);
			continue;
		}

		OnEachPDPTE(pdpte, OnEachPage, Context);
	}
}

VOID WalkPageTables(_In_ CR3 cr3, _In_ VOID (*OnEachPage)(ULONG64, SIZE_T, PVOID), _In_opt_ PVOID Context)
{
	PML4E_64* pml4es = NULL;
	PML4E_64 pml4e = { 0 };

	pml4es = (PML4E_64*)GetVirtualAddress(cr3.AddressOfPageDirectory << PAGE_SHIFT);
	if (!IsValidAddress(pml4es))
	{
		return 0;
	}

	for (USHORT i = 0; i < TABLE_SIZE; ++i)
	{
		pml4e = pml4es[i];
		if (!pml4e.Present)
		{
			continue;
		}

		OnEachPML4E(pml4e, OnEachPage, Context);
	}
}