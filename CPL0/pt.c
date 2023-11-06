#include "pt.h"
#include "common.h"
#include <ntddk.h>

ULONG GetPTEFlags(_In_ PTE_64 pte)
{
	PAGED_CODE();

	ULONG flags = 0;

	flags = PAGE_READABLE;
	if (!pte.ExecuteDisable)
	{
		flags |= PAGE_EXECUTABLE;
	}

	if (pte.Write)
	{
		flags |= PAGE_WRITABLE;
	}

	if (pte.Supervisor)
	{
		flags |= PAGE_SUPERIVSOR;
	}

	return flags;
}

ULONG GetPDEFlags(_In_ PDE_64 pde)
{
	PAGED_CODE();

	ULONG flags = 0;

	flags = PAGE_READABLE;
	if (!pde.ExecuteDisable)
	{
		flags |= PAGE_EXECUTABLE;
	}

	if (pde.Write)
	{
		flags |= PAGE_WRITABLE;
	}

	if (pde.Supervisor)
	{
		flags |= PAGE_SUPERIVSOR;
	}

	return flags;
}

ULONG GetPDPTEFlags(_In_ PDPTE_64 pdpte)
{
	PAGED_CODE();

	ULONG flags = 0;
	
	flags = PAGE_READABLE;
	if (!pdpte.ExecuteDisable)
	{
		flags |= PAGE_EXECUTABLE;
	}

	if (pdpte.Write)
	{
		flags |= PAGE_WRITABLE;
	}

	if (pdpte.Supervisor)
	{
		flags |= PAGE_SUPERIVSOR;
	}

	return flags;
}

VOID OnEachPDE(_In_ PDE_64 pde, _In_ VOID(*OnEachPage)(ULONG64, ULONG, PVOID), _In_opt_ PVOID Context)
{
	PAGED_CODE();

	PTE_64* ptes = NULL;
	PTE_64 pte = { 0 };
	PHYSICAL_ADDRESS phys_addr = { 0 };
	ULONG64 page_start = 0;
	
	phys_addr.QuadPart = pde.PageFrameNumber << PAGE_SHIFT;
	ptes = (PTE_64*)MmGetVirtualForPhysical(phys_addr);
	if (!MmIsAddressValid(ptes))
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

		phys_addr.QuadPart = pte.PageFrameNumber << PAGE_SHIFT;
		page_start = MmGetVirtualForPhysical(phys_addr);
		if (!MmIsAddressValid(page_start))
		{
			continue;
		}

		OnEachPage(page_start, GetPTEFlags(pte), Context);
	}
}

VOID OnEachPDPTE(_In_ PDPTE_64 pdpte, _In_ VOID(*OnEachPage)(ULONG64, ULONG, PVOID), _In_opt_ PVOID Context)
{
	PAGED_CODE();

	PDE_64* pdes = NULL;
	PDE_64 pde = { 0 };
	PHYSICAL_ADDRESS phys_addr = { 0 };
	ULONG64 page_start = 0;
	ULONG page_flags = 0;

	phys_addr.QuadPart = pdpte.PageFrameNumber << PAGE_SHIFT;
	pdes = (PDPTE_64*)MmGetVirtualForPhysical(phys_addr);
	if (!MmIsAddressValid(pdes))
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
			phys_addr.QuadPart = pdpte.PageFrameNumber << PAGE_SHIFT;
			page_start = MmGetVirtualForPhysical(phys_addr);
			if (!MmIsAddressValid(page_start))
			{
				continue;
			}

			page_flags = GetPDEFlags(pde);
			for (SIZE_T i = 0; i < TABLE_SIZE; ++i)
			{
				OnEachPage(page_start + i * PAGE_SIZE, page_flags, Context);
			}
		}
		else
		{
			OnEachPDE(pde, OnEachPage, Context);
		}

	}
}

VOID OnEachPML4E(_In_ PML4E_64 pml4e, _In_ VOID(*OnEachPage)(ULONG64, ULONG, PVOID), _In_opt_ PVOID Context)
{
	PAGED_CODE();

	PDPTE_64* pdptes = NULL;
	PDPTE_64 pdpte = { 0 };
	PHYSICAL_ADDRESS phys_addr = { 0 };
	ULONG64 page_start = 0;
	ULONG page_flags = 0;

	phys_addr.QuadPart = pml4e.PageFrameNumber << PAGE_SHIFT;
	pdptes = (PDPTE_64*)MmGetVirtualForPhysical(phys_addr);
	if (!MmIsAddressValid(pdptes))
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
			phys_addr.QuadPart = pdpte.PageFrameNumber << PAGE_SHIFT;
			page_start = MmGetVirtualForPhysical(phys_addr);
			if (!MmIsAddressValid(page_start))
			{
				continue;
			}

			page_flags = GetPDPTEFlags(pdpte);
			for (SIZE_T i = 0; i < TABLE_SIZE * TABLE_SIZE; ++i)
			{
				OnEachPage(page_start + i * PAGE_SIZE, page_flags, Context);
			}
		}
		else
		{
			OnEachPDPTE(pdpte, OnEachPage, Context);
		}
	}
}

VOID WalkPageTables(_In_ CR3 cr3, _In_ VOID(*OnEachPage)(ULONG64, ULONG, PVOID), _In_opt_ PVOID Context)
{
	PAGED_CODE();

	PML4E_64* pml4es = NULL;
	PML4E_64 pml4e = { 0 };
	PHYSICAL_ADDRESS phys_addr = { 0 };

	phys_addr.QuadPart = cr3.AddressOfPageDirectory << PAGE_SHIFT;
	pml4es = (PML4E_64*)MmGetVirtualForPhysical(phys_addr);
	if (!MmIsAddressValid(pml4es))
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