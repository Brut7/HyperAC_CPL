#include "pt.h"
#include "common.h"
#include "memory.h"
#include <ntddk.h>
#include "config.h"
#include "flow.h"
#include "mmu.h"


ULONG GetPTEFlags(_In_ PTE_64 pte)
{
	

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
	

	PTE_64* ptes = NULL;
	PTE_64 pte = { 0 };
	NTSTATUS status = STATUS_SUCCESS;
	LONG64 page_start = 0;
	ULONG page_flags = 0;

	
	ptes = ToVirtual(pde.PageFrameNumber << PAGE_SHIFT);
	if (ptes == NULL)
	{
		return;
	}
		
	for (USHORT i = 0; i < TABLE_LENGTH; ++i)
	{
		pte = ptes[i];
		if (!pte.Present)
		{
			continue;
		}

		page_start = ToVirtual(pte.PageFrameNumber << PAGE_SHIFT);
		if (page_start == 0 || MmIsAddressValid(page_start) == FALSE)
		{
			continue;
		}

		page_flags = GetPDEFlags(pde);
		OnEachPage(page_start, page_flags, Context);
	}
}

VOID OnEachPDPTE(_In_ PDPTE_64 pdpte, _In_ VOID(*OnEachPage)(ULONG64, ULONG, PVOID), _In_opt_ PVOID Context)
{
	

	PDE_64* pdes = NULL;
	PDE_64 pde = { 0 };
	NTSTATUS status = STATUS_SUCCESS;
	LONG64 page_start = 0;
	ULONG page_flags = 0;

	pdes = ToVirtual(pdpte.PageFrameNumber << PAGE_SHIFT);
	if (pdes == NULL)
	{
		return;
	}

	for (USHORT i = 0; i < TABLE_LENGTH; ++i)
	{
		pde = pdes[i];
		if (!pde.Present)
		{
			continue;
		}

		if (pde.LargePage)
		{
			page_flags = GetPDEFlags(pde);
			page_start = pdpte.PageFrameNumber << PAGE_SHIFT;
			for (SIZE_T i = 0; i < TABLE_LENGTH; ++i)
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
	

	PDPTE_64* pdptes = NULL;
	PDPTE_64 pdpte = { 0 };
	NTSTATUS status = STATUS_SUCCESS;
	LONG64 page_start = 0;
	ULONG page_flags = 0;


	pdptes = ToVirtual(pml4e.PageFrameNumber << PAGE_SHIFT);
	if (pdptes == NULL)
	{
		return;
	}

	for (USHORT i = 0; i < TABLE_LENGTH; ++i)
	{
		pdpte = pdptes[i];
		if (!pdpte.Present)
		{
			continue;
		}

		if (pdpte.LargePage)
		{
			page_flags = GetPDPTEFlags(pdpte);
			page_start = pdpte.PageFrameNumber << PAGE_SHIFT;
			for (ULONG i = 0; i < TABLE_LENGTH * TABLE_LENGTH; ++i)
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
	

	PML4E_64* pml4es = NULL;
	PML4E_64 pml4e = { 0 };
	NTSTATUS status = STATUS_SUCCESS;

	pml4es = ToVirtual(cr3.AddressOfPageDirectory << PAGE_SHIFT);
	if (pml4es == NULL)
	{
		return;
	}

	for (USHORT i = 0; i < TABLE_LENGTH; ++i)
	{
		pml4e = pml4es[i];
		if (!pml4e.Present)
		{
			continue;
		}

		OnEachPML4E(pml4e, OnEachPage, Context);
	}
}