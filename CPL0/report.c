#include "report.h"
#include "mmu.h"
#include "config.h"
#include "spinlock.h"

REPORT_NODE* InsertReportNode(_In_ REPORT_NODE* Head, _In_ SIZE_T DataSize)
{
	PAGED_CODE();

	REPORT_NODE* last = Head;
	REPORT_NODE* node = NULL;

	SpinlockAcquire(&g_ReportLock);
	while (last->Next)
	{
		last = last->Next;
	}

	node = (REPORT_NODE*)MMU_Alloc(DataSize + sizeof(REPORT_NODE) - sizeof(node->Data));
	if (node == NULL)
	{
		return NULL;
	}

	memset((void*)((ULONG64)node + sizeof(REPORT_NODE) - sizeof(node->Data)), 0, DataSize);
	last->Next = node;

	SpinlockRelease(&g_ReportLock);
	return node;
}

VOID FreeReportList(_In_ REPORT_NODE* Head)
{
	PAGED_CODE();

	REPORT_NODE* node = NULL;
	REPORT_NODE* next = NULL;

	if (Head == NULL)
	{
		return;
	}

	SpinlockAcquire(&g_ReportLock);

	node = Head->Next;
	next = node;

	while (next)
	{
		next = node->Next;
		MMU_Free(node);
		node = next;
	}

	SpinlockRelease(&g_ReportLock);
}