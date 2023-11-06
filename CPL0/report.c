#include "report.h"
#include "mmu.h"
#include "config.h"
#include "spinlock.h"

REPORT_NODE* GetReportNode(_In_ REPORT_NODE* Head, _In_ USHORT Index)
{
	PAGED_CODE();

	REPORT_NODE* node = NULL;
	USHORT count = 0;

	if (Head == NULL)
	{
		return NULL;
	}

	SpinlockAcquire(&g_ReportLock);

	node = Head->Next;
	while (node)
	{
		if (count == Index)
		{
			break;
		}

		++count;
		node = node->Next;
	}

	SpinlockRelease(&g_ReportLock);
	return node;
}

USHORT GetReportCount(_In_ REPORT_NODE* Head)
{
	PAGED_CODE();

	USHORT count = 0;
	REPORT_NODE* node = NULL;

	if (Head == NULL)
	{
		return 0;
	}

	SpinlockAcquire(&g_ReportLock);

	node = Head->Next;
	while (node)
	{
		++count;
		node = node->Next;
	}

	SpinlockRelease(&g_ReportLock);
	return count;
}

REPORT_NODE* InsertReportNode(_In_ REPORT_NODE* Head, _In_ SIZE_T DataSize)
{
	PAGED_CODE();

	if (Head == NULL)
	{
		return NULL;
	}

	// MUST CHECK IF REPORT ALREADY EXISTS

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