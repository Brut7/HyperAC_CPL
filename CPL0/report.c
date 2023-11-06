#include "report.h"
#include "mmu.h"
#include "config.h"
#include "spinlock.h"

VOID ValidateReportList()
{
    PAGED_CODE();

    REPORT_NODE* node = NULL;
    USHORT count = 0;

    SpinlockAcquire(&g_ReportLock);

    node = g_ReportHead.Next;
    while (node)
    {
        if (node->Index != count)
        {
            __fastfail(FAST_FAIL_CORRUPTED_REPORT_LIST);
            return;
        }

        node = node->Next;
        ++count;
    }

    SpinlockRelease(&g_ReportLock);
}

REPORT_NODE* GetReportNode(_In_ USHORT Index)
{
    PAGED_CODE();

    REPORT_NODE* node = NULL;
    USHORT count = 0;

    SpinlockAcquire(&g_ReportLock);

    node = g_ReportHead.Next;
    while (node && count < Index)
    {
        node = node->Next;
        ++count;
    }

    SpinlockRelease(&g_ReportLock);
    return (count == Index) ? node : NULL;
}

USHORT GetReportCount()
{
    PAGED_CODE();

    USHORT count = 0;
    REPORT_NODE* node = NULL;

    SpinlockAcquire(&g_ReportLock);

    node = g_ReportHead.Next;
    while (node)
    {
        ++count;
        node = node->Next;
    }

    SpinlockRelease(&g_ReportLock);
    return count;
}

BOOLEAN InsertReportNode(_In_ REPORT_NODE* NewNode)
{
    PAGED_CODE();

    USHORT count = 0;
    REPORT_NODE* node = NULL;
    REPORT_NODE* last = NULL;

    if (NewNode == NULL)
    {
        return FALSE;
    }

    SpinlockAcquire(&g_ReportLock);

    node = g_ReportHead.Next;
    if (node == NULL)
    {
        NewNode->Index = 0;
        g_ReportHead.Next = NewNode;
        SpinlockRelease(&g_ReportLock);
        return TRUE;
    }

    while (node != NULL)
    {
        if (node->DataSize == NewNode->DataSize && node->Id == NewNode->Id
            && !memcmp(node->Data, NewNode->Data, NewNode->DataSize))
        {
            SpinlockRelease(&g_ReportLock);
            return FALSE;
        }

        last = node;
        node = node->Next;
        ++count;
    }

    NewNode->Index = count;
    last->Next = NewNode;
    SpinlockRelease(&g_ReportLock);
    return TRUE;
}

VOID FreeReportList()
{
    PAGED_CODE();

    REPORT_NODE* node = NULL;
    REPORT_NODE* next = NULL;

    SpinlockAcquire(&g_ReportLock);

    node = g_ReportHead.Next;
    while (node)
    {
        next = node->Next;
        MMU_Free(node);
        node = next;
    }

    g_ReportHead.Next = NULL;
    SpinlockRelease(&g_ReportLock);
}