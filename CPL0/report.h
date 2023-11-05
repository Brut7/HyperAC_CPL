#ifndef H_REPORT
#define H_REPORT

#include <ntifs.h>
#include <minwindef.h>
#include <ioc.h>

REPORT_NODE* GetReportNode(_In_ REPORT_NODE* Head, _In_ USHORT Index);
USHORT GetReportCount(_In_ REPORT_NODE* Head);
REPORT_NODE* InsertReportNode(_In_ REPORT_NODE* Head, _In_ SIZE_T DataSize);
VOID FreeReportList(_In_ REPORT_NODE* Head);

#pragma alloc_text(PAGE, InsertReportNode)
#pragma alloc_text(PAGE, FreeReportList)
#pragma alloc_text(PAGE, GetReportCount)
#pragma alloc_text(PAGE, GetReportNode)

#endif // H_REPORT