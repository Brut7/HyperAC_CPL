#ifndef H_REPORT
#define H_REPORT

#include <ntifs.h>
#include <minwindef.h>
#include <ioc.h>

VOID ValidateReportList();
REPORT_NODE* GetReportNode(_In_ USHORT Index);
USHORT GetReportCount();
BOOLEAN InsertReportNode(_In_ REPORT_NODE* NewNode);
VOID FreeReportList();

#pragma alloc_text(PAGE, ValidateReportList)
#pragma alloc_text(PAGE, InsertReportNode)
#pragma alloc_text(PAGE, FreeReportList)
#pragma alloc_text(PAGE, GetReportCount)
#pragma alloc_text(PAGE, GetReportNode)

#endif // H_REPORT