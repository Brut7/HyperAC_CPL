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

#endif // H_REPORT