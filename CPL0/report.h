#ifndef H_REPORT
#define H_REPORT

#include <ntifs.h>
#include <minwindef.h>

typedef enum _REPORT_ID {
	None = 0,
	HypervisorRDTSC,
}REPORT_ID, *PREPORT_ID;

typedef struct _REPORT_NODE {
	struct _REPORT_NODE* Next;
	REPORT_ID Id;
	BYTE Data[1];
}REPORT_NODE, *PREPORT_NODE;

REPORT_NODE* InsertReportNode(_In_ REPORT_NODE* Head, _In_ SIZE_T DataSize);
VOID FreeReportList(_In_ REPORT_NODE* Head);

#pragma alloc_text(PAGE, InsertReportNode)
#pragma alloc_text(PAGE, FreeReportList)

#endif // H_REPORT