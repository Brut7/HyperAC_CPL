#ifndef H_CONFIG
#define H_CONFIG

#include <ntifs.h>
#include "report.h"
#include "spinlock.h"

#define DebugMessage(msg, ...) \
  DbgPrintEx(0, 0, "[" __FUNCTION__ "] " msg, __VA_ARGS__)

extern volatile LONG g_AllocCount;
extern volatile LONG g_FreeCount;

extern BOOLEAN g_Unloading;
extern volatile ULONG g_ThreadCount;
extern HANDLE g_MainThread;
extern HANDLE g_SigScanThread;

extern REPORT_NODE g_ReportHead;
extern SPINLOCK g_ReportLock;

extern PDRIVER_OBJECT g_DriverObject;
extern UNICODE_STRING g_DeviceName;
extern UNICODE_STRING g_SymbolicLinkName;

#endif// H_CONFIG