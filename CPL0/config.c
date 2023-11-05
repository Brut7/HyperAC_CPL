#include "config.h"
#include "spinlock.h"

volatile ULONG g_AllocCount = 0;
volatile ULONG g_FreeCount = 0;

BOOLEAN g_Unloading = FALSE;
volatile ULONG g_ThreadCount = 0;
HANDLE g_MainThread = NULL;

REPORT_NODE g_ReportHead = { NULL };
SPINLOCK g_ReportLock = { 0 };

PDRIVER_OBJECT g_DriverObject = NULL;
UNICODE_STRING g_DeviceName = RTL_CONSTANT_STRING(L"\\Device\\HyperAC");
UNICODE_STRING g_SymbolicLinkName = RTL_CONSTANT_STRING(L"\\??\\HyperAC");
