#include "config.h"
#include "spinlock.h"
#include "report.h"
#include "mmu.h"

volatile LONG64 g_AllocCount = 0;
volatile LONG64 g_FreeCount = 0;

volatile LONG g_UnloadThreads = FALSE;
volatile LONG g_ThreadCount = 0;
HANDLE g_MainThread = NULL;

REPORT_NODE g_ReportHead = { NULL };
SPINLOCK g_ReportLock = { 0 };

PDRIVER_OBJECT g_DriverObject = NULL;
UNICODE_STRING g_DeviceName = RTL_CONSTANT_STRING(L"\\Device\\HyperAC");
UNICODE_STRING g_SymbolicLinkName = RTL_CONSTANT_STRING(L"\\??\\HyperAC");

PVOID g_ObRegistrationHandle = NULL;
BOOLEAN g_ProcessCallbackRegistered = FALSE;

PEPROCESS g_GameProcess = NULL;
HANDLE g_GameProcessId = NULL;

VOID FreeConfig(VOID)
{
    PAGED_CODE();

    if (g_MainThread != NULL)
    {
        ZwClose(g_MainThread);
    }

    if (g_GameProcess != NULL)
    {
        ObfDereferenceObject(g_GameProcess);
    }

    FreeReportList();
}