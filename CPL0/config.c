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

PFN_CiCheckSignedFile g_CiCheckSignedFile = NULL;

BCRYPT_ALG_HANDLE g_hAlgorithm_MD5 = NULL;
BCRYPT_HASH_HANDLE g_hHash_MD5 = NULL;

BCRYPT_ALG_HANDLE g_hAlgorithm_SHA1 = NULL;
BCRYPT_HASH_HANDLE g_hHash_SHA1 = NULL;

BCRYPT_ALG_HANDLE g_hAlgorithm_SHA256 = NULL;
BCRYPT_HASH_HANDLE g_hHash_SHA256 = NULL;

volatile LONG g_PT_Walking = 0;

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

    if (g_hHash_MD5 != NULL)
    {
        BCryptDestroyHash(g_hHash_MD5);
    }

    if (g_hAlgorithm_MD5 != NULL)
    {
        BCryptCloseAlgorithmProvider(g_hAlgorithm_MD5, 0);
    }

    if (g_hAlgorithm_SHA1 != NULL)
    {
        BCryptDestroyHash(g_hAlgorithm_SHA1);
    }

    if (g_hHash_SHA1 != NULL)
    {
        BCryptCloseAlgorithmProvider(g_hHash_SHA1, 0);
    }

    FreeReportList();
}