#ifndef H_CONFIG
#define H_CONFIG

#include <ntifs.h>
#include <bcrypt.h>
#include "report.h"
#include "spinlock.h"
#include "common.h"

#define DebugMessage(msg, ...) \
  DbgPrintEx(0, 0, "[" __FUNCTION__ "] " msg, __VA_ARGS__)

#define PSEUDO_RANDOM(_min, _max) \
  (_min + (__rdtsc() % (_max - _min + 1)))

#define FAST_FAIL_POOL_ERROR 0x23
#define FAST_FAIL_CORRUPTED_REPORT_LIST 0x24

extern volatile LONG64 g_AllocCount;
extern volatile LONG64 g_FreeCount;

extern volatile LONG g_UnloadThreads;
extern volatile LONG g_ThreadCount;
extern HANDLE g_MainThread;

extern REPORT_NODE g_ReportHead;
extern SPINLOCK g_ReportLock;

extern PDRIVER_OBJECT g_DriverObject;
extern UNICODE_STRING g_DeviceName;
extern UNICODE_STRING g_SymbolicLinkName;

extern PVOID g_ObRegistrationHandle;
extern BOOLEAN g_ProcessCallbackRegistered;

extern PEPROCESS g_GameProcess;
extern HANDLE g_GameProcessId;

extern PFN_CiCheckSignedFile g_CiCheckSignedFile;

extern BCRYPT_ALG_HANDLE g_hAlgorithm_MD5;
extern BCRYPT_HASH_HANDLE g_hHash_MD5;

extern BCRYPT_ALG_HANDLE g_hAlgorithm_SHA1;
extern BCRYPT_HASH_HANDLE g_hHash_SHA1;

extern BCRYPT_ALG_HANDLE g_hAlgorithm_SHA256;
extern BCRYPT_HASH_HANDLE g_hHash_SHA256;

extern volatile LONG g_PT_Walking;

VOID FreeConfig(VOID);

#endif// H_CONFIG