#ifndef H_CALLBACKS
#define H_CALLBACKS

#include <ntifs.h>
#include "common.h"

VOID OnEachPage(_In_ ULONG64 PageStart, _In_ ULONG PageFlags, _In_ PSCAN_CONTEXT Context);
STATIC OB_PREOP_CALLBACK_STATUS OnProcessHandleCreation(_In_ PVOID Context, _Inout_ POB_PRE_OPERATION_INFORMATION OpInfo);
STATIC OB_PREOP_CALLBACK_STATUS OnThreadHandleCreation(_In_ PVOID Context, _Inout_ POB_PRE_OPERATION_INFORMATION OpInfo);
STATIC VOID OnProcessCreation(_In_ HANDLE ParentId, _In_ HANDLE ProcessId, _In_ BOOLEAN Create);
NTSTATUS RegisterCallbacks(VOID);
NTSTATUS UnregisterCallbacks(VOID);

#pragma alloc_text(PAGE, OnEachPage)
#pragma alloc_text(PAGE, OnProcessHandleCreation)
#pragma alloc_text(PAGE, OnThreadHandleCreation)
#pragma alloc_text(PAGE, OnProcessCreation)
#pragma alloc_text(PAGE, RegisterCallbacks)
#pragma alloc_text(PAGE, UnregisterCallbacks)

#endif