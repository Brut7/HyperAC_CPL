#ifndef H_CALLBACKS
#define H_CALLBACKS

#include <ntifs.h>
#include "common.h"

STATIC VOID OnEachPage(_In_ ULONG64 PageStart, _In_ ULONG PageFlags, _In_ PSCAN_CONTEXT Context);
STATIC OB_PREOP_CALLBACK_STATUS OnHandleCreation(_In_ PVOID RegistrationContext, _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation);
STATIC VOID OnProcessCreation(_In_ HANDLE ParentId, _In_ HANDLE ProcessId, _In_ BOOLEAN Create);
NTSTATUS RegisterCallbacks(VOID);
NTSTATUS UnregisterCallbacks(VOID);

#pragma alloc_text(PAGE, OnEachPage)
#pragma alloc_text(PAGE, OnHandleCreation)
#pragma alloc_text(PAGE, OnProcessCreation)
#pragma alloc_text(PAGE, RegisterCallbacks)
#pragma alloc_text(PAGE, UnregisterCallbacks)

#endif