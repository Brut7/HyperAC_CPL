#include "callbacks.h"
#include "sha256.h"
#include "config.h"
#include "report.h"
#include "mmu.h"
#include "memory.h"
#include <ioc.h>

VOID OnEachPage(_In_ ULONG64 PageStart, _In_ ULONG PageFlags, _In_ PSCAN_CONTEXT Context)
{
	PAGED_CODE();
	
	UCHAR page_data[PAGE_SIZE] = { 0 };
	SCAN_HASH hash = { 0 };
	UCHAR page_hash[32] = { 0 };
	PREPORT_HASH hash_data = NULL;
	PREPORT_NODE report = NULL;
	SHA256_CTX sha256_ctx = { 0 };
	NTSTATUS status = STATUS_SUCCESS;

	status = SafeCopy(page_data, PageStart, sizeof(page_data));
	if (!NT_SUCCESS(status))
	{
		return;
	}

	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, &page_data, sizeof(page_data));
	sha256_final(&sha256_ctx, &hash);

	for (USHORT i = 0; i < Context->HashCount; ++i)
	{
		hash = Context->Hashes[i];
		if (memcmp(&page_hash, &hash.SHA256[i], sizeof(hash)) == 0)
		{
			report = MMU_Alloc(REPORT_HEADER_SIZE + sizeof(REPORT_HASH));
			report->Id = REPORT_ID_HASH;
			report->DataSize = sizeof(REPORT_HASH);

			hash_data = (PREPORT_HASH)&report->Data;
			hash_data->HashIndex = i;
			hash_data->PageStart = PageStart;
			if (!InsertReportNode(report))
			{
				MMU_Free(report);
			}
		}
	}
}

OB_PREOP_CALLBACK_STATUS OnHandleCreation(_In_ PVOID Context, _Inout_ POB_PRE_OPERATION_INFORMATION OpInfo)
{
	UNREFERENCED_PARAMETER(Context);
	PAGED_CODE();
	
	OB_PREOP_CALLBACK_STATUS status = OB_PREOP_SUCCESS;

	if (g_GameProcess != (PEPROCESS)OpInfo->Object)
	{
		return status;
	}

	DebugMessage("Handle creation for game process\n");
}

VOID OnProcessCreation(_In_ HANDLE ParentId, _In_ HANDLE ProcessId, _In_ BOOLEAN Create)
{
	PAGED_CODE();

	PEPROCESS process = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	CHAR* image_name = NULL;
	HANDLE process_id = NULL;

	status = PsLookupProcessByProcessId(ProcessId, &process);
	if (!NT_SUCCESS(status))
	{
		goto ExitCallback;
	}

	image_name = (CHAR*)((ULONG64)process + 0x5a8);
	process_id = *(HANDLE*)((ULONG64)process + 0x440);

	if (!strcmp(image_name, "Crab Game.exe"))
	{
		if (Create)
		{
			g_GameProcess = process;
			g_GameProcessId = process_id;
			DebugMessage("Game process created\n");
		}
		else
		{
			ObfDereferenceObject(g_GameProcess);
			DebugMessage("Game process closed\n");
		}

		return;
	}

ExitCallback:

	if (process != NULL)
	{
		ObfDereferenceObject(process);
	}
}

NTSTATUS RegisterCallbacks(VOID)
{
	PAGED_CODE();

	NTSTATUS status = STATUS_SUCCESS;
	/*OB_CALLBACK_REGISTRATION ob_callback = { 0 };
	POB_OPERATION_REGISTRATION op_reg = NULL;
	
	ob_callback.Version = OB_FLT_REGISTRATION_VERSION;
	ob_callback.OperationRegistrationCount = 1;
	ob_callback.RegistrationContext = NULL;

	op_reg = &ob_callback.OperationRegistration[0];
	op_reg->ObjectType = PsProcessType;
	op_reg->Operations = OB_OPERATION_HANDLE_CREATE;
	op_reg->PreOperation = OnHandleCreation;
	op_reg->PostOperation = NULL;

	status = ObRegisterCallbacks(&ob_callback, &g_ObRegistrationHandle);
	if (!NT_SUCCESS(status))
	{
		DebugMessage("ObRegisterCallbacks failed: 0x%08X\n", status);
		return status;
	}*/

	status = PsSetCreateProcessNotifyRoutine(OnProcessCreation, FALSE);
	if (!NT_SUCCESS(status))
	{
		DebugMessage("PsSetCreateProcessNotifyRoutine failed: 0x%08X\n", status);
		UnregisterCallbacks();
		return status;
	}
	g_ProcessCallbackRegistered = TRUE;

	return status;
}

NTSTATUS UnregisterCallbacks(VOID)
{
	PAGED_CODE();

	//if (g_ObRegistrationHandle != NULL)
	//{
	//	ObUnRegisterCallbacks(g_ObRegistrationHandle);
	//}

	if (g_ProcessCallbackRegistered == TRUE)
	{
		PsSetCreateProcessNotifyRoutine(&OnProcessCreation, TRUE);
		g_ProcessCallbackRegistered = FALSE;
	}
}
