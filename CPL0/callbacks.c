#include "callbacks.h"
#include "config.h"
#include "report.h"
#include "mmu.h"
#include "memory.h"
#include "file.h"
#include <ioc.h>

#include "pe.h"
#include "hash.h"
#include "flow.h"
#include <ntstrsafe.h>

VOID OnEachPage(_In_ ULONG64 PageStart, _In_ ULONG PageFlags, _In_ PSCAN_CONTEXT Context)
{
	

	UCHAR page_data[PAGE_SIZE] = { 0 };
	SCAN_HASH hash = { 0 };
	UCHAR page_hash[16] = { 0 };
	PREPORT_HASH hash_data = NULL;
	PREPORT_NODE report = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	if (PageStart == 0 || Context == NULL)
	{
		return;
	}

	status = SafeVirtualCopy(page_data, PageStart, sizeof(page_data));
	if (!NT_SUCCESS(status))
	{
		return;
	}

	status = MD5_HashBuffer(page_data, sizeof(page_data), page_hash);
	if (!NT_SUCCESS(status))
	{
		return;
	}

	for (USHORT i = 0; i < Context->HashCount; ++i)
	{
		hash = Context->Hashes[i];
		if (memcmp(&page_hash, &hash.MD5[i], sizeof(hash)) == 0)
		{
			report = MMU_Alloc(REPORT_HEADER_SIZE + sizeof(REPORT_HASH));
			report->Id = REPORT_ID_HASH;
			report->DataSize = sizeof(REPORT_HASH);

			hash_data = (PREPORT_HASH)&report->Data;
			hash_data->HashIndex = i;
			hash_data->PageStart = PageStart;
			hash_data->PageFlags = PageFlags;
			if (!InsertReportNode(report))
			{
				MMU_Free(report);
			}
		}
	}
}

OB_PREOP_CALLBACK_STATUS OnProcessHandleCreation(_In_ PVOID Context, _Inout_ POB_PRE_OPERATION_INFORMATION OpInfo)
{
	UNREFERENCED_PARAMETER(Context);
	
	
	PEPROCESS process = NULL;
	PEPROCESS parent_process = NULL;
	HANDLE parent_process_id = NULL;
	HANDLE process_id = NULL;
	PCHAR image_name = NULL;
	PREPORT_NODE report = NULL;
	PREPORT_BLOCKED_PROCESS data = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	process = (PEPROCESS)OpInfo->Object;
	process_id = PsGetProcessId(process);
	parent_process = IoGetCurrentProcess();
	parent_process_id = PsGetProcessId(parent_process);
	image_name = PsGetProcessImageFileName(parent_process);
	
	if (g_GameProcess == process && g_GameProcessId == process_id && parent_process != g_GameProcess)
	{
		if (!strcmp(image_name, "csrss.exe") || !strcmp(image_name, "explorer.exe") || !strcmp(image_name, "lsass.exe"))
		{
			WCHAR path_buffer[MAX_PATH];
			UNICODE_STRING resolved_path;
			resolved_path.Buffer = path_buffer;
			GetFilePathFromProcess(parent_process, &resolved_path);

			UCHAR hash_buffer[32];
			LoadAndCalculateHash(&resolved_path, hash_buffer, sizeof(hash_buffer));
			BOOL successfully_authenticated = AuthenticateApplication(&resolved_path, hash_buffer, 2);
			if (successfully_authenticated)
			{
				goto ExitCallback;
			}
			else
			{
				DebugMessage("Failed to authenticate %wZ", &resolved_path);
			}
		}

		OpInfo->Parameters->CreateHandleInformation.DesiredAccess = PROCESS_QUERY_LIMITED_INFORMATION;
		OpInfo->Parameters->DuplicateHandleInformation.DesiredAccess = PROCESS_QUERY_LIMITED_INFORMATION;
		report = MMU_Alloc(REPORT_HEADER_SIZE + sizeof(REPORT_BLOCKED_PROCESS));
		if (report)
		{
			report->Id = REPORT_ID_BLOCKED_PROCESS;
			report->DataSize = sizeof(REPORT_BLOCKED_PROCESS);

			data = (PREPORT_BLOCKED_PROCESS)&report->Data;
			data->ProcessId = parent_process_id;
			strncpy(data->ImageName, image_name, sizeof(data->ImageName) - 1);
			data->ImageName[sizeof(data->ImageName) - 1] = '\0';
			if (!InsertReportNode(report))
			{
				MMU_Free(report);
			}
		}
	}
ExitCallback:
	return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS OnThreadHandleCreation(_In_ PVOID Context, _Inout_ POB_PRE_OPERATION_INFORMATION OpInfo)
{
	UNREFERENCED_PARAMETER(Context);
	PAGED_CODE();

	PEPROCESS process = NULL;
	PEPROCESS parent_process = NULL;
	HANDLE parent_process_id = NULL;
	HANDLE thread_id = NULL;
	PKTHREAD thread = NULL;
	HANDLE process_id = NULL;
	PCHAR image_name = NULL;
	PREPORT_NODE report = NULL;
	PREPORT_BLOCKED_THREAD data = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	thread = (PKTHREAD)OpInfo->Object;
	thread_id = PsGetThreadId(thread);
	process = *(PEPROCESS*)((ULONG64)thread + 0x220);
	process_id = PsGetProcessId(process);
	parent_process = IoGetCurrentProcess();
	parent_process_id = PsGetProcessId(parent_process);
	image_name = PsGetProcessImageFileName(parent_process);

	if (g_GameProcess == process && g_GameProcessId == process_id && parent_process != g_GameProcess)
	{
		//DebugMessage("(%x) (%s) %i %i %i", status, image_name, protection.Signer, protection.Audit, protection.Type);

		if (!strcmp(image_name, "csrss.exe") || !strcmp(image_name, "explorer.exe") || !strcmp(image_name, "lsass.exe"))
		{
			WCHAR path_buffer[MAX_PATH];
			UNICODE_STRING resolved_path;
			resolved_path.Buffer = path_buffer;
			GetFilePathFromProcess(parent_process, &resolved_path);

			UCHAR hash_buffer[32];
			LoadAndCalculateHash(&resolved_path, hash_buffer, sizeof(hash_buffer));
			BOOL successfully_authenticated = AuthenticateApplication(&resolved_path, hash_buffer, 2);
			if (successfully_authenticated)
			{
				goto ExitCallback;
			}
			else
			{
				DebugMessage("Failed to authenticate %wZ", &resolved_path);
			}
		}

		//DebugMessage("Unknown process blocked (%s)\n", image_name);
		OpInfo->Parameters->CreateHandleInformation.DesiredAccess = PROCESS_QUERY_LIMITED_INFORMATION;
		OpInfo->Parameters->DuplicateHandleInformation.DesiredAccess = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_CREATE_PROCESS;

		report = MMU_Alloc(REPORT_HEADER_SIZE + sizeof(REPORT_BLOCKED_THREAD));
		report->Id = REPORT_ID_BLOCKED_THREAD;
		report->DataSize = sizeof(REPORT_BLOCKED_THREAD);

		data = (REPORT_BLOCKED_THREAD*)&report->Data;
		data->ThreadId = thread_id;
		data->ProcessId = parent_process_id;
		strcpy(data->ImageName, image_name);

		if (!InsertReportNode(report))
		{
			MMU_Free(report);
		}
	}

ExitCallback:
	return OB_PREOP_SUCCESS;
}

VOID OnProcessCreation(_In_ HANDLE ParentId, _In_ HANDLE ProcessId, _In_ BOOLEAN Create)
{
	UNREFERENCED_PARAMETER(ParentId);
	

	PEPROCESS process = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	CHAR* image_name = NULL;
	HANDLE process_id = NULL;

	status = PsLookupProcessByProcessId(ProcessId, &process);
	if (!NT_SUCCESS(status))
	{
		return;
	}

	image_name = PsGetProcessImageFileName(process);
	process_id = PsGetProcessId(process);

	if (Create && (g_GameProcess == NULL || g_GameProcessId == 0))
	{
		if (!strcmp(image_name, "Crab Game.exe"))
		{
			g_GameProcess = process;
			g_GameProcessId = process_id;
			DebugMessage("Game process created");
			return;
		}
	}
	else if (g_GameProcess != NULL && process_id == g_GameProcessId)
	{
		ObfDereferenceObject(g_GameProcess);
		g_GameProcess = NULL;
		g_GameProcessId = 0;
		DebugMessage("Game process closed");
		return;
	}

	ObfDereferenceObject(process);
}

NTSTATUS RegisterCallbacks(VOID)
{
	

	NTSTATUS status = STATUS_SUCCESS;
	OB_CALLBACK_REGISTRATION ob_callback = { 0 };
	OB_OPERATION_REGISTRATION op[2] = { 0 };

	op[0].ObjectType = PsProcessType;
	op[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	op[0].PreOperation = OnProcessHandleCreation;
	op[0].PostOperation = NULL;

	op[1].ObjectType = PsThreadType;
	op[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	op[1].PreOperation = OnThreadHandleCreation;
	op[1].PostOperation = NULL;

	ob_callback.Version = OB_FLT_REGISTRATION_VERSION;
	ob_callback.OperationRegistrationCount = ARRAYSIZE(op);
	ob_callback.RegistrationContext = NULL;
	ob_callback.OperationRegistration = op;

	status = ObRegisterCallbacks(&ob_callback, &g_ObRegistrationHandle);
	if (!NT_SUCCESS(status))
	{
		DebugMessage("ObRegisterCallbacks failed: 0x%08X\n", status);
		return status;
	}

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
	

	if (g_ObRegistrationHandle != NULL)
	{
		ObUnRegisterCallbacks(g_ObRegistrationHandle);
		g_ObRegistrationHandle = NULL;
	}

	if (g_ProcessCallbackRegistered == TRUE)
	{
		PsSetCreateProcessNotifyRoutine(&OnProcessCreation, TRUE);
		g_ProcessCallbackRegistered = FALSE;
	}
}
