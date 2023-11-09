#include "callbacks.h"
#include "config.h"
#include "report.h"
#include "mmu.h"
#include "memory.h"
#include "pt.h"
#include <ioc.h>
#include <ntimage.h>
#include "pe.h"
#include "hash.h"
#include <ntstrsafe.h>
VOID OnEachPage(_In_ ULONG64 PageStart, _In_ ULONG PageFlags, _In_ PSCAN_CONTEXT Context)
{
	PAGED_CODE();
	
	UCHAR page_data[PAGE_SIZE] = { 0 };
	SCAN_HASH hash = { 0 };
	UCHAR page_hash[16] = { 0 };
	PREPORT_HASH hash_data = NULL;
	PREPORT_NODE report = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	status = SafeCopy(page_data, PageStart, sizeof(page_data));
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
			if (!InsertReportNode(report))
			{
				MMU_Free(report);
			}
		}
	}
}
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

BOOLEAN CalculateAuthenticodeHash(
	_In_ PVOID buffer,
	_In_ ULONG bufferSize,
	_Out_ PUCHAR hashBuffer,
	_In_ ULONG hashBufferSize)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	BCRYPT_ALG_HANDLE hAlgorithm = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	ULONG resultSize = 0;
	PUCHAR hashObject = NULL;
	ULONG hashObjectSize = 0;
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS ntHeaders;
	ULONG checksumOffset;
	ULONG securityDirectoryOffset;
	ULONG securityDirectorySize;

	// Validate that buffer is large enough for DOS header.
	if (bufferSize < sizeof(IMAGE_DOS_HEADER)) {
		return FALSE;
	}

	dosHeader = (PIMAGE_DOS_HEADER)buffer;

	// Validate that buffer is large enough for NT headers.
	if (bufferSize < dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
		return FALSE;
	}

	ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)buffer + dosHeader->e_lfanew);

	// Calculate the checksum offset.
	checksumOffset = (ULONG)((PUCHAR)&ntHeaders->OptionalHeader.CheckSum - (PUCHAR)buffer);

	// Validate that buffer is large enough for the checksum.
	if (bufferSize < checksumOffset + sizeof(DWORD)) {
		return FALSE;
	}

	// Calculate the security directory offset and size.
	securityDirectoryOffset = (ULONG)((PUCHAR)&ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] - (PUCHAR)buffer);
	securityDirectorySize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;

	// Validate that buffer is large enough for the security directory.
	if (bufferSize < securityDirectoryOffset + securityDirectorySize) {
		return FALSE;
	}

	// Open an algorithm handle.
	status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(status)) {
		return FALSE;
	}

	// Get the size of the buffer to hold the hash object.
	status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjectSize, sizeof(ULONG), &resultSize, 0);
	if (!NT_SUCCESS(status)) {
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return FALSE;
	}

	// Allocate the hash object on the heap.
	hashObject = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, hashObjectSize, 'hash');
	if (!hashObject) {
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return FALSE;
	}

	// Create a hash.
	status = BCryptCreateHash(hAlgorithm, &hHash, hashObject, hashObjectSize, NULL, 0, 0);
	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(hashObject, 'hash');
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return FALSE;
	}

	// Hash the image up to the checksum.
	status = BCryptHashData(hHash, (PUCHAR)buffer, checksumOffset, 0);
	if (!NT_SUCCESS(status)) {
		goto Cleanup;
	}
	//shit
	status = BCryptFinishHash(hHash, hashBuffer, hashBufferSize, 0);
	return status;
	// Skip checksum and security directory, continue hashing after them.
	ULONG afterChecksumOffset = checksumOffset + sizeof(DWORD);
	ULONG afterSecurityDirectoryOffset = securityDirectoryOffset + securityDirectorySize;
	ULONG sizeToHash;

	// Hash the data between the checksum and the security directory.
	if (afterChecksumOffset < securityDirectoryOffset) {
		sizeToHash = securityDirectoryOffset - afterChecksumOffset;
		status = BCryptHashData(hHash, (PUCHAR)buffer + afterChecksumOffset, sizeToHash, 0);
		if (!NT_SUCCESS(status)) {
			goto Cleanup;
		}
	}

	// Hash the remaining part of the image after the security directory.
	if (afterSecurityDirectoryOffset < bufferSize) {
		sizeToHash = bufferSize - afterSecurityDirectoryOffset;
		status = BCryptHashData(hHash, (PUCHAR)buffer + afterSecurityDirectoryOffset, sizeToHash, 0);
		if (!NT_SUCCESS(status)) {
			goto Cleanup;
		}
	}

	// Finalize the hash.
	status = BCryptFinishHash(hHash, hashBuffer, hashBufferSize, 0);

Cleanup:
	if (hHash) {
		BCryptDestroyHash(hHash);
	}
	if (hashObject) {
		ExFreePoolWithTag(hashObject, 'hash');
	}
	BCryptCloseAlgorithmProvider(hAlgorithm, 0);

	return NT_SUCCESS(status);
}

NTSTATUS ReadFileIntoBuffer(
	_In_ PUNICODE_STRING FileName,
	_Out_ PVOID* FileBuffer,
	_Out_ PULONG FileSize)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	HANDLE fileHandle = NULL;
	OBJECT_ATTRIBUTES objectAttributes;
	IO_STATUS_BLOCK ioStatusBlock;
	FILE_STANDARD_INFORMATION fileInformation;
	PVOID buffer = NULL;

	InitializeObjectAttributes(&objectAttributes, FileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	// Open the file
	status = ZwCreateFile(
		&fileHandle,
		GENERIC_READ,
		&objectAttributes,
		&ioStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	// Get file size
	status = ZwQueryInformationFile(
		fileHandle,
		&ioStatusBlock,
		&fileInformation,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);

	if (!NT_SUCCESS(status)) {
		ZwClose(fileHandle);
		return status;
	}

	// Allocate memory to read the file
	buffer = ExAllocatePoolWithTag(NonPagedPool, fileInformation.EndOfFile.LowPart, 'file');
	if (!buffer) {
		ZwClose(fileHandle);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Read the file
	status = ZwReadFile(
		fileHandle,
		NULL,
		NULL,
		NULL,
		&ioStatusBlock,
		buffer,
		fileInformation.EndOfFile.LowPart,
		NULL,
		NULL);

	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(buffer, 'file');
		ZwClose(fileHandle);
		return status;
	}

	*FileBuffer = buffer;
	*FileSize = fileInformation.EndOfFile.LowPart;
	ZwClose(fileHandle);

	return STATUS_SUCCESS;
}

// This function assumes FileName is a valid UNICODE_STRING ready to be used.
NTSTATUS LoadAndCalculateHash(
	_In_ PUNICODE_STRING FileName,
	_Out_ PUCHAR HashBuffer,
	_In_ ULONG HashBufferSize)
{
	PVOID fileBuffer = NULL;
	ULONG fileSize = 0;
	NTSTATUS status = ReadFileIntoBuffer(FileName, &fileBuffer, &fileSize);

	if (!NT_SUCCESS(status)) {
		// Handle error, possibly log it
		return status;
	}

	// Calculate the hash of the buffer here.
	// The function CalculateAuthenticodeHash is assumed to be defined elsewhere.
	BOOLEAN result = CalculateAuthenticodeHash(fileBuffer, fileSize, HashBuffer, HashBufferSize);

	// Free the file buffer after hashing.
	ExFreePoolWithTag(fileBuffer, 'file');

	return result ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}
void PrintHashAsHex(const UCHAR* hashBuffer, size_t hashBufferSize) {
	// Each byte takes 2 characters in hex, +1 for the terminating null
	size_t stringLength = (hashBufferSize * 2) + 1;
	PCHAR hashString = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, stringLength, 'hash');

	if (hashString != NULL) {
		RtlZeroMemory(hashString, stringLength);
		for (size_t i = 0; i < hashBufferSize; ++i) {
			// Append each byte in hex format to the string
			RtlStringCbPrintfA(hashString + (i * 2), stringLength - (i * 2), "%02X", hashBuffer[i]);
		}
		// Use DPFLTR_IHVDRIVER_ID to represent your driver, this value can be changed accordingly
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "SHA-256: %s\n", hashString);
		ExFreePoolWithTag(hashString, 'hash');
	}
	else {
		// Handle allocation failure
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to allocate memory for hash string\n");
	}
}
OB_PREOP_CALLBACK_STATUS OnProcessHandleCreation(_In_ PVOID Context, _Inout_ POB_PRE_OPERATION_INFORMATION OpInfo)
{
	UNREFERENCED_PARAMETER(Context);
	PAGED_CODE();
	
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
		// WHITELISTED PROCESSES MUST BE VALIDATED FURTHER
		if (!strcmp(image_name, "csrss.exe") || !strcmp(image_name, "explorer.exe") || !strcmp(image_name, "lsass.exe"))
		{
			WCHAR explorerPathBuffer[] = L"\\??\\C:\\Windows\\explorer.exe";
			UNICODE_STRING explorerPath;
			RtlInitUnicodeString(&explorerPath, explorerPathBuffer);

			// Assuming SHA-256 is used, the hash size will be 32 bytes
			UCHAR hashBuffer[32];
			ULONG hashBufferSize = sizeof(hashBuffer);

			// Initialize the hash buffer to zero
			RtlZeroMemory(hashBuffer, hashBufferSize);

			NTSTATUS status = LoadAndCalculateHash(&explorerPath, hashBuffer, hashBufferSize);
			PrintHashAsHex(hashBuffer, hashBufferSize);
			goto ExitCallback;
		}

		//DebugMessage("Unknown process blocked (%s)\n", image_name);
		OpInfo->Parameters->CreateHandleInformation.DesiredAccess = PROCESS_QUERY_LIMITED_INFORMATION;
		OpInfo->Parameters->DuplicateHandleInformation.DesiredAccess = PROCESS_QUERY_LIMITED_INFORMATION;
		
		report = MMU_Alloc(REPORT_HEADER_SIZE + sizeof(REPORT_BLOCKED_PROCESS));
		report->Id = REPORT_ID_BLOCKED_PROCESS;
		report->DataSize = sizeof(REPORT_BLOCKED_PROCESS);

		data = (REPORT_BLOCKED_PROCESS*)&report->Data;
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
			goto ExitCallback;
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
	PAGED_CODE();

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
	PAGED_CODE();

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
	PAGED_CODE();

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
