#include "callbacks.h"
#include "sha256.h"
#include "config.h"
#include "report.h"
#include "mmu.h"
#include "memory.h"
#include "pt.h"
#include <ioc.h>
#include <ntimage.h>
#include "pe.h"
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

	//sha256_init(&sha256_ctx);
	//sha256_update(&sha256_ctx, &page_data, sizeof(page_data));
	//sha256_final(&sha256_ctx, &hash);

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
//shit
BOOL inRange(const BYTE* rangeStartAddr, const BYTE* rangeEndAddr, const BYTE* addrToCheck)
{
	if (addrToCheck > rangeEndAddr || addrToCheck < rangeStartAddr)
	{
		return FALSE;
	}
	return TRUE;
}

BOOL AuthenticateApplication(PCUNICODE_STRING ImageFileName, PVOID DigestBuffer, LONG SHAtype)
{
		
	IO_STATUS_BLOCK IoBlock = { 0 };
	OBJECT_ATTRIBUTES ObjAttr = { 0 }, ObjAttr2 = { 0 };
	HANDLE FileHandle = NULL, SectionHandle = NULL;
	PVOID SectionObject = NULL, BaseAddress = NULL;
	SIZE_T BaseSize = NULL;

	InitializeObjectAttributes(&ObjAttr, (PUNICODE_STRING)(ImageFileName), OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	NTSTATUS Status = ZwOpenFile(&FileHandle, SYNCHRONIZE | FILE_READ_DATA, &ObjAttr, &IoBlock, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);

	if (!NT_SUCCESS(Status) || !NT_SUCCESS(IoBlock.Status) || !FileHandle)
	{
		DebugMessage("Failed to open file: 0x%llX | 0x%llX\n", Status, IoBlock.Status);
		return FALSE;
	}

	InitializeObjectAttributes(&ObjAttr2, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	Status = ZwCreateSection(&SectionHandle, SECTION_MAP_READ, &ObjAttr2, NULL, PAGE_READONLY, SEC_COMMIT, FileHandle);
	ZwClose(FileHandle);

	if (!NT_SUCCESS(Status) || !SectionHandle)
	{
		DebugMessage("Failed to create section: 0x%llX\n", Status);
		return FALSE;
	}

	Status = ObReferenceObjectByHandle(SectionHandle, SECTION_MAP_READ, NULL, KernelMode, &SectionObject, NULL);

	if (!NT_SUCCESS(Status))
	{
		DebugMessage("Failed to reference object: 0x%llX\n", Status);
		return FALSE;
	}

	ZwClose(SectionHandle);

	Status = MmMapViewInSystemSpace(SectionObject, &BaseAddress, &BaseSize);
	ObfDereferenceObject(SectionObject);

	if (!NT_SUCCESS(Status))
	{
		DebugMessage("Failed to map section: 0x%llX\n", Status);
		return FALSE;
	}

	ULONG SecurityDirectoryEntrySize = NULL;
	PVOID SecurityDirectoryEntry = RtlImageDirectoryEntryToData(BaseAddress, TRUE, 4, &SecurityDirectoryEntrySize);

	if (!SecurityDirectoryEntry)
	{
		DebugMessage("Failed to get security directory!\n");
		MmUnmapViewInSystemSpace(BaseAddress);
		return FALSE;
	}

	const BYTE* EndOfFileAddress = (BYTE*)(BaseAddress)+BaseSize;
	const BYTE* EndOfSecurityDirectory = (BYTE*)(SecurityDirectoryEntry)+SecurityDirectoryEntrySize;

	if (EndOfSecurityDirectory > EndOfFileAddress || SecurityDirectoryEntry < BaseAddress)
	{
		DebugMessage("Security Directory is not contained in the file view!\n");
		MmUnmapViewInSystemSpace(BaseAddress);
		return FALSE;
	}

	LPWIN_CERTIFICATE WinCert = (LPWIN_CERTIFICATE)(SecurityDirectoryEntry);

	PolicyInfo SignerPolicyInfo, TAPolicyInfo;
	LARGE_INTEGER SigningTime = { 0 };
	const LONG DigestSize = SHAtype == 1 ? 20 : 32; // SHA1 / SHA256 size
	const LONG DigestIdentifier = SHAtype == 1 ? 0x8004 : 0x800C; // SHA1 / SHA256 identifier

	Status = g_CiCheckSignedFile(DigestBuffer, DigestSize, DigestIdentifier, WinCert, SecurityDirectoryEntrySize, &SignerPolicyInfo, &SigningTime, &TAPolicyInfo);

	if (NT_SUCCESS(Status))
	{
		DebugMessage("Signed file found!\n");
		MmUnmapViewInSystemSpace(BaseAddress);

		/*if (DebugEnabled)
		{*/
		const pCertChainInfoHeader ChainInfoHeader = SignerPolicyInfo.certChainInfo;
		const BYTE* StartOfCertChainInfo = (BYTE*)ChainInfoHeader;
		const BYTE* EndOfCertChainInfo = (BYTE*)SignerPolicyInfo.certChainInfo + ChainInfoHeader->bufferSize;

		if (!inRange(StartOfCertChainInfo, EndOfCertChainInfo, (BYTE*)ChainInfoHeader->ptrToCertChainMembers))
			return TRUE;

		if (!inRange(StartOfCertChainInfo, EndOfCertChainInfo, (BYTE*)ChainInfoHeader->ptrToCertChainMembers + sizeof(CertChainMember)))
			return TRUE;

		pCertChainMember SignerChainMember = ChainInfoHeader->ptrToCertChainMembers;

		DebugMessage("Subject: %.*s\nIssuer: %.*s\n", SignerChainMember->subjectName.nameLen, (char*)(SignerChainMember->subjectName.pointerToName),
			SignerChainMember->issuerName.nameLen, (char*)(SignerChainMember->issuerName.pointerToName));
		//}

		return TRUE;
	}
	else
		DebugMessage("Failed to get signed file0x%llX\n", Status);

	MmUnmapViewInSystemSpace(BaseAddress);
	return FALSE;
}
NTSTATUS GetProcessImagePath(OUT PUNICODE_STRING ProcessImagePath)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	HANDLE processHandle = NULL;

	// Get a handle to the current process.
	status = ObOpenObjectByPointer(PsGetCurrentProcess(),
		OBJ_KERNEL_HANDLE,
		NULL,
		GENERIC_READ,
		*PsProcessType,
		KernelMode,
		&processHandle);

	if (NT_SUCCESS(status))
	{
		// Query the process image file name.
		ULONG returnedLength;
		status = ZwQueryInformationProcess(processHandle,
			ProcessImageFileName,
			ProcessImagePath,
			ProcessImagePath->MaximumLength,
			&returnedLength);

		// Close the handle to the process.
		ZwClose(processHandle);
	}

	return status;
}
#include <bcrypt.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

BOOLEAN CalculateAuthenticodeHash(
	_In_ PVOID imageBase,
	_In_ ULONG checksumOffset,
	_In_ ULONG securityDirectoryOffset,
	_In_ ULONG securityDirectorySize,
	_Out_ PUCHAR hashBuffer,
	_In_ ULONG hashBufferSize)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	BCRYPT_ALG_HANDLE hAlgorithm = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	ULONG resultSize = 0;
	PUCHAR hashObject = NULL;
	ULONG hashObjectSize = 0;

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
	if (hashObject == NULL) {
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
	DebugMessage("imagebase byte value: %x", *(PUCHAR)imageBase);
	// Hash the image up to the checksum.
	status = BCryptHashData(hHash, (PUCHAR)imageBase, checksumOffset, 0);
	if (!NT_SUCCESS(status)) {
		goto Cleanup;
	}
	BCryptFinishHash(hHash, hashBuffer, hashBufferSize, 0);
	return NT_SUCCESS(status);

	// Skip checksum and security directory, continue hashing after them.
	ULONG startOfHash = securityDirectoryOffset + securityDirectorySize;
	ULONG sizeToHash = checksumOffset + securityDirectorySize - startOfHash;
	status = BCryptHashData(hHash, (PUCHAR)imageBase + startOfHash, sizeToHash, 0);
	if (!NT_SUCCESS(status)) {
		goto Cleanup;
	}

	// Finalize the hash.
	status = BCryptFinishHash(hHash, hashBuffer, hashBufferSize, 0);
	if (!NT_SUCCESS(status)) {
		goto Cleanup;
	}

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

VOID PrintHash(const PUCHAR digestBuffer, SIZE_T digestSize) {
	CHAR hexOutput[65] = { 0 }; // 32 bytes * 2 characters/byte + 1 for null-terminator
	const CHAR hexDigits[] = "0123456789ABCDEF";

	for (SIZE_T i = 0, j = 0; i < digestSize; ++i) {
		hexOutput[j++] = hexDigits[(digestBuffer[i] >> 4) & 0x0F];
		hexOutput[j++] = hexDigits[digestBuffer[i] & 0x0F];
	}

	// Print the hex string using DbgPrintEx
	DbgPrintEx(0, 0, "%s\n", hexOutput);
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
		//DebugMessage("(%x) %i %i %i", status, protection.Signer, protection.Audit, protection.Type);

		if (!strcmp(image_name, "explorer.exe"))
		{

			UNICODE_STRING ImageFileName;
			//GetProcessImagePath(&ImageFileName);
			DebugMessage("%wZ", );
			UNICODE_STRING UnicodeImageFileName;
			ANSI_STRING AnsiImageFileName;
			// First convert the char* ImageFileName to an ANSI_STRING
			RtlInitAnsiString(&AnsiImageFileName, "\\??\\C:\\Windows\\explorer.exe");
			// Then convert the ANSI_STRING to a UNICODE_STRING
			RtlAnsiStringToUnicodeString(&UnicodeImageFileName, &AnsiImageFileName, TRUE);
			/*char DigestBuffer[] = {
	0x95, 0xed, 0x57, 0x7f, 0xa7, 0x50, 0x31, 0xd2,
	0x1c, 0x56, 0x3a, 0x96, 0x89, 0x6a, 0xaf, 0xda,
	0x00, 0x23, 0x71, 0x98, 0xea, 0x95, 0x27, 0xc1,
	0x53, 0x13, 0x60, 0x69, 0xce, 0x17, 0x67, 0xef
			};*/
			PVOID base_address = PsGetProcessSectionBaseAddress(IoGetCurrentProcess());
			PIMAGE_NT_HEADERS nt_header = RtlImageNtHeader(base_address);
			//SafeGetNtHeader(base_address, &nt_header);

			ULONG64 security_offset = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
			//nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
			ULONG64 checksumaddress = &nt_header->OptionalHeader.CheckSum;

			DebugMessage("value: %x ", *(PUCHAR)((ULONG64)base_address + 2));
			DebugMessage("allok\n");
			char DigestBuffer[32];
			CalculateAuthenticodeHash(base_address, checksumaddress - (ULONG64)base_address, security_offset - (ULONG64)base_address, 0, DigestBuffer, 32);
			DebugMessage("checksumoffset: %x", checksumaddress - (ULONG64)base_address);
			PrintHash(DigestBuffer, 32);
			BOOL result = AuthenticateApplication(&UnicodeImageFileName, DigestBuffer, 2);
			DebugMessage("auth result: %i\n", result);
		}
		// WHITELISTED PROCESSES MUST BE VALIDATED FURTHER
		if (!strcmp(image_name, "csrss.exe") || !strcmp(image_name, "explorer.exe") || !strcmp(image_name, "lsass.exe"))
		{
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
