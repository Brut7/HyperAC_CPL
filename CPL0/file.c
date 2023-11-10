#include "file.h"
#include <ntimage.h>

BOOLEAN CalculateAuthenticodeHash(
	_In_ PVOID buffer,
	_In_ ULONG bufferSize,
	_Out_ PUCHAR hashBuffer,
	_In_ ULONG hashBufferSize,
	_In_ ULONG file_size)
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
	if (bufferSize < sizeof(IMAGE_DOS_HEADER)) {
		return FALSE;
	}
	dosHeader = (PIMAGE_DOS_HEADER)buffer;
	if (bufferSize < dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
		return FALSE;
	}
	ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)buffer + dosHeader->e_lfanew);
	checksumOffset = (ULONG)((PUCHAR)&ntHeaders->OptionalHeader.CheckSum - (PUCHAR)buffer);
	if (bufferSize < checksumOffset + sizeof(DWORD)) {
		return FALSE;
	}
	securityDirectoryOffset = (ULONG)((PUCHAR)&ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] - (PUCHAR)buffer);
	securityDirectorySize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
	if (bufferSize < securityDirectoryOffset + securityDirectorySize) {
		return FALSE;
	}
	status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(status)) {
		return FALSE;
	}
	status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjectSize, sizeof(ULONG), &resultSize, 0);
	if (!NT_SUCCESS(status)) {
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return FALSE;
	}
	hashObject = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, hashObjectSize, 'hash');
	if (!hashObject) {
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return FALSE;
	}
	status = BCryptCreateHash(hAlgorithm, &hHash, hashObject, hashObjectSize, NULL, 0, 0);
	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(hashObject, 'hash');
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return FALSE;
	}
	status = BCryptHashData(hHash, (PUCHAR)buffer, checksumOffset, 0);
	if (!NT_SUCCESS(status)) {
		goto Cleanup;
	}
	ULONG64 fileOffset = checksumOffset + sizeof(ntHeaders->OptionalHeader.CheckSum);
	ULONG cbInput = securityDirectoryOffset - fileOffset;
	status = BCryptHashData(hHash, (PUCHAR)RtlOffsetToPointer(buffer, fileOffset), cbInput, 0);
	if (!NT_SUCCESS(status)) {
		goto Cleanup;
	}
	fileOffset = securityDirectoryOffset + sizeof(IMAGE_DATA_DIRECTORY);
	ULONG secDirVirtualAddress = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
	cbInput = secDirVirtualAddress == 0 ? file_size - fileOffset : secDirVirtualAddress - fileOffset;
	status = BCryptHashData(hHash, (PUCHAR)RtlOffsetToPointer(buffer, fileOffset), cbInput, 0);
	if (!NT_SUCCESS(status)) {
		goto Cleanup;
	}
	status = BCryptFinishHash(hHash, hashBuffer, hashBufferSize, 0);
Cleanup:
	if (hHash) {
		BCryptDestroyHash(hHash);
	}
	if (hashObject) {
		ExFreePoolWithTag(hashObject, 'xdxd');
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
	status = ZwCreateFile(&fileHandle, GENERIC_READ, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	status = ZwQueryInformationFile(fileHandle, &ioStatusBlock, &fileInformation, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(status))
	{
		ZwClose(fileHandle);
		return status;
	}
	buffer = ExAllocatePoolWithTag(NonPagedPool, fileInformation.EndOfFile.LowPart, 'ffff');
	if (!buffer)
	{
		ZwClose(fileHandle);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	status = ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock, buffer, fileInformation.EndOfFile.LowPart, NULL, NULL);
	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(buffer, 'ffff');
		ZwClose(fileHandle);
		return status;
	}
	*FileBuffer = buffer;
	*FileSize = fileInformation.EndOfFile.LowPart;
	ZwClose(fileHandle);
	return STATUS_SUCCESS;
}

NTSTATUS LoadAndCalculateHash(
	_In_ PUNICODE_STRING FileName,
	_Out_ PUCHAR HashBuffer,
	_In_ ULONG HashBufferSize)
{
	PVOID fileBuffer = NULL;
	ULONG fileSize = 0;
	NTSTATUS status = ReadFileIntoBuffer(FileName, &fileBuffer, &fileSize);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	BOOLEAN result = CalculateAuthenticodeHash(fileBuffer, fileSize, HashBuffer, HashBufferSize, fileSize);
	ExFreePoolWithTag(fileBuffer, 'ffff');
	return result ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

BOOL AuthenticateApplication(PCUNICODE_STRING ImageFileName, PVOID DigestBuffer, int SHAtype)
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
	const int DigestSize = SHAtype == 1 ? 20 : 32;
	const int DigestIdentifier = SHAtype == 1 ? 0x8004 : 0x800C;

	Status = g_CiCheckSignedFile(DigestBuffer, DigestSize, DigestIdentifier, WinCert, SecurityDirectoryEntrySize, &SignerPolicyInfo, &SigningTime, &TAPolicyInfo);

	if (NT_SUCCESS(Status))
	{
		MmUnmapViewInSystemSpace(BaseAddress);

		//maybe we could keep this commented as info, because we could check the Issuer of some certificates to do blacklists or other detections
		/*if (DebugEnabled)
		{
			const pCertChainInfoHeader ChainInfoHeader = SignerPolicyInfo.certChainInfo;
			const BYTE* StartOfCertChainInfo = (BYTE*)ChainInfoHeader;
			const BYTE* EndOfCertChainInfo = (BYTE*)SignerPolicyInfo.certChainInfo + ChainInfoHeader->bufferSize;

			if (!inRange(StartOfCertChainInfo, EndOfCertChainInfo, (BYTE*)ChainInfoHeader->ptrToCertChainMembers))
				return TRUE;

			if (!inRange(StartOfCertChainInfo, EndOfCertChainInfo, (BYTE*)ChainInfoHeader->ptrToCertChainMembers + sizeof(CertChainMember)))
				return TRUE;

			pCertChainMember SignerChainMember = ChainInfoHeader->ptrToCertChainMembers;

			DebugMessage("Subject: %.*s\nIssuer: %.*s\n", SignerChainMember->subjectName.nameLen, static_cast<char*>(SignerChainMember->subjectName.pointerToName),
				SignerChainMember->issuerName.nameLen, static_cast<char*>(SignerChainMember->issuerName.pointerToName));
		}*/

		return TRUE;
	}
	else
		DebugMessage("Failed to get signed file0x%llX\n", Status);

	MmUnmapViewInSystemSpace(BaseAddress);
	return FALSE;
}

VOID GetFilePathFromProcess(PEPROCESS process, PUNICODE_STRING path_string)
{
	HANDLE process_handle;
	NTSTATUS status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, *PsProcessType, KernelMode, &process_handle);

	path_string->MaximumLength = (MAX_PATH) * sizeof(WCHAR);
	USHORT returnedLength = 0;
	status = ZwQueryInformationProcess(process_handle, ProcessImageFileNameWin32, path_string->Buffer, MAX_PATH * sizeof(WCHAR), &returnedLength);
	path_string->Buffer += 4;
	RtlCopyMemory(path_string->Buffer, L"\\??\\", 4 * sizeof(WCHAR));
	path_string->Length = returnedLength - 10;
	ZwClose(process_handle);
}