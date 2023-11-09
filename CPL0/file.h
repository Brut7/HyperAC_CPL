#pragma once

#include "config.h"

BOOLEAN CalculateAuthenticodeHash(
	_In_ PVOID buffer,
	_In_ ULONG bufferSize,
	_Out_ PUCHAR hashBuffer,
	_In_ ULONG hashBufferSize,
	_In_ ULONG file_size);

NTSTATUS ReadFileIntoBuffer(
	_In_ PUNICODE_STRING FileName,
	_Out_ PVOID* FileBuffer,
	_Out_ PULONG FileSize);

NTSTATUS LoadAndCalculateHash(
	_In_ PUNICODE_STRING FileName,
	_Out_ PUCHAR HashBuffer,
	_In_ ULONG HashBufferSize);

BOOL AuthenticateApplication(PCUNICODE_STRING ImageFileName, PVOID DigestBuffer, int SHAtype);

VOID GetFilePathFromProcess(PEPROCESS process, PUNICODE_STRING path_string);