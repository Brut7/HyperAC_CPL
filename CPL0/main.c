#include "main.h"
#include "config.h"
#include "common.h"
#include "hv.h"
#include "flow.h"
#include "memory.h"
#include "sha256.h"
#include "mmu.h"
#include "pt.h"

typedef struct _SCAN_SIGNATURE
{
	CHAR Pattern[128];
	CHAR Mask[128];
}SCAN_SIGNATURE, *PSCAN_SIGNATURE;

typedef struct _SCAN_HASH
{
	BYTE SHA256[32];
}SCAN_HASH, * PSCAN_HASH;

typedef struct _SCAN_CONTEXT
{
	USHORT SigCount;
	PSCAN_SIGNATURE Signatures;

	USHORT HashCount;
	PSCAN_HASH Hashes;
}SCAN_CONTEXT, *PSCAN_CONTEXT;


ULONG Found = 0;

static VOID OnEachPage(_In_ ULONG64 PageStart, _In_ ULONG PageFlags, _In_ PSCAN_CONTEXT Context)
{
	UCHAR page_data[PAGE_SIZE] = { 0 };
	SCAN_SIGNATURE signature = { 0 };
	SCAN_HASH hash = { 0 };
	UCHAR page_hash[32] = { 0 };
	PREPORT_SIGNATURE sig_data = NULL;
	PREPORT_HASH hash_data = NULL;
	PREPORT_NODE report = NULL;
	SHA256_CTX sha256_ctx = { 0 };
	ULONG64 sig_address = 0;
	NTSTATUS status = STATUS_SUCCESS;

	status = SafeCopy(page_data, PageStart, sizeof(page_data));
	if (!NT_SUCCESS(status))
	{
		return;
	}

	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, &page_data, sizeof(page_data));
	sha256_final(&sha256_ctx, &hash);

	for (USHORT i = 0; i < Context->SigCount; ++i)
	{
		signature = Context->Signatures[i];

		sig_address = FindSignature(page_data, PAGE_SIZE, signature.Pattern, signature.Mask);
		if (sig_address)
		{
			report = MMU_Alloc(REPORT_HEADER_SIZE + sizeof(REPORT_SIGNATURE));
			report->Id = REPORT_ID_SIGNATURE;
			report->DataSize = sizeof(REPORT_SIGNATURE);

			sig_data = (PREPORT_SIGNATURE)&report->Data;
			sig_data->SigIndex = i;
			sig_data->PageStart = PageStart;
			memcpy(sig_data->PageHash, &page_hash, SHA256_SIZE);
			memcpy(sig_data->PageData, page_data, PAGE_SIZE);
			if (!InsertReportNode(report))
			{
				MMU_Free(report);
			}

			++Found;
		}
	}

	for (USHORT i = 0; i < Context->HashCount; ++i)
	{
		hash = Context->Hashes[i];

		if (memcmp(&hash, &hash.SHA256[i], sizeof(hash)) == 0)
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

VOID ScannerThread(_In_opt_ PVOID Context)
{
	UNREFERENCED_PARAMETER(Context);
	PAGED_CODE();

	SHA256_CTX sha256_ctx = { 0 };
	CR3 cr3 = { 0 };
	CHAR header[PAGE_SIZE] = { 0 };
	PEPROCESS game_process = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	InterlockedIncrement(&g_ThreadCount);
	
	status = PsLookupProcessByProcessId((HANDLE)3600, &game_process);
	if (!NT_SUCCESS(status))
	{
		goto ExitThread;
	}

	KeAttachProcess(game_process);
	SafeCopy(header, 0x7ff6aa040000, sizeof(header));
	KeDetachProcess(game_process);

	while (InterlockedExchange(&g_UnloadThreads, g_UnloadThreads) == FALSE)
	{
		SCAN_CONTEXT context;
		context.HashCount = 0;
		context.SigCount = 1;
		context.Signatures = MMU_Alloc(sizeof(SCAN_SIGNATURE) * context.SigCount);
		strcpy(context.Signatures[0].Pattern, "\x48\x8B\xC4\xFA\x48\x83\xEC\x10\x50\x9C\x6A\x10\x48\x8D\x05\xCC\xCC\xCC\xCC\x50\xB8\x3F\x00");
		strcpy(context.Signatures[0].Mask, "xxxxxxxxxxxxxxx????xxxx");

		Found = 0;
		KeAttachProcess(game_process);
		cr3.AsUInt = __readcr3();
		WalkPageTables(cr3, OnEachPage, &context);
		KeDetachProcess();

		DebugMessage("found! %i\n", Found);

		MMU_Free(context.Signatures);

		DebugMessage("cr3: 0x%llx\n", cr3.AsUInt);

		//Sleep(1000);
	}

ExitThread:
	InterlockedDecrement(&g_ThreadCount);
}

VOID MainThread(_In_opt_ PVOID Context)
{
	InterlockedIncrement(&g_ThreadCount);

	PeformVmExitCheck();

	while (InterlockedExchange(&g_UnloadThreads, g_UnloadThreads) == FALSE)
	{
		ValidateReportList();

		Sleep(1);
	}

	InterlockedDecrement(&g_ThreadCount);
	PsTerminateSystemThread(STATUS_SUCCESS);
}