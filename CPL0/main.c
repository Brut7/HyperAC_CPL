#include "main.h"
#include "config.h"
#include "common.h"
#include "hv.h"
#include "flow.h"
#include "memory.h"
#include "sha256.h"


UCHAR g_hashes[4][32] = {
	{ 0 },
	{ 0 },
	{ 0 },
	{ 0 },
};

static VOID OnEachPage(_In_ ULONG64 PageStart, _In_ SIZE_T PageSize, _In_opt_ PVOID Context)
{
	UNREFERENCED_PARAMETER(Context);
	PAGED_CODE();

	/* List of hashed pages, we will get them from server */

	UCHAR hash[32] = { 0 };
	REPORT_SIGNATURE* data = NULL;
	REPORT_NODE* report = NULL;
	SHA256_CTX sha256_ctx = { 0 };

	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, (PVOID)PageStart, PAGE_SIZE);
	sha256_final(&sha256_ctx, &hash);

	for (UCHAR i = 0; i < ARRAYSIZE(g_hashes); ++i)
	{
		if (memcmp(&hash, &g_hashes[i], sizeof(hash)) == 0)
		{
			DebugMessage("Found hash at 0x%llx\n", PageStart);

			report = InsertReportNode(&g_ReportHead, sizeof(REPORT_SIGNATURE));
			report->Id = REPORT_ID_SIGNATURE;
			report->DataSize = sizeof(REPORT_SIGNATURE);

			data = (REPORT_SIGNATURE*)&report->Data;
			data->HashIndex = i;
			data->PageStart = PageStart;
			data->PageSize = PageSize;
		}
	}
}

VOID SigScanThread(_In_opt_ PVOID Context)
{
	UNREFERENCED_PARAMETER(Context);
	PAGED_CODE();

	SHA256_CTX sha256_ctx = { 0 };
	CR3 cr3 = { 0 };

	InterlockedIncrement(&g_ThreadCount);
	
	// hash some func in ntoskrnl to test

	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, (PVOID)((ULONG64)&ExAllocatePool & ~0xFFF), PAGE_SIZE);
	sha256_final(&sha256_ctx, &g_hashes[1]);
	
	while (g_Unloading == FALSE)
	{
		cr3.AsUInt = __readcr3();
		WalkPageTables(cr3, OnEachPage, NULL);

		Sleep(1000);
	}

	InterlockedDecrement(&g_ThreadCount);
}

VOID MainThread(_In_opt_ PVOID Context)
{
	InterlockedIncrement(&g_ThreadCount);

	PeformVmExitCheck();

	while (g_Unloading == FALSE)
	{
	
		Sleep(500);
	}

	InterlockedDecrement(&g_ThreadCount);
	PsTerminateSystemThread(STATUS_SUCCESS);
}