#include "hwid.h"
#include "common.h"
#include "sha256.h"
#include "mmu.h"
#include "config.h"

NTSTATUS HWID_GetBootUUID(_Out_ UCHAR Hash[32]) {
	PAGED_CODE();

	NTSTATUS status = STATUS_SUCCESS;
	ULONG req_size = 0;
	PSYSTEM_BOOT_ENVIRONMENT_INFORMATION boot_info = NULL;
	SHA256_CTX ctx = { 0 };

	status = ZwQuerySystemInformation(SystemBootEnvironmentInformation, NULL, 0, &req_size);
	if (status != STATUS_INFO_LENGTH_MISMATCH) {
		DebugMessage("ZwQuerySystemInformation failed: 0x%08X\n", status);
		return status;
	}

	boot_info = (PSYSTEM_BOOT_ENVIRONMENT_INFORMATION)MMU_Alloc(req_size);
	if (boot_info == NULL) {
		DebugMessage("MMU_Alloc failed\n");
		return STATUS_NO_MEMORY;
	};

	status = ZwQuerySystemInformation(SystemBootEnvironmentInformation, boot_info, req_size, &req_size);
	if (!NT_SUCCESS(status)) {
		DebugMessage("ZwQuerySystemInformation failed: 0x%08X\n", status);
		MMU_Free(boot_info);
		return status;
	}

	sha256_init(&ctx);
	sha256_update(&ctx, (UCHAR*)&boot_info->BootIdentifier, sizeof(GUID));
	sha256_final(&ctx, Hash);

	MMU_Free(boot_info);
	return status;
}

NTSTATUS HWID_GetMonitorEDID(_Out_ UCHAR Hash[32]) {
	PAGED_CODE();

	NTSTATUS status = STATUS_SUCCESS;

	/* TODO */

	

	return status;
}