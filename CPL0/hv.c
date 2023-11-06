#include "hv.h"
#include "report.h"
#include "common.h"
#include "config.h"
#include "ia32.h"
#include "mmu.h"
#include <intrin.h>
#include <ioc.h>

VOID PeformVmExitCheck(VOID)
{
	PAGED_CODE();

#define LOOP_COUNT 255
#define NORMAL_AVG_TSC 2000

	KAFFINITY prev_affinity = { 0 };
	KIRQL prev_irql = 0;
	int r[4] = {0, 0, 0, 0};
	REPORT_NODE* report = NULL;
	REPORT_HYPERVISOR* data = NULL;
	ULONG64 avg_tsc = 0;
	ULONG64 start_tsc = 0;
	ULONG64 end_tsc = 0;

	prev_affinity = KeSetSystemAffinityThreadEx(1ull << KeGetCurrentProcessorNumber());
	prev_irql = KfRaiseIrql(HIGH_LEVEL, NULL);
	_disable();

	for (UCHAR i = 0; i < LOOP_COUNT; ++i)
	{
		start_tsc = __rdtsc();
		__cpuid(&r, 1);
		end_tsc = __rdtsc();

		avg_tsc += end_tsc - start_tsc;
	}
	avg_tsc /= LOOP_COUNT;

	_enable();
	KeLowerIrql(prev_irql);
	KeRevertToUserAffinityThreadEx(prev_affinity);

	if (avg_tsc > NORMAL_AVG_TSC)
	{
		report = MMU_Alloc(REPORT_HEADER_SIZE + sizeof(REPORT_HYPERVISOR));
		report->Id = REPORT_ID_HYPERVISOR;
		report->DataSize = sizeof(REPORT_HYPERVISOR);

		data = (REPORT_SIGNATURE*)&report->Data;
		data->Tsc = avg_tsc;
		if (!InsertReportNode(report))
		{
			MMU_Free(report);
		}
	}
}

VOID FaultVmExit(VOID)
{
	PAGED_CODE();

	KAFFINITY prev_affinity = { 0 };
	KIRQL prev_irql = 0;
	ULONG64 prev_cr3 = 0;
	int r[4] = { 0, 0, 0, 0 };

	prev_affinity = KeSetSystemAffinityThreadEx(1ull << KeGetCurrentProcessorNumber());
	prev_irql = KfRaiseIrql(HIGH_LEVEL, NULL);
	_disable();

	prev_cr3 = __readcr3();
	__writecr3(0);
	__cpuid(&r, 1);
	__writecr3(prev_cr3);

	_enable();
	KeLowerIrql(prev_irql);
	KeRevertToUserAffinityThreadEx(prev_affinity);
}