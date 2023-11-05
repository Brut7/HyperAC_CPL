#include "hv.h"
#include "report.h"
#include "common.h"
#include "config.h"
#include <intrin.h>
#include <ioc.h>

VOID HV_PeformVmExitCheck()
{
#define LOOP_COUNT 255
#define NORMAL_AVG_TSC 2000

	KAFFINITY prev_affinity = { 0 };
	KIRQL prev_irql = 0;
	int r[4] = {0, 0, 0, 0};
	REPORT_NODE* report = NULL;
	REPORT_HYPERVISOR* data = NULL;
	ULONG64 avg_tsc = 0;

	prev_affinity = KeSetSystemAffinityThreadEx(1ull << KeGetCurrentProcessorNumber());
	prev_irql = KfRaiseIrql(HIGH_LEVEL, NULL);
	_disable();

	for (UCHAR i = 0; i < LOOP_COUNT; ++i)
	{
		ULONG64 tsc = __rdtsc();
		__cpuid(&r, 1);
		avg_tsc += __rdtsc() - tsc;
	}
	avg_tsc /= LOOP_COUNT;

	_enable();
	KeLowerIrql(prev_irql);
	KeRevertToUserAffinityThreadEx(prev_affinity);

	if (avg_tsc > NORMAL_AVG_TSC)
	{
		report = InsertReportNode(&g_ReportHead, sizeof(REPORT_HYPERVISOR));
		data = (REPORT_HYPERVISOR*)&report->Data;

		data->rdtsc = avg_tsc;
		DebugMessage("HV_PeformVmExitCheck: %llu\n", avg_tsc);

	}
}