#include "hv.h"
#include "report.h"
#include "common.h"
#include "config.h"
#include "ia32.h"
#include <intrin.h>
#include <ioc.h>

VOID HV_PeformVmExitCheck()
{
#define LOOP_COUNT 255
#define NORMAL_AVG_TSC 2000

	KAFFINITY prev_affinity = { 0 };
	KIRQL prev_irql = 0;
	int r[4] = {0, 0, 0, 0};
	REPORT_NODE* report_node = NULL;
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
		report_node = InsertReportNode(&g_ReportHead, sizeof(REPORT_HYPERVISOR));
		data = (REPORT_HYPERVISOR*)&report_node->Data;

		data->rdtsc = avg_tsc;
	}
}