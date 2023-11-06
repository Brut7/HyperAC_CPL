#include <Windows.h>

#include <iostream>
#include <sstream>
#include <memory>
#include <iomanip>
#include <memory>

#include <ioc.h>
#include <cpl0.hpp>


using namespace std;

int main() {
  auto cpl0 = make_shared<cpl0_c>();

  auto hwid = cpl0->GetHWID(BootGUID);
  printf("BootGUID: ");
  for (BYTE b : hwid) {
	printf("%02x", b);
  }
  printf("\n");

  while (!GetAsyncKeyState(VK_END))
  {
	  auto reports = cpl0->GetReports();
	  printf("reports: %u\n", reports.size());

	  for (auto& report : reports)
	  {
		  switch (report->Id)
		  {
		  case REPORT_ID_HYPERVISOR:
		  {
			  REPORT_HYPERVISOR* data = (REPORT_HYPERVISOR*)&report->Data;
			  printf("REPORT_ID_HYPERVISOR:\n");
			  printf("\t+ Tsc: %llu\n", data->Tsc);
		  } break;
		  case REPORT_ID_SIGNATURE:
		  {
			  REPORT_SIGNATURE* data = (REPORT_SIGNATURE*)&report->Data;
			  printf("REPORT_ID_SIGNATURE:\n");
			  printf("\t+ SigIndex: %u\n", data->SigIndex);
			  printf("\t+ PageStart: %p\n", data->PageStart);
			  printf("\t+ PageHash: ", data->PageHash);
			  for (BYTE b : hwid)
			  {
				  printf("%02x", b);
			  }
			  printf("\n");
		  } break;
		  case REPORT_ID_HASH:
		  {
			  REPORT_HASH* data = (REPORT_HASH*)&report->Data;
			  printf("REPORT_ID_HASH:\n");
			  printf("\t+ HashIndex: %u\n", data->HashIndex);
			  printf("\t+ PageStart: %p\n", data->PageStart);
		  } break;
		  case REPORT_ID_BLOCKED_PROCESS:
		  {
			  REPORT_BLOCKED_PROCESS* data = (REPORT_BLOCKED_PROCESS*)&report->Data;
			  printf("REPORT_ID_BLOCKED_PROCESS:\n");
			  printf("\t+ ProcessId: %u\n", data->ProcessId);
			  printf("\t+ ImageName: %s\n", data->ImageName);
		  } break;
		  }

		  printf("\n");
	  }

	  Sleep(1000);
  }

 

  return 0;
}