#include <Windows.h>

#include <iostream>
#include <sstream>
#include <memory>
#include <iomanip>
#include <memory>

#include <ioc.h>
#include <cpl0.hpp>


using namespace std;

string Hex2String(const BYTE* Data, SIZE_T Size) {
	stringstream ss;
	ss << hex << setfill('0');
	for (size_t i = 0; i < Size; ++i) {
		ss << setw(2) << (int)Data[i];
	}

	return ss.str();
}

string GetHWID(shared_ptr<cpl0_c> cpl0, CPL0_GET_HWID_TYPE Type) {
	CPL0_GET_HWID_REQ req;
	req.Type = Type;

	CPL0_GET_HWID_RES res;
	if (!cpl0->Send(IOCTL_GET_HWID, &req, sizeof(req), &res, sizeof(res))) {
		return ""; 
	}

	return Hex2String(res.Hash, sizeof(res.Hash));
}

int main() {
  auto cpl0 = make_shared<cpl0_c>();
  printf("BootGUID: %s\n", GetHWID(cpl0, BootGUID).data());
  return 0;
}