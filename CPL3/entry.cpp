#include <Windows.h>

#include <iostream>
#include <memory>

#include <io.h>
#include <cpl0.hpp>


using namespace std;

int main() {
  auto cpl0 = make_unique<cpl0_c>();

  CPL0_GET_STATUS_REQ req;
  req.input = 64;

  CPL0_GET_STATUS_RES res;
  cpl0->SendControl(IOCTL_HYPERAC_GET_STATUS, &req, sizeof(req), &res,
                    sizeof(res));

  printf("%i\n", res.output);

  cpl0.reset();
  return 0;
}