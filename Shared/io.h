#ifndef H_IO
#define H_IO

#define IOCTL_HYPERAC_GET_STATUS \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _CPL0_GET_STATUS_REQ {
  int input;
} CPL0_GET_STATUS_REQ, *PCPL0_GET_STATUS_REQ;

typedef struct _CPL0_GET_STATUS_RES {
  int output;
} CPL0_GET_STATUS_RES, *PCPL0_GET_STATUS_RES;

#endif  // H_IO