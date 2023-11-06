#ifndef H_IO
#define H_IO

#define IOCTL_GET_HWID \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_GET_REPORTS \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_GET_REPORTS_SIZE \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define PAGE_SIZE 0x1000

#include <minwindef.h>

#define REPORT_HEADER_SIZE (sizeof(REPORT_NODE) - sizeof(BYTE))

typedef enum _REPORT_ID
{
	REPORT_ID_NONE = 0,
	REPORT_ID_HYPERVISOR,
	REPORT_ID_SIGNATURE
}REPORT_ID, * PREPORT_ID;

typedef struct _REPORT_NODE
{
	struct _REPORT_NODE* Next;
	USHORT Index;
	REPORT_ID Id;
	USHORT DataSize;
	BYTE Data[1];
}REPORT_NODE, * PREPORT_NODE;

typedef enum _CPL0_GET_HWID_TYPE {
	BootGUID,
	MonitorEDID, // TODO
}CPL0_GET_HWID_TYPE, *PCPL0_GET_HWID_TYPE;

typedef struct _CPL0_GET_HWID_REQ {
	CPL0_GET_HWID_TYPE Type;
} CPL0_GET_HWID_REQ, *PCPL0_GET_HWID_REQ;

typedef struct _CPL0_GET_HWID_RES {
	BYTE Hash[32]; // SHA256
} CPL0_GET_HWID_RES, *PCPL0_GET_HWID_RES;

typedef struct _CPL0_GET_REPORTS_REQ
{
	SIZE_T Size;
} CPL0_GET_REPORTS_REQ, * PCPL0_GET_REPORTS_REQ;

typedef struct _CPL0_GET_REPORTS_RES
{
	UCHAR Reports[1];
} CPL0_GET_REPORTS_RES, * PCPL0_GET_REPORTS_RES;

typedef struct _CPL0_GET_REPORTS_SIZE_REQ
{
	ULONG64 Nothing;
} CPL0_GET_REPORTS_SIZE_REQ, * PCPL0_GET_REPORTS_SIZE_REQ;

typedef struct _CPL0_GET_REPORTS_SIZE_RES
{
	SIZE_T Size;
} CPL0_GET_REPORTS_SIZE_RES, * PCPL0_GET_REPORTS_SIZE_RES;

typedef struct _REPORT_HYPERVISOR {
	ULONG64 Tsc;
}REPORT_HYPERVISOR, * PREPORT_HYPERVISOR;

typedef struct _REPORT_SIGNATURE
{
	ULONG64 PageStart;
	ULONG PageSize;
	UCHAR HashIndex;
}REPORT_SIGNATURE, *PREPORT_SIGNATURE;

#endif  // H_IO