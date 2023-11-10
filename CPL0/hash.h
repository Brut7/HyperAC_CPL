#ifndef H_HASH
#define H_HASH

#include <ntifs.h>

NTSTATUS MD5_Init(VOID);
NTSTATUS MD5_HashBuffer(_In_ UCHAR* Buffer, _In_ SIZE_T Size, _Out_ UCHAR Hash[16]);

NTSTATUS SHA1_Init(VOID);
NTSTATUS SHA1_HashBuffer(_In_ UCHAR* Buffer, _In_ SIZE_T Size, _Out_ UCHAR Hash[20]);

NTSTATUS SHA256_Init(VOID);
NTSTATUS SHA256_HashBuffer(_In_ UCHAR* Buffer, _In_ SIZE_T Size, _Out_ UCHAR Hash[32]);

#endif // H_HASH
