#include "hash.h"
#include "config.h"
#include "config.h"
#include <bcrypt.h>

NTSTATUS MD5_Init(VOID)
{
    PAGED_CODE();

    NTSTATUS status = STATUS_SUCCESS;

    status = BCryptOpenAlgorithmProvider(&g_hAlgorithm_MD5, BCRYPT_MD5_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = BCryptCreateHash(g_hAlgorithm_MD5, &g_hHash_MD5, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(g_hAlgorithm_MD5, 0);
        return status;
    }

    return status;
}

NTSTATUS MD5_HashBuffer(_In_ UCHAR* Buffer, _In_ SIZE_T Size, _Out_ UCHAR Hash[16])
{
    PAGED_CODE();

    NTSTATUS status = STATUS_SUCCESS;

    status = BCryptHashData(g_hHash_MD5, Buffer, Size, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = BCryptFinishHash(g_hHash_MD5, Hash, 16, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    BCryptDestroyHash(g_hHash_MD5);
    status = BCryptCreateHash(g_hAlgorithm_MD5, &g_hHash_MD5, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(g_hAlgorithm_MD5, 0);
        return status;
    }

    return status;
}

NTSTATUS SHA1_Init(VOID)
{
    PAGED_CODE();

    NTSTATUS status = STATUS_SUCCESS;

    status = BCryptOpenAlgorithmProvider(&g_hAlgorithm_SHA1, BCRYPT_SHA1_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = BCryptCreateHash(g_hAlgorithm_SHA1, &g_hHash_SHA1, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(g_hAlgorithm_SHA1, 0);
        return status;
    }

    return status;
}

NTSTATUS SHA1_HashBuffer(_In_ UCHAR* Buffer, _In_ SIZE_T Size, _Out_ UCHAR Hash[20])
{
    PAGED_CODE();

    NTSTATUS status = STATUS_SUCCESS;

    status = BCryptHashData(g_hHash_SHA1, Buffer, Size, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = BCryptFinishHash(g_hHash_SHA1, Hash, 20, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    BCryptDestroyHash(g_hHash_SHA1);
    status = BCryptCreateHash(g_hAlgorithm_SHA1, &g_hHash_SHA1, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(g_hAlgorithm_SHA1, 0);
        return status;
    }

    return status;
}