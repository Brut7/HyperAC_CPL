#ifndef H_MAIN
#define H_MAIN

#include <ntifs.h>

VOID SigScanThread(_In_opt_ PVOID Context);
VOID MainThread(_In_opt_ PVOID Context);

#pragma alloc_text(PAGE, SigScanThread)
#pragma alloc_text(PAGE, MainThread)

#endif