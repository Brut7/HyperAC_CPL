#ifndef H_MAIN
#define H_MAIN

#include <ntifs.h>

VOID ScannerThread(_In_opt_ PVOID Context);
VOID MainThread(_In_opt_ PVOID Context);

#pragma alloc_text(PAGE, ScannerThread)
#pragma alloc_text(PAGE, MainThread)

#endif