#ifndef H_MAIN
#define H_MAIN

#include <ntifs.h>

VOID MainThread(_In_opt_ PVOID Context);

#pragma alloc_text(PAGE, MainThread)

#endif