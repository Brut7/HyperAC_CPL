#ifndef H_THREADS
#define H_THREADS

#include <ntifs.h>

BOOLEAN IsThreadValid(_In_ PETHREAD Thread);

VOID DetectHiddenThreads(VOID);

#pragma alloc_text(PAGE, IsThreadValid)
#pragma alloc_text(PAGE, DetectHiddenThreads)

#endif // H_THREADS