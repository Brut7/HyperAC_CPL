#ifndef H_THREADS
#define H_THREADS

#include <ntifs.h>

BOOLEAN IsThreadValid(_In_ PETHREAD Thread);
VOID DetectHiddenThreads(VOID);

#endif // H_THREADS