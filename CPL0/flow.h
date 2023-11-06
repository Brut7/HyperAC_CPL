#ifndef H_FLOW
#define H_FLOW

#include <ntifs.h>

VOID Sleep(_In_ LONG64 Milliseconds);

#pragma alloc_text(PAGE, Sleep)

#endif // H_FLOW