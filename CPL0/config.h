#ifndef H_CONFIG
#define H_CONFIG

#define DebugMessage(msg, ...) \
  DbgPrintEx(0, 0, "[" __FUNCTION__ "] " msg, __VA_ARGS__)


static UNICODE_STRING g_DeviceName = RTL_CONSTANT_STRING(L"\\Device\\HyperAC");
static UNICODE_STRING g_SymbolicLinkName = RTL_CONSTANT_STRING(L"\\??\\HyperAC");

#endif// H_CONFIG