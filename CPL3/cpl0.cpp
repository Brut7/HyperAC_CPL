#include <cpl0.hpp>

cpl0_c::cpl0_c() {
  m_handle = CreateFileW(L"\\\\.\\HyperAC", GENERIC_READ | GENERIC_WRITE, 0,
                         NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

cpl0_c::~cpl0_c() {
  if (IsValid()) {
    CloseHandle(m_handle);
  }
}

bool cpl0_c::IsValid() const {
  return m_handle && m_handle != INVALID_HANDLE_VALUE;
}

HANDLE cpl0_c::GetHandle() const { return m_handle; }


DWORD cpl0_c::SendControl(DWORD Code, void* InputBuffer, size_t InputSize,
                          void* OutputBuffer, size_t OutputSize) const {
  if (!IsValid()) {
    return 0;
  }

  DWORD res = 0;
  if (!DeviceIoControl(m_handle, Code, InputBuffer, InputSize, OutputBuffer,
                       OutputSize, &res, NULL)) {
    return 0;
  }

  return res;
}