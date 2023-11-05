#ifndef HPP_CPL0
#define HPP_CPL0

#include <Windows.h>

#include <memory>

class cpl0_c {
 public:
  cpl0_c();
  ~cpl0_c();

  bool IsValid() const;
  HANDLE GetHandle() const;

  DWORD SendControl(DWORD Code, void* InputBuffer, size_t InputSize,
                    void* OutputBuffer, size_t OutputSize) const;

 private:
  HANDLE m_handle;
};

#endif  // HPP_CPL0