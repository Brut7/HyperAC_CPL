#ifndef HPP_CPL0
#define HPP_CPL0

#include <Windows.h>
#include <memory>
#include <ioc.h>
#include <array>
#include <vector>

using namespace std;

class cpl0_c
{
public:
    cpl0_c();
    ~cpl0_c();

    bool IsValid() const;

    array<BYTE, SHA1_SIZE> GetHWID(CPL0_GET_HWID_TYPE Type) const;
    vector<unique_ptr<REPORT_NODE>> GetReports() const;
    SIZE_T GetReportsSize() const;

private:
    HANDLE GetHandle() const;

    DWORD Send(DWORD Code, void* InputBuffer, size_t InputSize,
        void* OutputBuffer, size_t OutputSize) const;

    HANDLE m_handle;
};

#endif  // HPP_CPL0