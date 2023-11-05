#include <cpl0.hpp>

cpl0_c::cpl0_c()
{
    m_handle = CreateFileW(L"\\\\.\\HyperAC", GENERIC_READ | GENERIC_WRITE, 0,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

cpl0_c::~cpl0_c()
{
    if (IsValid())
    {
        CloseHandle(m_handle);
    }
}

bool cpl0_c::IsValid() const
{
    return m_handle && m_handle != INVALID_HANDLE_VALUE;
}

array<BYTE, 32> cpl0_c::GetHWID(CPL0_GET_HWID_TYPE Type) const
{
    CPL0_GET_HWID_REQ req;
    req.Type = Type;

    CPL0_GET_HWID_RES res;
    if (!Send(IOCTL_GET_HWID, &req, sizeof(req), &res, sizeof(res)))
    {
		return {};
    }

    array<BYTE, 32> hash;
    memcpy(hash.data(), &res.Hash, hash.size());
    return hash;
}



SIZE_T cpl0_c::GetReportsSize() const
{
    CPL0_GET_REPORTS_SIZE_REQ req;
    CPL0_GET_REPORTS_SIZE_RES res;
    return Send(IOCTL_GET_REPORTS_SIZE, &req, sizeof(req), &res, sizeof(res)) ? res.Size : 0;
}

vector<unique_ptr<REPORT_NODE>> cpl0_c::GetReports() const
{
    size_t reports_size = GetReportsSize();
    unique_ptr<char[]> reports_data(new (nothrow) char[reports_size]);
    if (!reports_data)
    {
        return {};
    }

    CPL0_GET_REPORTS_REQ req;
    req.Size = reports_size;
    if (!Send(IOCTL_GET_REPORTS, &req, sizeof(req), reports_data.get(), reports_size))
    {
        return {};
    }

    vector<unique_ptr<REPORT_NODE>> reports;
    UCHAR* cursor = (UCHAR *)reports_data.get();
    SIZE_T size_left = reports_size;

    while (size_left > 0)
    {
        REPORT_NODE* report = (REPORT_NODE*)cursor;
        SIZE_T node_size = sizeof(REPORT_NODE) - sizeof(report->Data) + report->DataSize;
        unique_ptr<REPORT_NODE> node((REPORT_NODE*)(new char[node_size]));
        if (!node)
        {
            break;
        }

        memcpy(node.get(), report, node_size);
        reports.push_back(move(node));

        cursor += node_size;
        size_left -= node_size;
    }

    return reports;
}

HANDLE cpl0_c::GetHandle() const { return m_handle; }

DWORD cpl0_c::Send(DWORD Code, void* InputBuffer, size_t InputSize,
    void* OutputBuffer, size_t OutputSize) const
{
    DWORD res = 0;
    if (!DeviceIoControl(m_handle, Code, InputBuffer, InputSize, OutputBuffer,
        OutputSize, &res, NULL))
    {
        return 0;
    }

    return res;
}