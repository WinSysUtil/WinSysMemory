#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <cstdio>
#include <vector>
#include <string>

#ifdef min
#undef min
#endif

class CMemScanEx {
public:
    CMemScanEx() = default;

    bool Open(const std::string& processName = "");
    void Close();
    DWORD AobScan(const std::string& Aob, int Result = 0);
    bool ReadMemory(void* lpBaseAddress, void* lpBuffer, SIZE_T nSize);
    bool WriteMemory(void* lpBaseAddress, void* lpBuffer, SIZE_T nSize, DWORD flNewProtect, PDWORD lpflOldProtect);
    void SetScanRange(const std::string& moduleName);
    void GetScanRange(DWORD& dwStart, DWORD& dwEnd);

private:
    inline bool isHexChar(char c);
    inline BYTE getByte(const std::string& byteString);

    HANDLE handle_ = nullptr;
    DWORD dwScanStartAddress_ = 0;
    DWORD dwScanEndAddress_ = 0;
};