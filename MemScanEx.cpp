#include "MemScanEx.h"

bool CMemScanEx::Open(const std::string& processName) {
    HANDLE snapHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapHandle == INVALID_HANDLE_VALUE)
        return false;

    PROCESSENTRY32 procEntry = {};
    procEntry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapHandle, &procEntry)) {
        do {
            std::string currentProcName = procEntry.szExeFile;
            if (currentProcName == processName) {
                handle_ = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procEntry.th32ProcessID);
                if (handle_ == nullptr)
                    return false;
#if _WIN32
                dwScanStartAddress_ = 0x0;
                dwScanEndAddress_   = 0x7FFFFFFF;
#else
                dwScanStartAddress_ = 0x0000000000000000;
                dwScanEndAddress_   = 0x7FFFFFFFFFFFFFFF;
#endif
                
                return true;
            }
        } while (Process32Next(snapHandle, &procEntry));
    }

    return false;
}

void CMemScanEx::Close()
{
    CloseHandle(handle_);
    handle_ = 0;
}

DWORD CMemScanEx::AobScan(const std::string& Aob, int Result) {
    if (handle_ == nullptr)
        return 0;

    std::vector<BYTE> scanBytes;
    std::vector<bool> wildcardBytes;
    for (size_t i = 0; i < Aob.length(); i += 3) 
    {
        if (i + 1 >= Aob.length()) break;
        
        if (Aob[i] == '?' && Aob[i + 1] == '?')
        {
            scanBytes.push_back(0);
            wildcardBytes.push_back(true);
        }
        else if (isHexChar(Aob[i]) && isHexChar(Aob[i + 1])) 
        {
            scanBytes.push_back(getByte(Aob.substr(i, 2)));
            wildcardBytes.push_back(false);
        }
    }

    SIZE_T bytesRead = 0;
    DWORD searchStart = dwScanStartAddress_;
    MEMORY_BASIC_INFORMATION memInfo;
    while (searchStart < dwScanEndAddress_ && VirtualQueryEx(handle_, (LPVOID)searchStart, &memInfo, sizeof(memInfo))) {
        if (memInfo.State == MEM_COMMIT && (memInfo.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0) {
            std::vector<BYTE> memoryData(memInfo.RegionSize);
            ReadMemory((LPVOID)memInfo.BaseAddress, memoryData.data(), memInfo.RegionSize);
            for (size_t i = 0; i < memoryData.size() - scanBytes.size(); ++i) {
                bool found = true;
                for (size_t j = 0; j < scanBytes.size(); ++j) 
                {
                    if (wildcardBytes[j] == true)
                        continue;
                    if (memoryData[i + j] != scanBytes[j]) {
                        found = false;
                        break;
                    }
                }
                if (found) {
                    if (Result == 0)
                        return (DWORD)(memInfo.BaseAddress) + i;
                    else {
                        DWORD result;
                        ReadMemory((LPVOID)((DWORD)(memInfo.BaseAddress) + i + scanBytes.size()), &result, sizeof(DWORD));
                        return result;
                    }
                }
            }
        }
        searchStart += memInfo.RegionSize;
    }

    return 0;
}

bool CMemScanEx::ReadMemory(void* lpBaseAddress, void* lpBuffer, SIZE_T nSize) {
    SIZE_T bytesRead = 0;
    return ReadProcessMemory(handle_, lpBaseAddress, lpBuffer, nSize, &bytesRead);
}

bool CMemScanEx::WriteMemory(void* lpBaseAddress, void* lpBuffer, SIZE_T nSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    SIZE_T bytesWritten = 0;
    if (VirtualProtectEx(handle_, lpBaseAddress, nSize, flNewProtect, lpflOldProtect))
        if (WriteProcessMemory(handle_, lpBaseAddress, lpBuffer, nSize, &bytesWritten))
            return true;

    return false;
}

void CMemScanEx::SetScanRange(const std::string& moduleName) {
    MODULEENTRY32 module;
    module.dwSize = sizeof(MODULEENTRY32);

    HANDLE moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(handle_));
    if (Module32First(moduleSnapshot, &module)) {
        do {
            if (moduleName == module.szModule) {
                dwScanStartAddress_ = (DWORD)module.modBaseAddr;
                dwScanEndAddress_ = dwScanStartAddress_ + module.modBaseSize;
                break;
            }
        } while (Module32Next(moduleSnapshot, &module));
    }
}

void CMemScanEx::GetScanRange(DWORD& dwStart, DWORD& dwEnd) {
    dwStart = dwScanStartAddress_;
    dwEnd = dwScanEndAddress_;
}

inline bool CMemScanEx::isHexChar(char c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

inline BYTE CMemScanEx::getByte(const std::string& byteString) {
    return (BYTE)std::stoi(byteString, nullptr, 16);
}
