#include "MemCtrlEx.h"

void CMemCtrlEx::CreateMemoryDump() {
    DWORD dwStart, dwEnd;
    GetScanRange(dwStart, dwEnd);
    DWORD dwSize = dwEnd - dwStart;
    char* buffer = new char[dwSize];
    ReadMemory((void*)dwStart, buffer, dwSize);
    FILE* fp;
    
    fopen_s(&fp, "dump.bin", "wb");
    fwrite(buffer, 1, dwSize, fp);
    fclose(fp);
    delete[] buffer;
}

bool CMemCtrlEx::MemoryWriter(DWORD dwAddr, char* Code) {
    DWORD dwOldProtect = 0;
    if (WriteMemory((void*)dwAddr, Code, strlen(Code), PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
        return true;
    }
    return false;
}

bool CMemCtrlEx::RestoreMemory(DWORD dwAddr, DWORD dwSize) {
    BYTE* buffer = new BYTE[dwSize];
    memset(buffer, 0, dwSize);
    DWORD dwOldProtect = 0;
    if (WriteMemory((void*)dwAddr, buffer, dwSize, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
        return true;
    }
    return false;
}

bool CMemCtrlEx::WriteHook(DWORD dwPrev, WORD OpCode, void(*dwNext)(), DWORD* RetAddr, DWORD dwAdd) {
    DWORD dwSize = 16;
    BYTE* buffer = new BYTE[dwSize];
    memset(buffer, 0, dwSize);
    buffer[0] = (BYTE)OpCode;
    buffer[1] = (BYTE)(dwPrev - (DWORD)RetAddr - 2);
    buffer[2] = 0x90;
    memcpy(buffer + 3, &dwNext, sizeof(DWORD));
    DWORD dwOldProtect = 0;
    if (WriteMemory((void*)RetAddr, buffer, dwSize, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
        delete[] buffer;
        return true;
    }
    delete[] buffer;
    return false;
}

void CMemCtrlEx::GetDumpInfo(DWORD* MS, DWORD* ME, DWORD* MD) {
    DWORD dwStart, dwEnd;
    GetScanRange(dwStart, dwEnd);
    *MS = dwStart;
    *ME = dwEnd;
    *MD = dwEnd - dwStart;
}

void CMemCtrlEx::PointerHook(DWORD dwPointer, void(*NewFunction)(), DWORD* OldFunction) {
    DWORD dwSize = 16;
    BYTE* buffer = new BYTE[dwSize];
    memset(buffer, 0, dwSize);
    buffer[0] = 0xE9;
    DWORD dwOldProtect = 0;
    *OldFunction = AobScan("90 90 90 90 90", dwPointer);
    if (*OldFunction) {
        DWORD dwNext = *OldFunction + 5;
        DWORD dwJump = (DWORD)NewFunction - dwNext;
        memcpy(buffer + 1, &dwJump, sizeof(DWORD));
        WriteMemory((void*)*OldFunction, buffer, dwSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    }
    delete[] buffer;
}

DWORD CMemCtrlEx::AutoVMHook(DWORD dwFunction, void(*dwNext)(), DWORD* RetAddr) {
    DWORD dwSize = 16;
    BYTE* buffer = new BYTE[dwSize];
    memset(buffer, 0, dwSize);
    buffer[0] = 0x68;
    memcpy(buffer + 1, &dwNext, sizeof(DWORD));
    buffer[5] = 0xC3;
    DWORD dwOldProtect = 0;
    DWORD dwMem = AobScan("C3", dwFunction);
    if (dwMem) {
        WriteMemory((void*)dwMem, buffer, dwSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
        *RetAddr = dwMem + 5;
        delete[] buffer;
        return dwMem + 1;
    }
    delete[] buffer;
    return 0;
}
