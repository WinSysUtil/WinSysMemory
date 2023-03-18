#include "MemCtrlEx.h"
#include <iostream>

#include<psapi.h>
#pragma comment(lib, "psapi.lib")

CMemCtrlEx g_MemCtrl;

struct AobScanData {
    DWORD dwStart;
    DWORD dwEnd;
    BYTE* SearchBytes;
    int m;
    int Result;
    DWORD dwResult;

    AobScanData(DWORD dwStart, DWORD dwEnd, BYTE* SearchBytes, int m, int Result) {
        this->dwStart = dwStart;
        this->dwEnd = dwEnd;
        this->SearchBytes = SearchBytes;
        this->m = m;
        this->Result = Result;
        this->dwResult = NULL;
    }
};

// Constructor
CMemCtrlEx::CMemCtrlEx() {
    BaseAddress = NULL;
    Memory_Start = NULL;
    Memory_End = NULL;
    MemoryDump = NULL;
    IsDLL = false;
    OldAddr = NULL;
    OldSize = NULL;
    OldProtect = NULL;
}

// Initializes CMemCtrlEx
void CMemCtrlEx::Init(char* ModuleName) {
    MODULEINFO ModInfo;
    HMODULE hModule;
    char szTemp[MaxSize];

    if (ModuleName == NULL) {
        hModule = GetModuleHandle(NULL);
    }
    else {
        hModule = GetModuleHandleA(ModuleName);
    }
    if (hModule == NULL) {
        MessageBoxA(NULL, "Could not find module.", "CMemCtrlEx", MB_ICONERROR);
        return;
    }
    GetModuleInformation(GetCurrentProcess(), hModule, &ModInfo, sizeof(MODULEINFO));
    BaseAddress = (DWORD)ModInfo.lpBaseOfDll;
    Memory_Start = BaseAddress;
    Memory_End = BaseAddress + ModInfo.SizeOfImage;
    IsDLL = (ModInfo.EntryPoint == NULL) ? true : false;
}

// Creates Memory Dump
void CMemCtrlEx::CreateMemoryDump() {
    MemoryDump = (DWORD)VirtualAlloc(NULL, Memory_End - Memory_Start, MEM_COMMIT, PAGE_READWRITE);
    memcpy((void*)MemoryDump, (void*)Memory_Start, Memory_End - Memory_Start);
}

// Scans for specific pattern of bytes
DWORD CMemCtrlEx::AobScan(char* Aob, int Result) {
    int i, j, k = 0;
    int m = strlen(Aob);
    BYTE* SearchBytes = new BYTE[m];
    memcpy(SearchBytes, Aob, m);

    DWORD dwResult = NULL;
    const int THREAD_COUNT = 4;
    HANDLE hThreads[THREAD_COUNT];
    DWORD dwThreadIds[THREAD_COUNT];
    DWORD dwChunkSize = (Memory_End - Memory_Start - m) / THREAD_COUNT;

    for (i = 0; i < THREAD_COUNT; i++) {
        DWORD dwStart = Memory_Start + i * dwChunkSize;
        DWORD dwEnd = (i == THREAD_COUNT - 1) ? Memory_End - m : dwStart + dwChunkSize - m;
        DWORD dwThreadId;
        hThreads[i] = CreateThread(NULL, NULL, (&CMemCtrlEx::AobScanThread), (LPVOID)new AobScanData(dwStart, dwEnd, SearchBytes, m, Result), 0, &dwThreadId);
        dwThreadIds[i] = dwThreadId;
    }

    WaitForMultipleObjects(THREAD_COUNT, hThreads, TRUE, INFINITE);

    for (i = 0; i < THREAD_COUNT; i++) {
        DWORD dwThreadId = dwThreadIds[i];
        AobScanData* pData = NULL;
        GetExitCodeThread(hThreads[i], (LPDWORD)&pData);
        dwResult = pData->dwResult;
        delete pData;
        CloseHandle(hThreads[i]);
    }

    delete[] SearchBytes;
    return dwResult;
}

DWORD WINAPI CMemCtrlEx::AobScanThread(LPVOID lpParam) {
    AobScanData* pData = (AobScanData*)lpParam;
    int i, j, k = 0;
    int m = pData->m;
    BYTE* SearchBytes = pData->SearchBytes;
    DWORD dwStart = pData->dwStart;
    DWORD dwEnd = pData->dwEnd;
    int Result = pData->Result;

    BYTE* DumpBytes = (BYTE*)g_MemCtrl.MemoryDump;

    for (i = dwStart; i < dwEnd; i++) {
        if (memcmp(&DumpBytes[i - g_MemCtrl.Memory_Start], SearchBytes, m) == 0) {
            if (Result == 0 || Result == 1) {
                delete pData;
                return i;
            }
            Result--;
        }
    }

    delete pData;
    return NULL;
}

// Writes to memory at specified address
bool CMemCtrlEx::MemoryWriter(DWORD dwAddr, char* Code) {
    DWORD i, j, k = 0;
    int m = strlen(Code);
    BYTE* CodeBytes = new BYTE[m / 2 + 1];

    for (i = 0; i < m; i++) {
        if (Code[i] == ' ') {
            i++;
        }
        CodeBytes[k] = (BYTE)((Code[i] >= 'A') ? (Code[i] & 0xdf) - 'A' + 10 : (Code[i] - '0'));
        i++;
        CodeBytes[k] <<= 4;
        CodeBytes[k] |= (BYTE)((Code[i] >= 'A') ? (Code[i] & 0xdf) - 'A' + 10 : (Code[i] - '0'));
        k++;
    }
    HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    WriteProcessMemory(pHandle, (void*)dwAddr, CodeBytes, m / 2, NULL);
    delete[] CodeBytes;
    return true;
}

// Restores memory at specified address
bool CMemCtrlEx::RestoreMemory(DWORD dwAddr, DWORD dwSize) {
    DWORD dwOldProtect = NULL;
    VirtualProtect((LPVOID)dwAddr, dwSize, PAGE_READWRITE, &dwOldProtect);
    memcpy((void*)dwAddr, (void*)OldAddr, OldSize);
    VirtualProtect((LPVOID)dwAddr, dwSize, OldProtect, &dwOldProtect);
    return true;
}

// Writes a hook at specified address
bool CMemCtrlEx::WriteHook(DWORD dwPrev, WORD OpCode, void(*dwNext)(), DWORD* RetAddr, DWORD dwAdd) {
    DWORD dwOldProtect = NULL;
    VirtualProtect((LPVOID)dwPrev, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    if (RetAddr != NULL) {
        *RetAddr = dwPrev + 5;
    }
    OldAddr = dwPrev;
    OldSize = 5;
    OldProtect = dwOldProtect;
    *(BYTE*)dwPrev = OpCode;
    *(DWORD*)(dwPrev + 1) = (DWORD)dwNext - dwPrev - 5 + dwAdd;
    VirtualProtect((LPVOID)dwPrev, 5, dwOldProtect, &dwOldProtect);
    return true;
}

// Gets dump information
void CMemCtrlEx::GetDumpInfo(DWORD* MS, DWORD* ME, DWORD* MD) {
    *MS = Memory_Start;
    *ME = Memory_End;
    *MD = MemoryDump;
}

// Gets Base Address
DWORD CMemCtrlEx::GetBaseAddress() {
    return BaseAddress;
}

// Hooks Pointer
void CMemCtrlEx::PointerHook(DWORD dwPointer, void(*NewFunction)(), DWORD* OldFunction) {
    DWORD dwOldProtect = NULL;
    VirtualProtect((LPVOID)dwPointer, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    if (OldFunction != NULL) {
        *OldFunction = *(DWORD*)dwPointer;
    }
    *(DWORD*)dwPointer = (DWORD)NewFunction;
    VirtualProtect((LPVOID)dwPointer, 4, dwOldProtect, &dwOldProtect);
}

// Automatically Hooks Virtual Memory
DWORD CMemCtrlEx::AutoVMHook(DWORD dwFunction, void(*dwNext)(), DWORD* RetAddr) {
    DWORD dwNew = NULL;
    MEMORY_BASIC_INFORMATION MemInfo;

    while (VirtualQuery((LPCVOID)dwFunction, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION)) == sizeof(MEMORY_BASIC_INFORMATION)) {
        if (MemInfo.Protect == PAGE_EXECUTE_READWRITE || MemInfo.Protect == PAGE_EXECUTE_WRITECOPY) {
            WriteHook((DWORD)MemInfo.BaseAddress, JMP, dwNext, RetAddr, (DWORD)dwFunction - (DWORD)MemInfo.BaseAddress - 5);
            dwNew = (DWORD)MemInfo.BaseAddress + 5;
            break;
        }
        dwFunction = (DWORD)MemInfo.BaseAddress + MemInfo.RegionSize;
    }
    return dwNew;
}
