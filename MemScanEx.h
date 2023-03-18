#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <cstdio>
#include <vector>
#include <string>

class CMemScanEx {
public:
    /**
    * 생성자
    */
    CMemScanEx() = default;

    /**
    * 지정된 프로세스에 대한 핸들을 엽니다.
    *
    * @param processName 열 프로세스의 이름입니다. 비어있는 경우 현재 프로세스가 가정됩니다.
    * @return 핸들이 성공적으로 열린 경우 true를 반환하고 그렇지 않은 경우 false를 반환합니다.
    */
    virtual bool Open(const std::string& processName = "");

    /**
    * 프로세스 핸들을 닫습니다.
    */
    virtual void Close();

    /**
    * 프로세스의 주소 공간에서 지정된 바이트 배열을 검색합니다.
    *
    * @param Aob 16진수 형식으로 표시된 검색할 바이트 배열입니다.
    * @param Result 반환할 결과의 수입니다. 0인 경우 모든 결과가 반환됩니다.
    * @return 첫 번째 결과의 주소 또는 결과가 없는 경우 0입니다.
    */
    virtual DWORD AobScan(const std::string& Aob, int Result = 0);

    /**
    * 프로세스의 주소 공간에서 지정된 주소에서 메모리를 읽어옵니다.
    *
    * @param lpBaseAddress 읽어올 기준이 되는 주소입니다.
    * @param lpBuffer 주소 공간에서 읽어온 데이터를 받을 버퍼 포인터입니다.
    * @param nSize 읽어올 바이트 수입니다.
    * @return 메모리를 성공적으로 읽은 경우 true를 반환하고 그렇지 않은 경우 false를 반환합니다.
    */
    virtual bool ReadMemory(void* lpBaseAddress, void* lpBuffer, SIZE_T nSize);

    /**
    * 프로세스의 주소 공간에서 지정된 주소에 메모리를 씁니다.
    *
    * @param lpBaseAddress 쓸 기준이 되는 주소입니다.
    * @param lpBuffer 쓸 데이터가 저장된 버퍼 포인터입니다.
    * @param nSize 쓸 바이트 수입니다.
    * @param flNewProtect 설정할 새로운 메모리 보호입니다.
    * @param lpflOldProtect 이전 메모리 보호를 받을 변수에 대한 포인터입니다.
    * @return 메모리를 성공적으로 쓴 경우 true를 반환하고 그렇지 않은 경우 false를 반환합니다.
    */
    virtual bool WriteMemory(void* lpBaseAddress, void* lpBuffer, SIZE_T nSize, DWORD flNewProtect, PDWORD lpflOldProtect);

    /**
    * 스캔 범위를 지정된 모듈로 설정합니다.
    *
    * @param moduleName 스캔 범위를 설정할 모듈의 이름입니다.
    */
    virtual void SetScanRange(const std::string& moduleName);

    /**
    * 스캔 범위의 시작 주소와 끝 주소를 가져옵니다.
    *
    * @param dwStart 시작 주소를 받을 변수에 대한 참조입니다.
    * @param dwEnd 끝 주소를 받을 변수에 대한 참조입니다.
    */
    virtual void GetScanRange(DWORD& dwStart, DWORD& dwEnd);

private:
    /**
    * 지정된 문자가 16진수 숫자인지 여부를 확인합니다.
    *
    * @param c 확인할 문자입니다.
    * @return 문자가 16진수 숫자인 경우 true를 반환하고 그렇지 않은 경우 false를 반환합니다.
    */
    virtual bool isHexChar(char c);

    /**
    * 두 개의 16진수 문자로 표시된 문자열을 바이트로 변환합니다.
    *
    * @param byteString 변환할 두 개의 16진수 문자열입니다.
    * @return 문자열이 나타내는 바이트입니다.
    */
    virtual BYTE getByte(const std::string& byteString);

    /**
    * 프로세스의 핸들입니다.
    */
    HANDLE handle_ = nullptr;

    /**
    * 스캔 범위의 시작 주소입니다.
    */
    DWORD dwScanStartAddress_ = 0;

    /**
    * 스캔 범위의 끝 주소입니다.
    */
    DWORD dwScanEndAddress_ = 0;
};
