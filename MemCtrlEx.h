#pragma once
#include "MemScanEx.h"
#include <sstream>

#define MaxSize 256

#define CALL 0xE8
#define JMP 0xE9
#define JNE 0x850F
#define JE 0x840F

/**
 * @brief 메모리 제어 클래스
 */
class CMemCtrlEx : public CMemScanEx {
public:
    /**
     * @brief 생성자
     */
    CMemCtrlEx() = default;
    /**
     * @brief 생성자
     */
    virtual ~CMemCtrlEx() = default;

public:

    /**
     * @brief 메모리 덤프 생성
     */
    virtual void CreateMemoryDump();

    /**
     * @brief 메모리 쓰기
     * @param dwAddr 쓸 메모리 주소
     * @param Code 쓸 내용
     * @return 쓰기 성공 여부
     */
    virtual bool MemoryWriter(DWORD dwAddr, const char* strCode);

    /**
     * @brief 메모리 복원
     * @param dwAddr 복원할 메모리 주소
     * @param dwSize 복원할 메모리 크기
     * @return 복원 성공 여부
     */
    virtual bool RestoreMemory(DWORD dwAddr, DWORD dwSize);

    /**
     * @brief 후크 쓰기
     * @param dwPrev 이전 명령의 주소
     * @param OpCode 후크할 명령의 OpCode
     * @param dwNext 후크할 함수의 주소
     * @param RetAddr 리턴할 주소
     * @param dwAdd 추가할 값
     * @return 후크 성공 여부
     */
    virtual bool WriteHook(DWORD dwPrev, WORD OpCode, void(*dwNext)(), DWORD* RetAddr, DWORD dwAdd);

    /**
     * @brief 덤프 정보 가져오기
     * @param MS 시작 주소
     * @param ME 끝 주소
     * @param MD 덤프 크기
     */
    virtual void GetDumpInfo(DWORD* MS, DWORD* ME, DWORD* MD);

    /**
     * @brief 포인터 후크 - [개발중]
     * @param dwPointer 후크할 포인터
     * @param NewFunction 후크할 함수
     * @param OldFunction 원래 함수의 주소
     */
    virtual void PointerHook(DWORD dwPointer, void(*NewFunction)(), DWORD* OldFunction);

    /**
     * @brief 자동 VM 후크 - [개발중]
     * @param dwFunction 후크할 함수
     * @param dwNext 다음 함수의 주소
     * @param RetAddr 리턴할 주소
     * @return 후크한 함수의 주소
     */
    virtual DWORD AutoVMHook(DWORD dwFunction, void(*dwNext)(), DWORD* RetAddr);
};