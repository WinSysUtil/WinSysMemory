#pragma once
#include <Windows.h>

#define MaxSize 256

#define CALL 0xE8
#define JMP 0xE9
#define JNE 0x850F
#define JE 0x840F

/**
 * @brief CMemCtrlEx 클래스
 */
class CMemCtrlEx {
public:
    /**
     * @brief 생성자
     */
    CMemCtrlEx();

    /**
     * @brief CMemCtrlEx를 초기화하고 모듈 정보를 가져옵니다.
     *
     * @param ModuleName 가져올 모듈의 이름입니다. NULL일 경우 현재 프로세스를 가져옵니다.
     */
    virtual void Init(char* ModuleName);

    /**
     * @brief 메모리 덤프를 생성합니다.
     */
    virtual void CreateMemoryDump();

    /**
     * @brief 메모리 덤프에서 특정 패턴의 바이트를 검색합니다.
     *
     * @param Aob 검색할 패턴을 나타내는 문자열입니다.
     * @param Result 검색 결과에서 몇 번째 값을 반환할지를 결정합니다.
     * @return DWORD 검색된 메모리 주소를 반환합니다.
     */
    virtual DWORD AobScan(char* Aob, int Result);

    /**
     * @brief 메모리 주소 dwAddr에 Code 값을 씁니다.
     *
     * @param dwAddr 값을 쓸 메모리 주소입니다.
     * @param Code 쓸 값을 나타내는 문자열입니다.
     * @return true 값을 쓰는데 성공한 경우 반환합니다.
     * @return false 값을 쓰는데 실패한 경우 반환합니다.
     */
    virtual bool MemoryWriter(DWORD dwAddr, char* Code);

    /**
     * @brief 메모리 주소 dwAddr부터 dwSize 만큼을 복원합니다.
     *
     * @param dwAddr 값을 복원할 메모리 주소입니다.
     * @param dwSize 복원할 값의 크기입니다.
     * @return true 값을 복원하는데 성공한 경우 반환합니다.
     * @return false 값을 복원하는데 실패한 경우 반환합니다.
     */
    virtual bool RestoreMemory(DWORD dwAddr, DWORD dwSize);

    /**
     * @brief dwPrev 위치에 dwNext 함수를 호출하는 Hook을 작성합니다.
     *
     * @param dwPrev Hook을 작성할 메모리 주소입니다.
     * @param OpCode Hook을 작성할 코드입니다.
     * @param dwNext Hook에서 호출할 함수입니다.
     * @param RetAddr dwPrev + 5 값이 저장되는 변수입니다. NULL일 경우 생략됩니다.
     * @param dwAdd dwNext 함수 내에서 계산할 주소값입니다.
     * @return true Hook을 작성하는데 성공한 경우 반환합니다.
     * @return false Hook을 작성하는데 실패한 경우 반환합니다.
     */
    virtual bool WriteHook(DWORD dwPrev, WORD OpCode, void(*dwNext)(), DWORD* RetAddr, DWORD dwAdd);

    /**
     * @brief Memory_Start, Memory_End, MemoryDump 값을 반환합니다.
     *
     * @param MS 메모리 시작 주소값을 저장할 변수입니다.
     * @param ME 메모리 끝 주소값을 저장할 변수입니다.
     * @param MD 메모리 덤프 주소값을 저장할 변수입니다.
     */
    virtual void GetDumpInfo(DWORD* MS, DWORD* ME, DWORD* MD);

    /**
     * @brief BaseAddress 값을 반환합니다.
     *
     * @return DWORD BaseAddress 값을 반환합니다.
     */
    virtual DWORD GetBaseAddress();

    /**
     * @brief dwPointer 위치에서 OldFunction 값을 NewFunction으로 변경합니다.
     *
     * @param dwPointer 값을 변경할 메모리 주소입니다.
     * @param NewFunction 변경할 함수입니다.
     * @param OldFunction 변경 전 함수의 주소입니다. NULL일 경우 생략됩니다.
     */
    virtual void PointerHook(DWORD dwPointer, void(*NewFunction)(), DWORD* OldFunction);

    /**
     * @brief VirtualQuery 함수를 이용해 메모리 보호 속성을 확인하고 Hook을 작성합니다.
     *
     * @param dwFunction Hook할 함수의 주소입니다.
     * @param dwNext Hook에서 호출할 함수입니다.
     * @param RetAddr dwPrev + 5 값이 저장되는 변수입니다. NULL일 경우 생략됩니다.
     * @return DWORD Hook이 작성된 메모리 주소를 반환합니다.
     */
    virtual DWORD AutoVMHook(DWORD dwFunction, void(*dwNext)(), DWORD* RetAddr);

private:
    DWORD BaseAddress; /**< 모듈의 베이스 주소입니다. */
    DWORD Memory_Start; /**< 메모리 시작 주소입니다. */
    DWORD Memory_End; /**< 메모리 끝 주소입니다. */
    DWORD MemoryDump; /**< 메모리 덤프 주소입니다. */
    bool IsDLL; /**< DLL 여부입니다. */
    DWORD OldAddr; /**< 이전 주소입니다. */
    DWORD OldSize; /**< 이전 크기입니다. */
    DWORD OldProtect; /**< 이전 보호 속성입니다. */
};



// 예제코드
/**

int main(){
    AirMemory am;
    am.Init(NULL);
    am.CreateMemoryDump();
    DWORD ms, me, md;
    am.GetDumpInfo(&ms, &me, &md);
    DWORD addr = am.AobScan("90 90 90 90 90", 1);
    std::cout << "Address found: " << std::hex << addr << std::endl;
    if (addr != NULL){
        am.MemoryWriter(addr, "90 90 90 90 90");
    }
    am.RestoreMemory(addr, 5);
    std::cout << "Restored memory at address: " << std::hex << addr << std::endl;
    return 0;
}

 */





