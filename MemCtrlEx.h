#pragma once
#include <Windows.h>

#define MaxSize 256

#define CALL 0xE8
#define JMP 0xE9
#define JNE 0x850F
#define JE 0x840F

/**
 * @brief CMemCtrlEx Ŭ����
 */
class CMemCtrlEx {
public:
    /**
     * @brief ������
     */
    CMemCtrlEx();

    /**
     * @brief CMemCtrlEx�� �ʱ�ȭ�ϰ� ��� ������ �����ɴϴ�.
     *
     * @param ModuleName ������ ����� �̸��Դϴ�. NULL�� ��� ���� ���μ����� �����ɴϴ�.
     */
    virtual void Init(char* ModuleName);

    /**
     * @brief �޸� ������ �����մϴ�.
     */
    virtual void CreateMemoryDump();

    /**
     * @brief �޸� �������� Ư�� ������ ����Ʈ�� �˻��մϴ�.
     *
     * @param Aob �˻��� ������ ��Ÿ���� ���ڿ��Դϴ�.
     * @param Result �˻� ������� �� ��° ���� ��ȯ������ �����մϴ�.
     * @return DWORD �˻��� �޸� �ּҸ� ��ȯ�մϴ�.
     */
    virtual DWORD AobScan(char* Aob, int Result);

    /**
     * @brief �޸� �ּ� dwAddr�� Code ���� ���ϴ�.
     *
     * @param dwAddr ���� �� �޸� �ּ��Դϴ�.
     * @param Code �� ���� ��Ÿ���� ���ڿ��Դϴ�.
     * @return true ���� ���µ� ������ ��� ��ȯ�մϴ�.
     * @return false ���� ���µ� ������ ��� ��ȯ�մϴ�.
     */
    virtual bool MemoryWriter(DWORD dwAddr, char* Code);

    /**
     * @brief �޸� �ּ� dwAddr���� dwSize ��ŭ�� �����մϴ�.
     *
     * @param dwAddr ���� ������ �޸� �ּ��Դϴ�.
     * @param dwSize ������ ���� ũ���Դϴ�.
     * @return true ���� �����ϴµ� ������ ��� ��ȯ�մϴ�.
     * @return false ���� �����ϴµ� ������ ��� ��ȯ�մϴ�.
     */
    virtual bool RestoreMemory(DWORD dwAddr, DWORD dwSize);

    /**
     * @brief dwPrev ��ġ�� dwNext �Լ��� ȣ���ϴ� Hook�� �ۼ��մϴ�.
     *
     * @param dwPrev Hook�� �ۼ��� �޸� �ּ��Դϴ�.
     * @param OpCode Hook�� �ۼ��� �ڵ��Դϴ�.
     * @param dwNext Hook���� ȣ���� �Լ��Դϴ�.
     * @param RetAddr dwPrev + 5 ���� ����Ǵ� �����Դϴ�. NULL�� ��� �����˴ϴ�.
     * @param dwAdd dwNext �Լ� ������ ����� �ּҰ��Դϴ�.
     * @return true Hook�� �ۼ��ϴµ� ������ ��� ��ȯ�մϴ�.
     * @return false Hook�� �ۼ��ϴµ� ������ ��� ��ȯ�մϴ�.
     */
    virtual bool WriteHook(DWORD dwPrev, WORD OpCode, void(*dwNext)(), DWORD* RetAddr, DWORD dwAdd);

    /**
     * @brief Memory_Start, Memory_End, MemoryDump ���� ��ȯ�մϴ�.
     *
     * @param MS �޸� ���� �ּҰ��� ������ �����Դϴ�.
     * @param ME �޸� �� �ּҰ��� ������ �����Դϴ�.
     * @param MD �޸� ���� �ּҰ��� ������ �����Դϴ�.
     */
    virtual void GetDumpInfo(DWORD* MS, DWORD* ME, DWORD* MD);

    /**
     * @brief BaseAddress ���� ��ȯ�մϴ�.
     *
     * @return DWORD BaseAddress ���� ��ȯ�մϴ�.
     */
    virtual DWORD GetBaseAddress();

    /**
     * @brief dwPointer ��ġ���� OldFunction ���� NewFunction���� �����մϴ�.
     *
     * @param dwPointer ���� ������ �޸� �ּ��Դϴ�.
     * @param NewFunction ������ �Լ��Դϴ�.
     * @param OldFunction ���� �� �Լ��� �ּ��Դϴ�. NULL�� ��� �����˴ϴ�.
     */
    virtual void PointerHook(DWORD dwPointer, void(*NewFunction)(), DWORD* OldFunction);

    /**
     * @brief VirtualQuery �Լ��� �̿��� �޸� ��ȣ �Ӽ��� Ȯ���ϰ� Hook�� �ۼ��մϴ�.
     *
     * @param dwFunction Hook�� �Լ��� �ּ��Դϴ�.
     * @param dwNext Hook���� ȣ���� �Լ��Դϴ�.
     * @param RetAddr dwPrev + 5 ���� ����Ǵ� �����Դϴ�. NULL�� ��� �����˴ϴ�.
     * @return DWORD Hook�� �ۼ��� �޸� �ּҸ� ��ȯ�մϴ�.
     */
    virtual DWORD AutoVMHook(DWORD dwFunction, void(*dwNext)(), DWORD* RetAddr);

private:
    DWORD BaseAddress; /**< ����� ���̽� �ּ��Դϴ�. */
    DWORD Memory_Start; /**< �޸� ���� �ּ��Դϴ�. */
    DWORD Memory_End; /**< �޸� �� �ּ��Դϴ�. */
    DWORD MemoryDump; /**< �޸� ���� �ּ��Դϴ�. */
    bool IsDLL; /**< DLL �����Դϴ�. */
    DWORD OldAddr; /**< ���� �ּ��Դϴ�. */
    DWORD OldSize; /**< ���� ũ���Դϴ�. */
    DWORD OldProtect; /**< ���� ��ȣ �Ӽ��Դϴ�. */
};



// �����ڵ�
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





