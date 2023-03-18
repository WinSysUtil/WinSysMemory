#include "MemCtrlAPI.h"

void MemCtrl_API::Create_ScanEx(CMemScanEx** ppObj)
{
	(*ppObj) = new CMemScanEx();
}

void MemCtrl_API::Delete_ScanEx(CMemScanEx** ppObj)
{
	delete (*ppObj);
	(*ppObj) = nullptr;

}

void MemCtrl_API::Create_CtrlEx(CMemCtrlEx** ppObj)
{
	(*ppObj) = new CMemCtrlEx();
}

void MemCtrl_API::Delete_CtrlEx(CMemCtrlEx** ppObj)
{
	delete (*ppObj);
	(*ppObj) = nullptr;
}
