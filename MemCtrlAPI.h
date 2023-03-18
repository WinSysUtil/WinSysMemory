#pragma once
#include "MemScanEx.h"
#include "MemCtrlEx.h"

namespace MemCtrl_API {
	typedef void (*fp_Create_ScanEx)(CMemScanEx** ppObj);
	typedef void (*fp_Delete_ScanEx)(CMemScanEx** ppObj);
	typedef void (*fp_Create_CtrlEx)(CMemScanEx** ppObj);
	typedef void (*fp_Delete_CtrlnEx)(CMemScanEx** ppObj);

	void Create_ScanEx(CMemScanEx** ppObj);
	void Delete_ScanEx(CMemScanEx** ppObj);

	void Create_CtrlEx(CMemCtrlEx** ppObj);
	void Delete_CtrlEx(CMemCtrlEx** ppObj);
}
