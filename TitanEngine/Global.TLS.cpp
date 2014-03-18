#include "stdafx.h"
#include "definitions.h"
#include "Global.TLS.h"

ULONG_PTR engineTLSBreakOnCallBackAddress;
bool engineTLSBreakOnCallBack = false;

void ClearTlsVector(std::vector<ULONG_PTR>* vec)
{
    std::vector<ULONG_PTR>().swap(*vec);
}