#ifndef _GLOBAL_TLS_H
#define _GLOBAL_TLS_H

#include <vector>

extern ULONG_PTR engineTLSBreakOnCallBackAddress;
extern bool engineTLSBreakOnCallBack;

void ClearTlsVector(std::vector<ULONG_PTR>* vec);

#endif //_GLOBAL_TLS_H