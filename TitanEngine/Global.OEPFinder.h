#ifndef _GLOBAL_OEPFINDER_H
#define _GLOBAL_OEPFINDER_H

extern GenericOEPTracerData glbEntryTracerData;

void GenericOEPVirtualProtectHit();
void GenericOEPTraceHit();
void GenericOEPTraceHited();
void GenericOEPLibraryDetailsHit();
void GenericOEPTraceInit();
bool GenericOEPFileInitW(wchar_t* szFileName, LPVOID TraceInitCallBack, LPVOID CallBack);

#endif //_GLOBAL_OEPFINDER_H