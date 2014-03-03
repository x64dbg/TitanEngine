#ifndef _GLOBAL_INJECTOR_H
#define _GLOBAL_INJECTOR_H

extern HANDLE engineReservedMemoryProcess;
extern ULONG_PTR engineReservedMemoryLeft[UE_MAX_RESERVED_MEMORY_LEFT];

long injectedRemoteLoadLibrary(LPVOID Parameter);
long injectedRemoteFreeLibrary(LPVOID Parameter);
long injectedRemoteFreeLibrarySimple(LPVOID Parameter);
long injectedExitProcess(LPVOID Parameter);
void injectedTerminator();
long injectedImpRec(LPVOID Parameter);

#endif //_GLOBAL_INJECTOR_H