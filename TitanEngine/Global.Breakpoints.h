#ifndef _GLOBAL_BREAKPOINTS_H
#define _GLOBAL_BREAKPOINTS_H

#include <vector>
#include <unordered_map>

#include "Global.Engine.Threading.h"
#include "Global.Engine.h"
#include "Global.Debugger.h"


extern std::vector<BreakPointDetail> BreakPointBuffer;
extern std::unordered_map<ULONG_PTR, MemoryBreakpointPageDetail> MemoryBreakpointPages;

void uintdr7(ULONG_PTR dr7, DR7* ret);
ULONG_PTR dr7uint(DR7* dr7);
void BreakPointPostReadFilter(ULONG_PTR lpBaseAddress, unsigned char* lpBuffer, SIZE_T nSize);
void BreakPointPreWriteFilter(ULONG_PTR lpBaseAddress, SIZE_T nSize);
void BreakPointPostWriteFilter(ULONG_PTR lpBaseAddress, SIZE_T nSize);

bool IsDepEnabled(bool* outPermanent = nullptr);
DWORD GetPageProtectionForMemoryBreakpoint(const MemoryBreakpointPageDetail & page);
bool IsMemoryAccessAllowed(DWORD memProtect, ULONG_PTR accessType);

#endif //_GLOBAL_BREAKPOINTS_H
