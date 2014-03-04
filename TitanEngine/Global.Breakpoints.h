#ifndef _GLOBAL_BREAKPOINTS_H
#define _GLOBAL_BREAKPOINTS_H

#include <vector>

extern std::vector<BreakPointDetail> BreakPointBuffer;

void uintdr7(ULONG_PTR dr7, DR7* ret);
ULONG_PTR dr7uint(DR7* dr7);

#endif //_GLOBAL_BREAKPOINTS_H
