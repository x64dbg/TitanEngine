#ifndef _GLOBAL_BREAKPOINTS_H
#define _GLOBAL_BREAKPOINTS_H

extern int BreakPointSetCount;
extern BreakPointDetail BreakPointBuffer[MAXIMUM_BREAKPOINTS];

void uintdr7(ULONG_PTR dr7, DR7* ret);
ULONG_PTR dr7uint(DR7* dr7);

#endif //_GLOBAL_BREAKPOINTS_H