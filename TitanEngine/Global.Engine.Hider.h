#ifndef _GLOBAL_ENGINE_HIDER_H
#define _GLOBAL_ENGINE_HIDER_H

bool ChangeHideDebuggerState(HANDLE hProcess, DWORD PatchAPILevel, bool Hide);
#ifndef _WIN64
bool IsThisProcessWow64();
#endif

#endif //_GLOBAL_ENGINE_HIDER_H