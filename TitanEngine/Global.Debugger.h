#ifndef _GLOBAL_DEBUGGER_H
#define _GLOBAL_DEBUGGER_H

#include <vector>

extern HARDWARE_DATA DebugRegister[4];
extern PROCESS_INFORMATION dbgProcessInformation;
extern CustomHandler myDBGCustomHandler;
extern PCustomHandler DBGCustomHandler;
extern ExpertDebug expertDebug;
extern STARTUPINFOW dbgStartupInfo;
extern LPVOID DebugModuleEntryPointCallBack;
extern LPVOID DebugExeFileEntryPointCallBack;
extern ULONG_PTR DebugModuleEntryPoint;
extern ULONG_PTR DebugModuleImageBase;
extern ULONG_PTR DebugAttachedProcessCallBack;
extern bool DebugAttachedToProcess;
extern ULONG_PTR DebugReserveModuleBase;
extern ULONG_PTR DebugDebuggingMainModuleBase;
extern ULONG_PTR DebugDebuggingDLLBase;
extern bool DebugDebuggingDLL;
extern wchar_t* DebugDebuggingDLLFullFileName;
extern wchar_t* DebugDebuggingDLLFileName;
extern DEBUG_EVENT DBGEvent;
extern DEBUG_EVENT TerminateDBGEvent;
extern DWORD ProcessExitCode;
extern HANDLE DBGFileHandle;
extern ULONG_PTR tlsCallBackList[100];
extern std::vector<PROCESS_ITEM_DATA> hListProcess;
extern int engineStepCount;
extern LPVOID engineStepCallBack;
extern bool engineStepActive;
extern bool engineProcessIsNowDetached;
extern DWORD DBGCode;
extern bool engineFileIsBeingDebugged;
extern ULONG_PTR engineFakeDLLHandle;
extern LPVOID engineAttachedProcessDebugInfo;
extern wchar_t szDebuggerName[512];
extern bool DebugStepFinal = false;
extern LPVOID StepOutCallBack = 0;

long DebugLoopInSecondThread(LPVOID InputParameter);
void DebuggerReset();
void ClearProcessList();
void StepOutStepCallBack();

#endif //_GLOBAL_DEBUGGER_H
