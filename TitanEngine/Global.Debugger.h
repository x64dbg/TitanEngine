#ifndef _GLOBAL_DEBUGGER_H
#define _GLOBAL_DEBUGGER_H

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

extern ULONG_PTR engineAttachedProcessCallBack;
extern bool engineAttachedToProcess;
extern ULONG_PTR engineReserveModuleBase;
extern unsigned long long engineDebuggingMainModuleBase;
extern ULONG_PTR engineDebuggingDLLBase;
extern bool engineDebuggingDLL;
extern wchar_t* engineDebuggingDLLFullFileName;
extern wchar_t* engineDebuggingDLLFileName;

long DebugLoopInSecondThread(LPVOID InputParameter);
void DebuggerReset();

#endif //_GLOBAL_DEBUGGER_H