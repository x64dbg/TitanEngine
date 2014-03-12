#include "stdafx.h"
#include "definitions.h"
#include "Global.Debugger.h"
#include "Global.Handle.h"
#include "Global.Threader.h"
#include "Global.Librarian.h"

__declspec(dllexport) void TITCALL ForceClose()
{
    //manage process list
    int processcount=hListProcess.size();
    for(int i=0; i<processcount; i++)
    {
        EngineCloseHandle(hListProcess.at(i).hFile);
        EngineCloseHandle(hListProcess.at(i).hProcess);
    }
    ClearProcessList();
    //manage thread list
    int threadcount=hListThread.size();
    for(int i=0; i<threadcount; i++)
        EngineCloseHandle(hListThread.at(i).hThread);
    ClearThreadList();
    //manage library list
    int libcount=hListLibrary.size();
    for(int i=0; i<libcount; i++)
    {
        if(hListLibrary.at(i).hFile != (HANDLE)-1)
        {
            if(hListLibrary.at(i).hFileMappingView != NULL)
            {
                UnmapViewOfFile(hListLibrary.at(i).hFileMappingView);
                EngineCloseHandle(hListLibrary.at(i).hFileMapping);
            }
            EngineCloseHandle(hListLibrary.at(i).hFile);
        }
    }
    ClearLibraryList();

    if(!engineProcessIsNowDetached)
    {
        StopDebug();
    }
    RtlZeroMemory(&dbgProcessInformation, sizeof PROCESS_INFORMATION);
    if(DebugDebuggingDLL)
        DeleteFileW(szDebuggerName);
    DebugDebuggingDLL = false;
    DebugExeFileEntryPointCallBack = NULL;
}

__declspec(dllexport) void TITCALL StepInto(LPVOID StepCallBack)
{
    ULONG_PTR ueContext = NULL;

    ueContext = (ULONG_PTR)GetContextData(UE_EFLAGS);
    ueContext |= UE_TRAP_FLAG;
    SetContextData(UE_EFLAGS, ueContext);
    engineStepActive = true;
    engineStepCallBack = StepCallBack;
    engineStepCount = NULL;
}

__declspec(dllexport) void TITCALL StepOver(LPVOID StepCallBack)
{
    ULONG_PTR ueCurrentPosition = NULL;
#if !defined(_WIN64)
    ueCurrentPosition = (ULONG_PTR)GetContextData(UE_EIP);
#else
    ueCurrentPosition = GetContextData(UE_RIP);
#endif
    unsigned char instr[16];
    ReadProcessMemory(dbgProcessInformation.hProcess, (void*)ueCurrentPosition, instr, sizeof(instr), 0);
    char* DisassembledString=(char*)StaticDisassembleEx(ueCurrentPosition, (LPVOID)instr);
    if(strstr(DisassembledString, "CALL")||strstr(DisassembledString, "REP")||strstr(DisassembledString, "PUSHF"))
    {
        ueCurrentPosition+=StaticLengthDisassemble((void*)instr);
        SetBPX(ueCurrentPosition, UE_BREAKPOINT_TYPE_INT3+UE_SINGLESHOOT, StepCallBack);
    }
    else
        StepInto(StepCallBack);
}

__declspec(dllexport) void TITCALL SingleStep(DWORD StepCount, LPVOID StepCallBack)
{

    ULONG_PTR ueContext = NULL;

    ueContext = (ULONG_PTR)GetContextData(UE_EFLAGS);
    ueContext |= UE_TRAP_FLAG;
    SetContextData(UE_EFLAGS, ueContext);
    engineStepActive = true;
    engineStepCount = (int)StepCount;
    engineStepCallBack = StepCallBack;
    engineStepCount--;
}

__declspec(dllexport) void TITCALL SetNextDbgContinueStatus(DWORD SetDbgCode)
{

    if(SetDbgCode != DBG_CONTINUE)
    {
        DBGCode = DBG_EXCEPTION_NOT_HANDLED;
    }
    else
    {
        DBGCode = DBG_CONTINUE;
    }
}
