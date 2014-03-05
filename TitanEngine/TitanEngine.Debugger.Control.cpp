#include "stdafx.h"
#include "definitions.h"
#include "Global.Debugger.h"
#include "Global.Handle.h"
#include "Global.Threader.h"
#include "Global.Librarian.h"
#include <vector>

__declspec(dllexport) void TITCALL ForceClose()
{
    /*wchar_t szTempName[MAX_PATH];
    wchar_t szTempFolder[MAX_PATH];*/
    PPROCESS_ITEM_DATA hListProcessPtr = NULL;
    PTHREAD_ITEM_DATA hListThreadPtr = NULL;
    PLIBRARY_ITEM_DATAW hListLibraryPtr = NULL;
    //manage lists
    if(hListProcess != NULL)
    {
        hListProcessPtr = (PPROCESS_ITEM_DATA)hListProcess;
        while(hListProcessPtr->hProcess != NULL)
        {
            __try
            {
                EngineCloseHandle(hListProcessPtr->hFile);
                EngineCloseHandle(hListProcessPtr->hProcess);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {

            }
            hListProcessPtr = (PPROCESS_ITEM_DATA)((ULONG_PTR)hListProcessPtr + sizeof PROCESS_ITEM_DATA);
        }
        RtlZeroMemory(hListProcess, MAX_DEBUG_DATA * sizeof PROCESS_ITEM_DATA);
    }

    int threadcount=hListThread.size();
    for(int i=threadcount-1; i>-1; i--)
        EngineCloseHandle(hListThread.at(i).hThread);
    ClearThreadList();

    if(hListLibrary != NULL)
    {
        hListLibraryPtr = (PLIBRARY_ITEM_DATAW)hListLibrary;
        while(hListLibraryPtr->hFile != NULL)
        {
            if(hListLibraryPtr->hFile != (HANDLE)-1)
            {
                if(hListLibraryPtr->hFileMappingView != NULL)
                {
                    UnmapViewOfFile(hListLibraryPtr->hFileMappingView);
                    EngineCloseHandle(hListLibraryPtr->hFileMapping);
                }
                EngineCloseHandle(hListLibraryPtr->hFile);
            }
            hListLibraryPtr = (PLIBRARY_ITEM_DATAW)((ULONG_PTR)hListLibraryPtr + sizeof LIBRARY_ITEM_DATAW);
        }
        RtlZeroMemory(hListLibrary, MAX_DEBUG_DATA * sizeof LIBRARY_ITEM_DATAW);
    }
    if(!engineProcessIsNowDetached)
    {
        StopDebug();
    }
    RtlZeroMemory(&dbgProcessInformation, sizeof PROCESS_INFORMATION);
    /*if(DebugDebuggingDLL)
    {
        RtlZeroMemory(&szTempName, sizeof szTempName);
        RtlZeroMemory(&szTempFolder, sizeof szTempFolder);
        if(GetTempPathW(MAX_PATH, szTempFolder) < MAX_PATH)
        {
            if(GetTempFileNameW(szTempFolder, L"DeleteTempFile", GetTickCount(), szTempName))
            {
                DeleteFileW(szTempName);
                if(!MoveFileW(szDebuggerName, szTempName))
                {
                    DeleteFileW(szDebuggerName);
                }
                else
                {
                    DeleteFileW(szTempName);
                }
            }
            RtlZeroMemory(&szTempName, sizeof szTempName);
            if(GetTempFileNameW(szTempFolder, L"DeleteTempFile", GetTickCount() + 1, szTempName))
            {
                DeleteFileW(szTempName);
                if(!MoveFileW(szReserveModuleName, szTempName))
                {
                    DeleteFileW(szReserveModuleName);
                }
                else
                {
                    DeleteFileW(szTempName);
                }
            }
        }
    }*/
    DebugDebuggingDLL = false;
    DebugExeFileEntryPointCallBack = NULL;
}

__declspec(dllexport) void TITCALL StepInto(LPVOID StepCallBack)
{
    ULONG_PTR ueContext = NULL;

    ueContext = (ULONG_PTR)GetContextData(UE_EFLAGS);
    if(!(ueContext & 0x100))
    {
        ueContext = ueContext ^ 0x100;
    }
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
    if(!(ueContext & 0x100))
    {
        ueContext = ueContext ^ 0x100;
    }
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
