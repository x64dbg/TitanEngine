#include "stdafx.h"
#include "definitions.h"
#include "Global.Debugger.h"
#include "Global.Engine.h"
#include "Global.Handle.h"
#include "Global.Breakpoints.h"
#include "Global.Threader.h"

static wchar_t szBackupDebuggedFileName[512];
static wchar_t szDebuggerName[512];

// TitanEngine.Debugger.functions:
__declspec(dllexport) void* TITCALL InitDebug(char* szFileName, char* szCommandLine, char* szCurrentFolder)
{

    wchar_t* PtrUniFileName = NULL;
    wchar_t uniFileName[MAX_PATH] = {};
    wchar_t* PtrUniCommandLine = NULL;
    wchar_t uniCommandLine[MAX_PATH] = {};
    wchar_t* PtrUniCurrentFolder = NULL;
    wchar_t uniCurrentFolder[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        MultiByteToWideChar(CP_ACP, NULL, szCommandLine, lstrlenA(szCommandLine)+1, uniCommandLine, sizeof(uniCommandLine)/(sizeof(uniCommandLine[0])));
        MultiByteToWideChar(CP_ACP, NULL, szCurrentFolder, lstrlenA(szCurrentFolder)+1, uniCurrentFolder, sizeof(uniCurrentFolder)/(sizeof(uniCurrentFolder[0])));
        if(szFileName != NULL)
        {
            PtrUniFileName = &uniFileName[0];
        }
        if(szCommandLine != NULL)
        {
            PtrUniCommandLine = &uniCommandLine[0];
        }
        if(szCurrentFolder != NULL)
        {
            PtrUniCurrentFolder = &uniCurrentFolder[0];
        }
        return(InitDebugW(PtrUniFileName, PtrUniCommandLine, PtrUniCurrentFolder));
    }
    else
    {
        return NULL;
    }
}
__declspec(dllexport) void* TITCALL InitDebugW(wchar_t* szFileName, wchar_t* szCommandLine, wchar_t* szCurrentFolder)
{

    wchar_t szCreateWithCmdLine[1024];
    int DebugConsoleFlag = NULL;

    DebuggerReset();
    if(engineRemoveConsoleForDebugee)
    {
        DebugConsoleFlag = CREATE_NO_WINDOW;
    }
    BreakPointSetCount = 0;
    RtlZeroMemory(&BreakPointBuffer, sizeof BreakPointBuffer);
    if(szCommandLine == NULL)
    {
        if(CreateProcessW(szFileName, NULL, NULL, NULL, false, DEBUG_PROCESS|DEBUG_ONLY_THIS_PROCESS|DebugConsoleFlag|CREATE_NEW_CONSOLE, NULL, szCurrentFolder, &dbgStartupInfo, &dbgProcessInformation))
        {
            DebugAttachedToProcess = false;
            DebugAttachedProcessCallBack = NULL;
            RtlZeroMemory(&BreakPointBuffer, sizeof BreakPointBuffer);
            return(&dbgProcessInformation);
        }
        else
        {
            RtlZeroMemory(&dbgProcessInformation,sizeof PROCESS_INFORMATION);
            return(0);
        }
    }
    else
    {
        wsprintfW(szCreateWithCmdLine, L"\"%s\" %s", szFileName, szCommandLine);
        if(CreateProcessW(NULL, szCreateWithCmdLine, NULL, NULL, false, DEBUG_PROCESS|DEBUG_ONLY_THIS_PROCESS|DebugConsoleFlag|CREATE_NEW_CONSOLE, NULL, szCurrentFolder, &dbgStartupInfo, &dbgProcessInformation))
        {
            DebugAttachedToProcess = false;
            DebugAttachedProcessCallBack = NULL;
            RtlZeroMemory(&BreakPointBuffer, sizeof BreakPointBuffer);
            return(&dbgProcessInformation);
        }
        else
        {
            RtlZeroMemory(&dbgProcessInformation,sizeof PROCESS_INFORMATION);
            return(0);
        }
    }
}
__declspec(dllexport) void* TITCALL InitDebugEx(char* szFileName, char* szCommandLine, char* szCurrentFolder, LPVOID EntryCallBack)
{
    DebugExeFileEntryPointCallBack = EntryCallBack;
    return(InitDebug(szFileName, szCommandLine, szCurrentFolder));
}
__declspec(dllexport) void* TITCALL InitDebugExW(wchar_t* szFileName, wchar_t* szCommandLine, wchar_t* szCurrentFolder, LPVOID EntryCallBack)
{
    DebugExeFileEntryPointCallBack = EntryCallBack;
    return(InitDebugW(szFileName, szCommandLine, szCurrentFolder));
}
__declspec(dllexport) void* TITCALL InitDLLDebug(char* szFileName, bool ReserveModuleBase, char* szCommandLine, char* szCurrentFolder, LPVOID EntryCallBack)
{

    wchar_t* PtrUniFileName = NULL;
    wchar_t uniFileName[MAX_PATH] = {};
    wchar_t* PtrUniCommandLine = NULL;
    wchar_t uniCommandLine[MAX_PATH] = {};
    wchar_t* PtrUniCurrentFolder = NULL;
    wchar_t uniCurrentFolder[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        MultiByteToWideChar(CP_ACP, NULL, szCommandLine, lstrlenA(szCommandLine)+1, uniCommandLine, sizeof(uniCommandLine)/(sizeof(uniCommandLine[0])));
        MultiByteToWideChar(CP_ACP, NULL, szCurrentFolder, lstrlenA(szCurrentFolder)+1, uniCurrentFolder, sizeof(uniCurrentFolder)/(sizeof(uniCurrentFolder[0])));
        if(szFileName != NULL)
        {
            PtrUniFileName = &uniFileName[0];
        }
        if(szCommandLine != NULL)
        {
            PtrUniCommandLine = &uniCommandLine[0];
        }
        if(szCurrentFolder != NULL)
        {
            PtrUniCurrentFolder = &uniCurrentFolder[0];
        }
        return(InitDLLDebugW(PtrUniFileName, ReserveModuleBase, PtrUniCommandLine, PtrUniCurrentFolder, EntryCallBack));
    }
    else
    {
        return NULL;
    }
}
__declspec(dllexport) void* TITCALL InitDLLDebugW(wchar_t* szFileName, bool ReserveModuleBase, wchar_t* szCommandLine, wchar_t* szCurrentFolder, LPVOID EntryCallBack)
{

    int i = NULL;
    int j = NULL;
    bool ReturnData = false;
    DebugReserveModuleBase = NULL;

    RtlZeroMemory(&szDebuggerName, sizeof szDebuggerName);
    if(lstrlenW(szFileName) < 512)
    {
        RtlZeroMemory(&szBackupDebuggedFileName, sizeof szBackupDebuggedFileName);
        lstrcpyW(szBackupDebuggedFileName, szFileName);
        szFileName = &szBackupDebuggedFileName[0];
    }
    lstrcpyW(szDebuggerName, szFileName);
    i = lstrlenW(szDebuggerName);
    while(szDebuggerName[i] != 0x5C && i >= NULL)
    {
        i--;
    }
    if(i > NULL)
    {
        szDebuggerName[i+1] = 0x00;
#ifdef _WIN64
        lstrcpyW(szDebuggerName, L"DLLLoader64.exe");
#else
        lstrcpyW(szDebuggerName, L"DLLLoader32.exe");
#endif
    }
    else
    {
#ifdef _WIN64
        lstrcpyW(szDebuggerName, L"DLLLoader64.exe");
#else
        lstrcpyW(szDebuggerName, L"DLLLoader32.exe");
#endif
    }
    //RtlZeroMemory(&szReserveModuleName, sizeof szReserveModuleName);
    //lstrcpyW(szReserveModuleName, szFileName);
    //lstrcatW(szReserveModuleName, L".module");
#if defined(_WIN64)
    ReturnData = EngineExtractResource("LOADERx64", szDebuggerName);
    /*if(ReserveModuleBase)
    {
        EngineExtractResource("MODULEx64", szReserveModuleName);
    }*/
#else
    ReturnData = EngineExtractResource("LOADERx86", szDebuggerName);
    /*if(ReserveModuleBase)
    {
        EngineExtractResource("MODULEx86", szReserveModuleName);
    }*/
#endif
    if(ReturnData)
    {
        DebugDebuggingDLL = true;
        i = lstrlenW(szFileName);
        while(szFileName[i] != 0x5C && i >= NULL)
        {
            i--;
        }
        /*j = lstrlenW(szReserveModuleName);
        while(szReserveModuleName[j] != 0x5C && j >= NULL)
        {
            j--;
        }*/
        DebugDebuggingDLLBase = NULL;
        DebugDebuggingMainModuleBase = NULL;
        DebugDebuggingDLLFullFileName = szFileName;
        DebugDebuggingDLLFileName = &szFileName[i+1];
        //DebugDebuggingDLLReserveFileName = &szReserveModuleName[j+1];
        DebugModuleImageBase = (ULONG_PTR)GetPE32DataW(szFileName, NULL, UE_IMAGEBASE);
        DebugReserveModuleBase = DebugModuleImageBase;
        DebugModuleEntryPoint = (ULONG_PTR)GetPE32DataW(szFileName, NULL, UE_OEP);
        DebugModuleEntryPointCallBack = EntryCallBack;
        /*if(ReserveModuleBase)
        {
            RelocaterChangeFileBaseW(szReserveModuleName, DebugModuleImageBase);
        }*/
        return(InitDebugW(szDebuggerName, szCommandLine, szCurrentFolder));
    }
    else
    {
        return(NULL);
    }
    return(NULL);
}
__declspec(dllexport) bool TITCALL StopDebug()
{
    if(dbgProcessInformation.hProcess != NULL)
    {
        TerminateThread(dbgProcessInformation.hThread, NULL);
        TerminateProcess(dbgProcessInformation.hProcess, NULL);
        return(true);
    }
    else
    {
        return(false);
    }
}

__declspec(dllexport) bool TITCALL AttachDebugger(DWORD ProcessId, bool KillOnExit, LPVOID DebugInfo, LPVOID CallBack)
{

    typedef void(WINAPI *fDebugSetProcessKillOnExit)(bool KillExitingDebugee);
    fDebugSetProcessKillOnExit myDebugSetProcessKillOnExit;
    LPVOID funcDebugSetProcessKillOnExit = NULL;

    if(ProcessId != NULL && dbgProcessInformation.hProcess == NULL)
    {
        RtlZeroMemory(&BreakPointBuffer, sizeof BreakPointBuffer);
        if(DebugActiveProcess(ProcessId))
        {
            if(KillOnExit)
            {
                funcDebugSetProcessKillOnExit = GetProcAddress(GetModuleHandleA("kernel32.dll"), "DebugSetProcessKillOnExit");
                if(funcDebugSetProcessKillOnExit != NULL)
                {
                    myDebugSetProcessKillOnExit = (fDebugSetProcessKillOnExit)(funcDebugSetProcessKillOnExit);
                    myDebugSetProcessKillOnExit(KillOnExit);
                }
            }
            BreakPointSetCount = 0;
            DebugDebuggingDLL = false;
            DebugAttachedToProcess = true;
            DebugAttachedProcessCallBack = (ULONG_PTR)CallBack;
            engineAttachedProcessDebugInfo = DebugInfo;
            dbgProcessInformation.dwProcessId = ProcessId;
            DebugLoop();
            DebugAttachedToProcess = false;
            DebugAttachedProcessCallBack = NULL;
            return(true);
        }
    }
    else
    {
        return(false);
    }
    return(false);
}

__declspec(dllexport) bool TITCALL DetachDebugger(DWORD ProcessId)
{
    typedef bool(WINAPI *fDebugActiveProcessStop)(DWORD dwProcessId);
    fDebugActiveProcessStop myDebugActiveProcessStop;
    LPVOID funcDebugActiveProcessStop = NULL;
    bool FuncReturn = false;

    if(ProcessId != NULL)
    {
        funcDebugActiveProcessStop = GetProcAddress(GetModuleHandleA("kernel32.dll"), "DebugActiveProcessStop");
        if(funcDebugActiveProcessStop != NULL)
        {
            myDebugActiveProcessStop = (fDebugActiveProcessStop)(funcDebugActiveProcessStop);
            FuncReturn = myDebugActiveProcessStop(ProcessId);
            engineProcessIsNowDetached = true;
            Sleep(250);
        }
        DebugAttachedToProcess = false;
        if(FuncReturn)
        {
            return(true);
        }
        else
        {
            return(false);
        }
    }
    return(false);
}

__declspec(dllexport) bool TITCALL DetachDebuggerEx(DWORD ProcessId)
{

    HANDLE hActiveThread;
    CONTEXT myDBGContext;
    PTHREAD_ITEM_DATA hListThreadPtr = (PTHREAD_ITEM_DATA)hListThread;

    if(hListThreadPtr != NULL)
    {
        ThreaderPauseProcess();
        while(hListThreadPtr->hThread != NULL)
        {
            hActiveThread = OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_QUERY_INFORMATION, false, hListThreadPtr->dwThreadId);
            myDBGContext.ContextFlags = CONTEXT_CONTROL;
            GetThreadContext(hActiveThread, &myDBGContext);
            if((myDBGContext.EFlags & 0x100))
            {
                myDBGContext.EFlags = myDBGContext.EFlags ^ 0x100;
            }
            if(!(myDBGContext.EFlags & 0x10000))
            {
                myDBGContext.EFlags = myDBGContext.EFlags ^ 0x10000;
            }
            SetThreadContext(hActiveThread, &myDBGContext);
            EngineCloseHandle(hActiveThread);
            hListThreadPtr = (PTHREAD_ITEM_DATA)((ULONG_PTR)hListThreadPtr + sizeof THREAD_ITEM_DATA);
        }
        ContinueDebugEvent(DBGEvent.dwProcessId, DBGEvent.dwThreadId, DBG_CONTINUE);
        ThreaderResumeProcess();
        return(DetachDebugger(ProcessId));
    }
    else
    {
        return(false);
    }
}

__declspec(dllexport) void TITCALL AutoDebugEx(char* szFileName, bool ReserveModuleBase, char* szCommandLine, char* szCurrentFolder, DWORD TimeOut, LPVOID EntryCallBack)
{

    wchar_t* PtrUniFileName = NULL;
    wchar_t uniFileName[MAX_PATH] = {};
    wchar_t* PtrUniCommandLine = NULL;
    wchar_t uniCommandLine[MAX_PATH] = {};
    wchar_t* PtrUniCurrentFolder = NULL;
    wchar_t uniCurrentFolder[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        MultiByteToWideChar(CP_ACP, NULL, szCommandLine, lstrlenA(szCommandLine)+1, uniCommandLine, sizeof(uniCommandLine)/(sizeof(uniCommandLine[0])));
        MultiByteToWideChar(CP_ACP, NULL, szCurrentFolder, lstrlenA(szCurrentFolder)+1, uniCurrentFolder, sizeof(uniCurrentFolder)/(sizeof(uniCurrentFolder[0])));
        if(szFileName != NULL)
        {
            PtrUniFileName = &uniFileName[0];
        }
        if(szCommandLine != NULL)
        {
            PtrUniCommandLine = &uniCommandLine[0];
        }
        if(szCurrentFolder != NULL)
        {
            PtrUniCurrentFolder = &uniCurrentFolder[0];
        }
        return(AutoDebugExW(PtrUniFileName, ReserveModuleBase, PtrUniCommandLine, PtrUniCurrentFolder, TimeOut, EntryCallBack));
    }
}

__declspec(dllexport) void TITCALL AutoDebugExW(wchar_t* szFileName, bool ReserveModuleBase, wchar_t* szCommandLine, wchar_t* szCurrentFolder, DWORD TimeOut, LPVOID EntryCallBack)
{
    DebugReserveModuleBase = NULL;
    DWORD ThreadId;
    DWORD ExitCode = 0;
    HANDLE hSecondThread;
    bool FileIsDll = false;
#if !defined(_WIN64)
    PE32Struct PEStructure;
#else
    PE64Struct PEStructure;
#endif

    if(TimeOut == NULL)
    {
        TimeOut = INFINITE;
    }

    if(szFileName != NULL)
    {
        RtlZeroMemory(&expertDebug, sizeof ExpertDebug);
        expertDebug.ExpertModeActive = true;
        expertDebug.szFileName = szFileName;
        expertDebug.szCommandLine = szCommandLine;
        expertDebug.szCurrentFolder = szCurrentFolder;
        expertDebug.ReserveModuleBase = ReserveModuleBase;
        expertDebug.EntryCallBack = EntryCallBack;
        GetPE32DataExW(szFileName, (LPVOID)&PEStructure);
        if(PEStructure.Characteristics & 0x2000)
        {
            FileIsDll = true;
        }
        SetDebugLoopTimeOut(TimeOut);
        hSecondThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)DebugLoopInSecondThread, (LPVOID)FileIsDll, NULL, &ThreadId);
        WaitForSingleObject(hSecondThread, INFINITE);
        if(GetExitCodeThread(hSecondThread, &ExitCode))
        {
            if(ExitCode == -1)
            {
                ForceClose();
            }
        }
        RtlZeroMemory(&expertDebug, sizeof ExpertDebug);
        SetDebugLoopTimeOut(INFINITE);
    }
}