#include "stdafx.h"
#include "definitions.h"
#include "Global.Debugger.h"
#include "Global.Engine.h"
#include "Global.Handle.h"
#include "Global.Threader.h"

static wchar_t szBackupDebuggedFileName[512];

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
    int DebugConsoleFlag = NULL;

    if(DebugDebuggingDLL)
    {
        DebugConsoleFlag = CREATE_NO_WINDOW|CREATE_SUSPENDED;
    }
    else if(engineRemoveConsoleForDebugee)
    {
        DebugConsoleFlag = CREATE_NO_WINDOW;
    }
    
    if(engineEnableDebugPrivilege)
    {
        EngineSetDebugPrivilege(GetCurrentProcess(), true);
        DebugRemoveDebugPrivilege = true;
    }
    wchar_t* szFileNameCreateProcess;
    wchar_t* szCommandLineCreateProcess;
    if(szCommandLine == NULL || !lstrlenW(szCommandLine))
    {
        szCommandLineCreateProcess=0;
        szFileNameCreateProcess=szFileName;
    }
    else
    {
        wchar_t szCreateWithCmdLine[1024];
        wsprintfW(szCreateWithCmdLine, L"\"%s\" %s", szFileName, szCommandLine);
        szCommandLineCreateProcess=szCreateWithCmdLine;
        szFileNameCreateProcess=0;
    }
    if(CreateProcessW(szFileNameCreateProcess, szCommandLineCreateProcess, NULL, NULL, false, DEBUG_PROCESS|DEBUG_ONLY_THIS_PROCESS|DebugConsoleFlag|CREATE_NEW_CONSOLE, NULL, szCurrentFolder, &dbgStartupInfo, &dbgProcessInformation))
    {
        if(engineEnableDebugPrivilege)
            EngineSetDebugPrivilege(GetCurrentProcess(), false);
        DebugAttachedToProcess = false;
        DebugAttachedProcessCallBack = NULL;
        return &dbgProcessInformation;
    }
    else
    {
        DWORD lastError = GetLastError();
        if(engineEnableDebugPrivilege)
        {
            EngineSetDebugPrivilege(GetCurrentProcess(), false);
            DebugRemoveDebugPrivilege = false;
        }
        memset(&dbgProcessInformation, 0, sizeof(PROCESS_INFORMATION));
        SetLastError(lastError);
        return 0;
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
    memset(szDebuggerName, 0, sizeof(szDebuggerName));
    if(lstrlenW(szFileName) < sizeof(szDebuggerName))
    {
        memset(szBackupDebuggedFileName, 0, sizeof(szBackupDebuggedFileName));
        lstrcpyW(szBackupDebuggedFileName, szFileName);
        szFileName = &szBackupDebuggedFileName[0];
    }
    lstrcpyW(szDebuggerName, szFileName);
    int i = lstrlenW(szDebuggerName);
    while(szDebuggerName[i] != '\\' && i)
        i--;
    wchar_t DLLLoaderName[64]=L"";
#ifdef _WIN64
    wsprintfW(DLLLoaderName, L"DLLLoader64_%.4X.exe", GetTickCount()&0xFFFF);
#else
    wsprintfW(DLLLoaderName, L"DLLLoader32_%.4X.exe", GetTickCount()&0xFFFF);
#endif
    if(i)
        lstrcpyW(szDebuggerName+i+1, DLLLoaderName);
    else
        lstrcpyW(szDebuggerName, DLLLoaderName);

#if defined(_WIN64)
    if(EngineExtractResource("LOADERX64", szDebuggerName))
#else
    if(EngineExtractResource("LOADERX86", szDebuggerName))
#endif
    {
        DebugDebuggingDLL = true;
        int i = lstrlenW(szFileName);
        while(szFileName[i] != '\\' && i)
            i--;
        DebugDebuggingDLLBase = NULL;
        DebugDebuggingMainModuleBase = NULL;
        DebugDebuggingDLLFullFileName = szFileName;
        DebugDebuggingDLLFileName = &szFileName[i+1];
        DebugModuleImageBase = (ULONG_PTR)GetPE32DataW(szFileName, NULL, UE_IMAGEBASE);
        DebugModuleEntryPoint = (ULONG_PTR)GetPE32DataW(szFileName, NULL, UE_OEP);
        DebugModuleEntryPointCallBack = EntryCallBack;
        DebugReserveModuleBase = 0;
        if(ReserveModuleBase)
            DebugReserveModuleBase = DebugModuleImageBase;
        PPROCESS_INFORMATION ReturnValue = (PPROCESS_INFORMATION)InitDebugW(szDebuggerName, szCommandLine, szCurrentFolder);
        wchar_t szName[256]=L"";
        swprintf(szName, 256, L"Global\\szLibraryName%X", (unsigned int)ReturnValue->dwProcessId);
        DebugDLLFileMapping=CreateFileMappingW(INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 512*sizeof(wchar_t), szName);
        if(DebugDLLFileMapping)
        {
            wchar_t* szLibraryPathMapping=(wchar_t*)MapViewOfFile(DebugDLLFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 512*sizeof(wchar_t));
            if(szLibraryPathMapping)
            {
                wcscpy(szLibraryPathMapping, DebugDebuggingDLLFullFileName);
                UnmapViewOfFile(szLibraryPathMapping);
            }
        }
        ResumeThread(ReturnValue->hThread);
        return ReturnValue;
    }
    return 0;
}

__declspec(dllexport) bool TITCALL StopDebug()
{
    if(dbgProcessInformation.hProcess != NULL)
    {
        TerminateThread(dbgProcessInformation.hThread, NULL);
        TerminateProcess(dbgProcessInformation.hProcess, NULL);
        Sleep(10); //allow thread switching
        return true;
    }
    return false;
}

__declspec(dllexport) bool TITCALL AttachDebugger(DWORD ProcessId, bool KillOnExit, LPVOID DebugInfo, LPVOID CallBack)
{
    typedef void(WINAPI *fDebugSetProcessKillOnExit)(bool KillExitingDebugee);
    fDebugSetProcessKillOnExit myDebugSetProcessKillOnExit;
    LPVOID funcDebugSetProcessKillOnExit = NULL;

    if(ProcessId != NULL && dbgProcessInformation.hProcess == NULL)
    {
        if(engineEnableDebugPrivilege)
        {
            EngineSetDebugPrivilege(GetCurrentProcess(), true);
            DebugRemoveDebugPrivilege = true;
        }
        if(DebugActiveProcess(ProcessId))
        {
            if(engineEnableDebugPrivilege)
                EngineSetDebugPrivilege(GetCurrentProcess(), false);
            if(KillOnExit)
            {
                funcDebugSetProcessKillOnExit = GetProcAddress(GetModuleHandleA("kernel32.dll"), "DebugSetProcessKillOnExit");
                if(funcDebugSetProcessKillOnExit != NULL)
                {
                    myDebugSetProcessKillOnExit = (fDebugSetProcessKillOnExit)(funcDebugSetProcessKillOnExit);
                    myDebugSetProcessKillOnExit(KillOnExit);
                }
            }
            DebugDebuggingDLL = false;
            DebugAttachedToProcess = true;
            DebugAttachedProcessCallBack = (ULONG_PTR)CallBack;
            engineAttachedProcessDebugInfo = DebugInfo;
            dbgProcessInformation.dwProcessId = ProcessId;
            DebugLoop();
            DebugAttachedToProcess = false;
            DebugAttachedProcessCallBack = NULL;
            return true;
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL DetachDebugger(DWORD ProcessId)
{
    typedef bool(WINAPI *fDebugActiveProcessStop)(DWORD dwProcessId);
    fDebugActiveProcessStop myDebugActiveProcessStop;
    LPVOID funcDebugActiveProcessStop = NULL;
    bool FuncReturn = false;

    RemoveAllBreakPoints(UE_OPTION_REMOVEALL);

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
            return true;
        }
        else
        {
            return false;
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL DetachDebuggerEx(DWORD ProcessId)
{
    ThreaderPauseProcess();
    int threadcount=(int)hListThread.size();
    for(int i=0; i<threadcount; i++)
    {
        HANDLE hActiveThread = OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT, false, hListThread.at(i).dwThreadId);
        CONTEXT myDBGContext;
        myDBGContext.ContextFlags = CONTEXT_CONTROL;
        GetThreadContext(hActiveThread, &myDBGContext);
        myDBGContext.EFlags &= ~UE_TRAP_FLAG;
        myDBGContext.EFlags &= ~UE_RESUME_FLAG;
        SetThreadContext(hActiveThread, &myDBGContext);
        EngineCloseHandle(hActiveThread);
    }
    ContinueDebugEvent(DBGEvent.dwProcessId, DBGEvent.dwThreadId, DBG_CONTINUE);
    ThreaderResumeProcess();
    return DetachDebugger(ProcessId);
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
    DebugReserveModuleBase = 0;
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
