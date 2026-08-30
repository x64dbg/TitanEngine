#include "stdafx.h"
#include "definitions.h"
#include "Global.Handle.h"
#include "Global.Engine.h"

// TitanEngine.Process.functions:
__declspec(dllexport) long TITCALL GetActiveProcessId(char* szImageName)
{
    wchar_t uniImageName[MAX_PATH] = {0};

    if(szImageName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szImageName, -1, uniImageName, _countof(uniImageName));
        return(GetActiveProcessIdW(uniImageName));
    }
    else
    {
        return(NULL);
    }
}

__declspec(dllexport) long TITCALL GetActiveProcessIdW(wchar_t* szImageName)
{

    int i;
    wchar_t* szTranslatedProcName;
    DWORD bProcessId[1024] = {};
    wchar_t szProcessPath[1024] = {};
    DWORD cbNeeded = NULL;
    HANDLE hProcess;
    wchar_t* nameOnly = 0;

    if(EnumProcesses(bProcessId, sizeof(bProcessId), &cbNeeded))
    {
        for(i = 0; i < (int)(cbNeeded / sizeof(DWORD)); i++)
        {
            if(bProcessId[i] != NULL)
            {
                hProcess = EngineOpenProcess(PROCESS_QUERY_INFORMATION, false, bProcessId[i]);
                if(hProcess != NULL)
                {
                    if(GetProcessImageFileNameW(hProcess, szProcessPath, _countof(szProcessPath)) > NULL)
                    {
                        szTranslatedProcName = (wchar_t*)TranslateNativeNameW(szProcessPath);
                        lstrcpyW(szProcessPath, szTranslatedProcName);
                        VirtualFree((void*)szTranslatedProcName, NULL, MEM_RELEASE);
                        EngineCloseHandle(hProcess);

                        if(_wcsicmp(szProcessPath, szImageName) == 0)
                        {
                            return(bProcessId[i]);
                        }
                        else
                        {
                            nameOnly = wcsrchr(szProcessPath, L'\\');
                            if(nameOnly)
                            {
                                nameOnly++;
                                if(_wcsicmp(nameOnly, szImageName) == 0)
                                {
                                    return(bProcessId[i]);
                                }
                            }
                        }
                    }
                    else
                    {
                        EngineCloseHandle(hProcess);
                    }
                }
            }
        }
    }
    return(NULL);
}

__declspec(dllexport) void TITCALL EnumProcessesWithLibrary(char* szLibraryName, void* EnumFunction)
{

    int i;
    int j;
    typedef void(TITCALL * fEnumFunction)(DWORD ProcessId, HMODULE ModuleBaseAddress);
    fEnumFunction myEnumFunction = (fEnumFunction)EnumFunction;
    HMODULE EnumeratedModules[1024] = {0};
    DWORD bProcessId[1024] = {0};
    char szModuleName[1024] = {0};
    DWORD pProcessIdCount = NULL;
    DWORD cbNeeded = 0;
    HANDLE hProcess;

    if(EnumFunction != NULL)
    {
        if(EnumProcesses(bProcessId, sizeof(bProcessId), &pProcessIdCount))
        {
            for(i = 0; i < (int)(pProcessIdCount / sizeof(DWORD)); i++)
            {
                if(bProcessId[i] != NULL)
                {
                    hProcess = EngineOpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, bProcessId[i]);
                    if(hProcess != NULL)
                    {
                        RtlZeroMemory(EnumeratedModules, sizeof(EnumeratedModules));
                        if(EnumProcessModules(hProcess, (HMODULE*)EnumeratedModules, sizeof(EnumeratedModules), &cbNeeded))
                        {
                            for(j = 0; j < (int)(cbNeeded / sizeof(HMODULE)); j++)
                            {
                                if(EnumeratedModules[j] != NULL)
                                {
                                    if(GetModuleBaseNameA(hProcess, EnumeratedModules[j], szModuleName, _countof(szModuleName)) > NULL)
                                    {
                                        if(lstrcmpiA(szModuleName, szLibraryName) == NULL)
                                        {
                                            __try
                                            {
                                                myEnumFunction(bProcessId[i], EnumeratedModules[j]);
                                            }
                                            __except(EXCEPTION_EXECUTE_HANDLER)
                                            {
                                                EngineCloseHandle(hProcess);
                                                return;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        EngineCloseHandle(hProcess);
                    }
                }
            }
        }
    }
}

__declspec(dllexport) HANDLE TITCALL TitanOpenProcess(DWORD dwDesiredAccess, bool bInheritHandle, DWORD dwProcessId)
{
    return EngineOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}

__declspec(dllexport) HANDLE TITCALL TitanOpenThread(DWORD dwDesiredAccess, bool bInheritHandle, DWORD dwThreadId)
{
    return EngineOpenThread(dwDesiredAccess, bInheritHandle, dwThreadId);
}

__declspec(dllexport) bool TITCALL TitanCloseHandle(HANDLE hEngineHandle)
{
    return EngineCloseHandle(hEngineHandle);
}

__declspec(dllexport) bool TITCALL ProcessIsWow64(HANDLE hProcess, PBOOL isWow64)
{
    return !!IsWow64Process(hProcess, isWow64);
}

__declspec(dllexport) bool TITCALL TitanTerminateProcess(HANDLE hProcess, DWORD exitCode)
{
    return !!TerminateProcess(hProcess, exitCode);
}

__declspec(dllexport) bool TITCALL TitanDebugBreakProcess(HANDLE hProcess)
{
    return !!DebugBreakProcess(hProcess);
}

__declspec(dllexport) HANDLE TITCALL TitanCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE start, LPVOID argument, DWORD creationFlags, LPDWORD threadId)
{
    return CreateRemoteThread(hProcess, nullptr, 0, start, argument, creationFlags, threadId);
}

__declspec(dllexport) DWORD TITCALL TitanSuspendThread(HANDLE hThread)
{
    return SuspendThread(hThread);
}

__declspec(dllexport) DWORD TITCALL TitanResumeThread(HANDLE hThread)
{
    return ResumeThread(hThread);
}

__declspec(dllexport) bool TITCALL TitanTerminateThread(HANDLE hThread, DWORD exitCode)
{
    return !!TerminateThread(hThread, exitCode);
}

__declspec(dllexport) DWORD TITCALL TitanGetThreadId(HANDLE hThread)
{
    return GetThreadId(hThread);
}

__declspec(dllexport) int TITCALL TitanGetThreadPriority(HANDLE hThread)
{
    return GetThreadPriority(hThread);
}

__declspec(dllexport) bool TITCALL TitanSetThreadPriority(HANDLE hThread, int priority)
{
    return !!SetThreadPriority(hThread, priority);
}

__declspec(dllexport) bool TITCALL TitanGetThreadTimes(HANDLE hThread, LPFILETIME creation, LPFILETIME exit, LPFILETIME kernel, LPFILETIME user)
{
    return !!GetThreadTimes(hThread, creation, exit, kernel, user);
}

__declspec(dllexport) bool TITCALL TitanQueryThreadCycleTime(HANDLE hThread, PULONG64 cycleTime)
{
    return !!QueryThreadCycleTime(hThread, cycleTime);
}