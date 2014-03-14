#include "stdafx.h"
#include "definitions.h"
#include "Global.Handle.h"
#include "Global.Engine.h"
#include "Global.Threader.h"
#include "Global.Debugger.h"

// TitanEngine.Threader.functions:
__declspec(dllexport) bool TITCALL ThreaderImportRunningThreadData(DWORD ProcessId)
{
    if(dbgProcessInformation.hProcess != NULL || ProcessId == NULL)
        return false;
    std::vector<THREAD_ITEM_DATA>().swap(hListThread); //clear thread list
    THREADENTRY32 ThreadEntry = {};
    ThreadEntry.dwSize = sizeof THREADENTRY32;
    HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, ProcessId);
    if(hSnapShot != INVALID_HANDLE_VALUE)
    {
        if(Thread32First(hSnapShot, &ThreadEntry))
        {
            do
            {
                if(ThreadEntry.th32OwnerProcessID == ProcessId)
                {
                    THREAD_ITEM_DATA NewThreadData;
                    memset(&NewThreadData, 0, sizeof(THREAD_ITEM_DATA));
                    NewThreadData.dwThreadId = ThreadEntry.th32ThreadID;
                    NewThreadData.hThread = OpenThread(THREAD_ALL_ACCESS, false, NewThreadData.dwThreadId);
                    hListThread.push_back(NewThreadData);
                }
            }
            while(Thread32Next(hSnapShot, &ThreadEntry));
        }
        EngineCloseHandle(hSnapShot);
        return true;
    }
    return false;
}

__declspec(dllexport) void* TITCALL ThreaderGetThreadInfo(HANDLE hThread, DWORD ThreadId)
{
    if(!hThread && !ThreadId)
        return NULL;
    static THREAD_ITEM_DATA ThreadData;
    memset(&ThreadData, 0, sizeof(THREAD_ITEM_DATA));
    int threadcount=hListThread.size();
    for(int i=0; i<threadcount; i++)
        if(hListThread.at(i).hThread == hThread || hListThread.at(i).dwThreadId == ThreadId)
        {
            memcpy(&ThreadData, &hListThread.at(i), sizeof(THREAD_ITEM_DATA));
            return &ThreadData;
        }
    return NULL;
}

__declspec(dllexport) void TITCALL ThreaderEnumThreadInfo(void* EnumCallBack)
{
    typedef void(TITCALL *fEnumCallBack)(LPVOID fThreadDetail);
    fEnumCallBack myEnumCallBack = (fEnumCallBack)EnumCallBack;
    int threadcount=hListThread.size();
    for(int i=0; i<threadcount; i++)
    {
        __try
        {
            myEnumCallBack(&hListThread.at(i));
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            break;
        }
    }
}

__declspec(dllexport) bool TITCALL ThreaderPauseThread(HANDLE hThread)
{
    int threadcount=hListThread.size();
    for(int i=0; i<threadcount; i++)
        if(hListThread.at(i).hThread == hThread && SuspendThread(hThread) != -1)
            return true;
    return false;
}

__declspec(dllexport) bool TITCALL ThreaderResumeThread(HANDLE hThread)
{
    int threadcount=hListThread.size();
    for(int i=0; i<threadcount; i++)
        if(hListThread.at(i).hThread == hThread && ResumeThread(hThread) != -1)
            return true;
    return false;
}

__declspec(dllexport) bool TITCALL ThreaderTerminateThread(HANDLE hThread, DWORD ThreadExitCode)
{
    int threadcount=hListThread.size();
    for(int i=0; i<threadcount; i++)
        if(hListThread.at(i).hThread == hThread && TerminateThread(hThread, ThreadExitCode) != NULL)
        {
            hListThread.erase(hListThread.begin()+i);
            return true;
        }
    return false;
}

__declspec(dllexport) bool TITCALL ThreaderPauseAllThreads(bool LeaveMainRunning)
{
    bool ret=true;
    int threadcount=hListThread.size();
    for(int i=0; i<threadcount; i++)
    {
        DWORD suspended;
        if(LeaveMainRunning && hListThread.at(i).hThread != dbgProcessInformation.hThread)
            suspended=SuspendThread(hListThread.at(i).hThread);
        else
            suspended=SuspendThread(hListThread.at(i).hThread);
        if(suspended==-1)
            ret=false;
    }
    return ret;
}

__declspec(dllexport) bool TITCALL ThreaderResumeAllThreads(bool LeaveMainPaused)
{
    bool ret=true;
    int threadcount=hListThread.size();
    for(int i=0; i<threadcount; i++)
    {
        DWORD resumed;
        if(LeaveMainPaused && hListThread.at(i).hThread != dbgProcessInformation.hThread)
            resumed=ResumeThread(hListThread.at(i).hThread);
        else
            resumed=ResumeThread(hListThread.at(i).hThread);
        if(resumed==-1)
            ret=false;
    }
    return ret;
}

__declspec(dllexport) bool TITCALL ThreaderPauseProcess()
{
    return ThreaderPauseAllThreads(false);
}

__declspec(dllexport) bool TITCALL ThreaderResumeProcess()
{
    return ThreaderResumeAllThreads(false);
}

__declspec(dllexport) long long TITCALL ThreaderCreateRemoteThread(ULONG_PTR ThreadStartAddress, bool AutoCloseTheHandle, LPVOID ThreadPassParameter, LPDWORD ThreadId)
{
    return ThreaderCreateRemoteThreadEx(dbgProcessInformation.hProcess, ThreadStartAddress, AutoCloseTheHandle, ThreadPassParameter, ThreadId);
}

__declspec(dllexport) bool TITCALL ThreaderInjectAndExecuteCode(LPVOID InjectCode, DWORD StartDelta, DWORD InjectSize)
{
    return ThreaderInjectAndExecuteCodeEx(dbgProcessInformation.hProcess, InjectCode, StartDelta, InjectSize);
}

__declspec(dllexport) long long TITCALL ThreaderCreateRemoteThreadEx(HANDLE hProcess, ULONG_PTR ThreadStartAddress, bool AutoCloseTheHandle, LPVOID ThreadPassParameter, LPDWORD ThreadId)
{
    if(hProcess != NULL)
    {
        if(!AutoCloseTheHandle)
        {
            return (ULONG_PTR)CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)ThreadStartAddress, ThreadPassParameter, NULL, ThreadId);
        }
        else
        {
            HANDLE myThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)ThreadStartAddress, ThreadPassParameter, NULL, ThreadId);
            EngineCloseHandle(myThread);
            return NULL;
        }
    }
    return NULL;
}

__declspec(dllexport) bool TITCALL ThreaderInjectAndExecuteCodeEx(HANDLE hProcess, LPVOID InjectCode, DWORD StartDelta, DWORD InjectSize)
{
    if(hProcess != NULL)
    {
        LPVOID ThreadBase = VirtualAllocEx(hProcess, NULL, InjectSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        ULONG_PTR ueNumberOfBytesRead = 0;
        if(WriteProcessMemory(hProcess, ThreadBase, InjectCode, InjectSize, &ueNumberOfBytesRead))
        {
            ThreaderCreateRemoteThread((ULONG_PTR)((ULONG_PTR)InjectCode + StartDelta), true, NULL, NULL);
            return true;
        }
        else
            return false;
    }
    return false;
}

__declspec(dllexport) void TITCALL ThreaderSetCallBackForNextExitThreadEvent(LPVOID exitThreadCallBack)
{
    engineExitThreadOneShootCallBack = exitThreadCallBack;
}

__declspec(dllexport) bool TITCALL ThreaderIsThreadStillRunning(HANDLE hThread)
{
    CONTEXT myDBGContext;
    memset(&myDBGContext, 0, sizeof(CONTEXT));
    myDBGContext.ContextFlags = CONTEXT_ALL;
    return !!GetThreadContext(hThread, &myDBGContext);
}

__declspec(dllexport) bool TITCALL ThreaderIsThreadActive(HANDLE hThread)
{
    if(SuspendThread(hThread)) //if previous suspend count is above 0 (which means thread is suspended)
    {
        ResumeThread(hThread); //decrement suspend count
        return true;
    }
    return false;
}

__declspec(dllexport) bool TITCALL ThreaderIsAnyThreadActive()
{
    int threadcount=hListThread.size();
    for(int i=0; i<threadcount; i++)
        if(ThreaderIsThreadActive(hListThread.at(i).hThread))
            return true;
    return false;
}

__declspec(dllexport) bool TITCALL ThreaderExecuteOnlyInjectedThreads()
{
    if(ThreaderPauseProcess())
    {
        engineResumeProcessIfNoThreadIsActive = true;
        return true;
    }
    return false;
}

__declspec(dllexport) long long TITCALL ThreaderGetOpenHandleForThread(DWORD ThreadId)
{
    int threadcount=hListThread.size();
    for(int i=0; i<threadcount; i++)
        if(hListThread.at(i).dwThreadId == ThreadId)
            return (ULONG_PTR)hListThread.at(i).hThread;
    return 0;
}

__declspec(dllexport) bool TITCALL ThreaderIsExceptionInMainThread()
{
    LPDEBUG_EVENT myDBGEvent = (LPDEBUG_EVENT)GetDebugData();

    return (myDBGEvent->dwThreadId == dbgProcessInformation.dwThreadId);
}
