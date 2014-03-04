#include "stdafx.h"
#include "definitions.h"
#include "Global.Handle.h"
#include "Global.Engine.h"
#include "Global.Threader.h"
#include "Global.Debugger.h"
#include <tlhelp32.h>

// TitanEngine.Threader.functions:
__declspec(dllexport) bool TITCALL ThreaderImportRunningThreadData(DWORD ProcessId)
{

    HANDLE hSnapShot;
    THREADENTRY32 ThreadEntry = {};
    PTHREAD_ITEM_DATA hListThreadPtr = NULL;

    if(dbgProcessInformation.hProcess == NULL && ProcessId != NULL)
    {
        if(hListThread == NULL)
        {
            hListThread = VirtualAlloc(NULL, MAX_DEBUG_DATA * sizeof THREAD_ITEM_DATA, MEM_COMMIT, PAGE_READWRITE);
        }
        else
        {
            RtlZeroMemory(hListThread, MAX_DEBUG_DATA * sizeof THREAD_ITEM_DATA);
        }
        ThreadEntry.dwSize = sizeof THREADENTRY32;
        hListThreadPtr = (PTHREAD_ITEM_DATA)hListThread;
        hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, ProcessId);
        if(hSnapShot != INVALID_HANDLE_VALUE)
        {
            if(Thread32First(hSnapShot, &ThreadEntry))
            {
                do
                {
                    if(ThreadEntry.th32OwnerProcessID == ProcessId)
                    {
                        hListThreadPtr->dwThreadId = ThreadEntry.th32ThreadID;
                        hListThreadPtr->hThread = OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_QUERY_INFORMATION|THREAD_SUSPEND_RESUME, false, hListThreadPtr->dwThreadId);
                        hListThreadPtr = (PTHREAD_ITEM_DATA)((ULONG_PTR)hListThreadPtr + sizeof THREAD_ITEM_DATA);
                    }
                }
                while(Thread32Next(hSnapShot, &ThreadEntry));
            }
            EngineCloseHandle(hSnapShot);
            return true;
        }
    }
    return false;
}
__declspec(dllexport) void* TITCALL ThreaderGetThreadInfo(HANDLE hThread, DWORD ThreadId)
{

    PTHREAD_ITEM_DATA hListThreadPtr = (PTHREAD_ITEM_DATA)hListThread;

    if(hListThreadPtr != NULL)
    {
        if(hThread != NULL)
        {
            while(hListThreadPtr->hThread != NULL && hListThreadPtr->hThread != hThread)
            {
                hListThreadPtr = (PTHREAD_ITEM_DATA)((ULONG_PTR)hListThreadPtr + sizeof THREAD_ITEM_DATA);
            }
            if(hListThreadPtr->hThread == hThread)
            {
                return((void*)hListThreadPtr);
            }
        }
        else if(ThreadId != NULL)
        {
            while(hListThreadPtr->hThread != NULL && hListThreadPtr->dwThreadId != ThreadId)
            {
                hListThreadPtr = (PTHREAD_ITEM_DATA)((ULONG_PTR)hListThreadPtr + sizeof THREAD_ITEM_DATA);
            }
            if(hListThreadPtr->dwThreadId == ThreadId)
            {
                return((void*)hListThreadPtr);
            }
        }
    }
    return(NULL);
}
__declspec(dllexport) void TITCALL ThreaderEnumThreadInfo(void* EnumCallBack)
{

    PTHREAD_ITEM_DATA hListThreadPtr = (PTHREAD_ITEM_DATA)hListThread;
    typedef void(TITCALL *fEnumCallBack)(LPVOID fThreadDetail);
    fEnumCallBack myEnumCallBack = (fEnumCallBack)EnumCallBack;

    if(hListThreadPtr != NULL)
    {
        while(EnumCallBack != NULL && hListThreadPtr->hThread != NULL)
        {
            if(hListThreadPtr->hThread != NULL)
            {
                __try
                {
                    myEnumCallBack((void*)hListThreadPtr);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    EnumCallBack = NULL;
                }
            }
            hListThreadPtr = (PTHREAD_ITEM_DATA)((ULONG_PTR)hListThreadPtr + sizeof THREAD_ITEM_DATA);
        }
    }
}
__declspec(dllexport) bool TITCALL ThreaderPauseThread(HANDLE hThread)
{

    PTHREAD_ITEM_DATA hListThreadPtr = (PTHREAD_ITEM_DATA)hListThread;

    if(hListThreadPtr != NULL)
    {
        if(hThread != NULL)
        {
            while(hListThreadPtr->hThread != NULL && hListThreadPtr->hThread != hThread)
            {
                hListThreadPtr = (PTHREAD_ITEM_DATA)((ULONG_PTR)hListThreadPtr + sizeof THREAD_ITEM_DATA);
            }
            if(hListThreadPtr->hThread == hThread)
            {
                if(SuspendThread(hThread) != -1)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }
    }
    return false;
}
__declspec(dllexport) bool TITCALL ThreaderResumeThread(HANDLE hThread)
{

    PTHREAD_ITEM_DATA hListThreadPtr = (PTHREAD_ITEM_DATA)hListThread;

    if(hListThreadPtr != NULL)
    {
        if(hThread != NULL)
        {
            while(hListThreadPtr->hThread != NULL && hListThreadPtr->hThread != hThread)
            {
                hListThreadPtr = (PTHREAD_ITEM_DATA)((ULONG_PTR)hListThreadPtr + sizeof THREAD_ITEM_DATA);
            }
            if(hListThreadPtr->hThread == hThread)
            {
                if(ResumeThread(hThread) != -1)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }
    }
    return false;
}
__declspec(dllexport) bool TITCALL ThreaderTerminateThread(HANDLE hThread, DWORD ThreadExitCode)
{

    PTHREAD_ITEM_DATA hListThreadPtr = (PTHREAD_ITEM_DATA)hListThread;

    if(hListThreadPtr != NULL)
    {
        if(hThread != NULL)
        {
            while(hListThreadPtr->hThread != NULL && hListThreadPtr->hThread != hThread)
            {
                hListThreadPtr = (PTHREAD_ITEM_DATA)((ULONG_PTR)hListThreadPtr + sizeof THREAD_ITEM_DATA);
            }
            if(hListThreadPtr->hThread == hThread)
            {
                if(TerminateThread(hThread, ThreadExitCode) != NULL)
                {
                    hListThreadPtr->hThread = (HANDLE)-1;
                    hListThreadPtr->dwThreadId = NULL;
                    hListThreadPtr->ThreadLocalBase = NULL;
                    hListThreadPtr->ThreadStartAddress = NULL;
                    return true;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }
    }
    return false;
}
__declspec(dllexport) bool TITCALL ThreaderPauseAllThreads(bool LeaveMainRunning)
{

    PTHREAD_ITEM_DATA hListThreadPtr = (PTHREAD_ITEM_DATA)hListThread;

    if(hListThreadPtr != NULL)
    {
        while(hListThreadPtr->hThread != NULL)
        {
            if(LeaveMainRunning)
            {
                if(hListThreadPtr->hThread != dbgProcessInformation.hThread)
                {
                    SuspendThread((HANDLE)hListThreadPtr->hThread);
                }
            }
            else
            {
                SuspendThread(hListThreadPtr->hThread);
            }
            hListThreadPtr = (PTHREAD_ITEM_DATA)((ULONG_PTR)hListThreadPtr + sizeof THREAD_ITEM_DATA);
        }
        return true;
    }
    return false;
}
__declspec(dllexport) bool TITCALL ThreaderResumeAllThreads(bool LeaveMainPaused)
{

    PTHREAD_ITEM_DATA hListThreadPtr = (PTHREAD_ITEM_DATA)hListThread;

    if(hListThreadPtr != NULL)
    {
        while(hListThreadPtr->hThread != NULL)
        {
            if(LeaveMainPaused)
            {
                if(hListThreadPtr->hThread != dbgProcessInformation.hThread)
                {
                    ResumeThread(hListThreadPtr->hThread);
                }
            }
            else
            {
                ResumeThread(hListThreadPtr->hThread);
            }
            hListThreadPtr = (PTHREAD_ITEM_DATA)((ULONG_PTR)hListThreadPtr + sizeof THREAD_ITEM_DATA);
        }
        return true;
    }
    return false;
}
__declspec(dllexport) bool TITCALL ThreaderPauseProcess()
{
    return(ThreaderPauseAllThreads(false));
}
__declspec(dllexport) bool TITCALL ThreaderResumeProcess()
{
    return(ThreaderResumeAllThreads(false));
}
__declspec(dllexport) long long TITCALL ThreaderCreateRemoteThread(ULONG_PTR ThreadStartAddress, bool AutoCloseTheHandle, LPVOID ThreadPassParameter, LPDWORD ThreadId)
{

    HANDLE myThread;

    if(dbgProcessInformation.hProcess != NULL)
    {
        if(!AutoCloseTheHandle)
        {
            return((ULONG_PTR)CreateRemoteThread(dbgProcessInformation.hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)ThreadStartAddress, ThreadPassParameter, NULL, ThreadId));
        }
        else
        {
            myThread = CreateRemoteThread(dbgProcessInformation.hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)ThreadStartAddress, ThreadPassParameter, NULL, ThreadId);
            EngineCloseHandle(myThread);
            return(NULL);
        }
    }
    return(NULL);
}
__declspec(dllexport) bool TITCALL ThreaderInjectAndExecuteCode(LPVOID InjectCode, DWORD StartDelta, DWORD InjectSize)
{

    LPVOID ThreadBase = 0;
    ULONG_PTR ueNumberOfBytesRead = 0;

    if(dbgProcessInformation.hProcess != NULL)
    {
        ThreadBase = VirtualAllocEx(dbgProcessInformation.hProcess, NULL, InjectSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if(WriteProcessMemory(dbgProcessInformation.hProcess, ThreadBase, InjectCode, InjectSize, &ueNumberOfBytesRead))
        {
            ThreaderCreateRemoteThread((ULONG_PTR)((ULONG_PTR)InjectCode + StartDelta), true, NULL, NULL);
            return true;
        }
        else
        {
            return false;
        }
    }
    return false;
}
__declspec(dllexport) long long TITCALL ThreaderCreateRemoteThreadEx(HANDLE hProcess, ULONG_PTR ThreadStartAddress, bool AutoCloseTheHandle, LPVOID ThreadPassParameter, LPDWORD ThreadId)
{

    HANDLE myThread;

    if(hProcess != NULL)
    {
        if(!AutoCloseTheHandle)
        {
            return((ULONG_PTR)CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)ThreadStartAddress, ThreadPassParameter, NULL, ThreadId));
        }
        else
        {
            myThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)ThreadStartAddress, ThreadPassParameter, NULL, ThreadId);
            EngineCloseHandle(myThread);
            return(NULL);
        }
    }
    return(NULL);
}
__declspec(dllexport) bool TITCALL ThreaderInjectAndExecuteCodeEx(HANDLE hProcess, LPVOID InjectCode, DWORD StartDelta, DWORD InjectSize)
{

    LPVOID ThreadBase = 0;
    ULONG_PTR ueNumberOfBytesRead = 0;

    if(hProcess != NULL)
    {
        ThreadBase = VirtualAllocEx(hProcess, NULL, InjectSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if(WriteProcessMemory(hProcess, ThreadBase, InjectCode, InjectSize, &ueNumberOfBytesRead))
        {
            ThreaderCreateRemoteThread((ULONG_PTR)((ULONG_PTR)InjectCode + StartDelta), true, NULL, NULL);
            return true;
        }
        else
        {
            return false;
        }
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

    RtlZeroMemory(&myDBGContext, sizeof CONTEXT);
    myDBGContext.ContextFlags = CONTEXT_ALL;
    if(GetThreadContext(hThread, &myDBGContext))
    {
        return true;
    }
    else
    {
        return false;
    }
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

    PTHREAD_ITEM_DATA hListThreadPtr = (PTHREAD_ITEM_DATA)hListThread;

    if(hListThreadPtr != NULL)
    {
        while(hListThreadPtr->hThread != NULL)
        {
            if(hListThreadPtr->hThread != (HANDLE)-1)
            {
                if(ThreaderIsThreadActive(hListThreadPtr->hThread))
                {
                    return true;
                }
            }
            hListThreadPtr = (PTHREAD_ITEM_DATA)((ULONG_PTR)hListThreadPtr + sizeof THREAD_ITEM_DATA);
        }
    }
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

    PTHREAD_ITEM_DATA hListThreadPtr = (PTHREAD_ITEM_DATA)hListThread;

    if(hListThread != NULL)
    {
        while(hListThreadPtr->hThread != NULL)
        {
            if(hListThreadPtr->hThread != (HANDLE)-1 && hListThreadPtr->dwThreadId == ThreadId)
            {
                return((ULONG_PTR)hListThreadPtr->hThread);
            }
            hListThreadPtr = (PTHREAD_ITEM_DATA)((ULONG_PTR)hListThreadPtr + sizeof THREAD_ITEM_DATA);
        }
    }
    return(NULL);
}
__declspec(dllexport) void* TITCALL ThreaderGetThreadData()
{
    return(hListThread);
}
__declspec(dllexport) bool TITCALL ThreaderIsExceptionInMainThread()
{

    LPDEBUG_EVENT myDBGEvent;

    myDBGEvent = (LPDEBUG_EVENT)GetDebugData();
    if(myDBGEvent->dwThreadId == dbgProcessInformation.dwThreadId)
    {
        return true;
    }
    return false;
}
