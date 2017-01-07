#include "stdafx.h"
#include "definitions.h"
#include "Global.Handle.h"
#include "Global.Engine.h"
#include "Global.Threader.h"
#include "Global.Debugger.h"

void updateThreadList(THREAD_ITEM_DATA* NewThreadData)
{
    bool notInList = true;
    int count = (int)hListThread.size();

    for(int i = 0; i < count; i++)
    {
        if(hListThread.at(i).dwThreadId == NewThreadData->dwThreadId)
        {
            notInList = false;
            CloseHandle(NewThreadData->hThread); //handle not needed
            hListThread.at(i).BasePriority = NewThreadData->BasePriority;
            hListThread.at(i).ContextSwitches = NewThreadData->ContextSwitches;
            hListThread.at(i).Priority = NewThreadData->Priority;
            hListThread.at(i).TebAddress = NewThreadData->TebAddress;
            hListThread.at(i).ThreadStartAddress = NewThreadData->ThreadStartAddress;
            hListThread.at(i).WaitReason = NewThreadData->WaitReason;
            hListThread.at(i).WaitTime = NewThreadData->WaitTime;
            hListThread.at(i).ThreadState = NewThreadData->ThreadState;
            break;
        }
    }

    if(notInList)
    {
        hListThread.push_back(*NewThreadData);
    }
}

// TitanEngine.Threader.functions:
__declspec(dllexport) bool TITCALL ThreaderImportRunningThreadData(DWORD ProcessId)
{
    bool updateList = false;
    DWORD dwProcessId = 0;

    if(ProcessId == NULL && dbgProcessInformation.hProcess != NULL)
    {
        updateList = true;
        dwProcessId = GetProcessId(dbgProcessInformation.hProcess);
    }
    else if(ProcessId != NULL && dbgProcessInformation.hProcess != NULL)
    {
        updateList = true;
        dwProcessId = ProcessId;
    }
    else if(ProcessId != NULL && dbgProcessInformation.hProcess == NULL)
    {
        updateList = false;
        dwProcessId = ProcessId;
    }
    else if(ProcessId == NULL && dbgProcessInformation.hProcess == NULL)
    {
        return false;
    }

    if(updateList == false)
    {
        std::vector<THREAD_ITEM_DATA>().swap(hListThread); //clear thread list
    }


    THREAD_ITEM_DATA NewThreadData;
    ULONG retLength = 0;
    ULONG bufferLength = 1;
    PSYSTEM_PROCESS_INFORMATION pBuffer = (PSYSTEM_PROCESS_INFORMATION)malloc(bufferLength);
    PSYSTEM_PROCESS_INFORMATION pIter;
    PSYSTEM_THREAD_INFORMATION pIterThread;

    if(NtQuerySystemInformation(SystemProcessInformation, pBuffer, bufferLength, &retLength) == STATUS_INFO_LENGTH_MISMATCH)
    {
        free(pBuffer);
        bufferLength = retLength + sizeof(SYSTEM_PROCESS_INFORMATION);
        pBuffer = (PSYSTEM_PROCESS_INFORMATION)malloc(bufferLength);
        if(!pBuffer)
            return false;

        if(NtQuerySystemInformation(SystemProcessInformation, pBuffer, bufferLength, &retLength) != STATUS_SUCCESS)
        {
            return false;
        }
    }
    else
    {
        return false;
    }

    pIter = pBuffer;

    while(TRUE)
    {
        if(pIter->UniqueProcessId == (HANDLE)dwProcessId)
        {
            pIterThread = &pIter->Threads[0];
            for(ULONG i = 0; i < pIter->NumberOfThreads; i++)
            {
                ZeroMemory(&NewThreadData, sizeof(THREAD_ITEM_DATA));

                NewThreadData.BasePriority = pIterThread->BasePriority;
                NewThreadData.ContextSwitches = pIterThread->ContextSwitches;
                NewThreadData.Priority = pIterThread->Priority;
                NewThreadData.BasePriority = pIterThread->BasePriority;
                //NewThreadData.ThreadStartAddress = pIterThread->StartAddress; <- wrong value
                NewThreadData.ThreadState = pIterThread->ThreadState;
                NewThreadData.WaitReason = pIterThread->WaitReason;
                NewThreadData.WaitTime = pIterThread->WaitTime;
                NewThreadData.dwThreadId = (DWORD)pIterThread->ClientId.UniqueThread;

                NewThreadData.hThread = EngineOpenThread(THREAD_ALL_ACCESS, FALSE, NewThreadData.dwThreadId);
                if(NewThreadData.hThread)
                {
                    NewThreadData.TebAddress = GetTEBLocation(NewThreadData.hThread);

                    PVOID startAddress = 0;
                    if(NtQueryInformationThread(NewThreadData.hThread, ThreadQuerySetWin32StartAddress, &startAddress, sizeof(PVOID), NULL) == STATUS_SUCCESS)
                    {
                        NewThreadData.ThreadStartAddress = startAddress;
                    }
                }

                if(updateList == false)
                {
                    hListThread.push_back(NewThreadData);
                }
                else
                {
                    updateThreadList(&NewThreadData);
                }

                pIterThread++;
            }

            break;
        }

        if(pIter->NextEntryOffset == 0)
        {
            break;
        }
        else
        {
            pIter = (PSYSTEM_PROCESS_INFORMATION)((DWORD_PTR)pIter + (DWORD_PTR)pIter->NextEntryOffset);
        }
    }

    free(pBuffer);
    return (hListThread.size() > 0);
}

__declspec(dllexport) void* TITCALL ThreaderGetThreadInfo(HANDLE hThread, DWORD ThreadId)
{
    if(!hThread && !ThreadId)
        return NULL;
    static THREAD_ITEM_DATA ThreadData;
    memset(&ThreadData, 0, sizeof(THREAD_ITEM_DATA));
    int threadcount = (int)hListThread.size();
    for(int i = 0; i < threadcount; i++)
        if(hListThread.at(i).hThread == hThread || hListThread.at(i).dwThreadId == ThreadId)
        {
            memcpy(&ThreadData, &hListThread.at(i), sizeof(THREAD_ITEM_DATA));
            return &ThreadData;
        }
    return NULL;
}

__declspec(dllexport) void TITCALL ThreaderEnumThreadInfo(void* EnumCallBack)
{
    typedef void(TITCALL * fEnumCallBack)(LPVOID fThreadDetail);
    fEnumCallBack myEnumCallBack = (fEnumCallBack)EnumCallBack;
    int threadcount = (int)hListThread.size();
    for(int i = 0; i < threadcount; i++)
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
    int threadcount = (int)hListThread.size();
    for(int i = 0; i < threadcount; i++)
        if(hListThread.at(i).hThread == hThread && SuspendThread(hThread) != -1)
            return true;
    return false;
}

__declspec(dllexport) bool TITCALL ThreaderResumeThread(HANDLE hThread)
{
    int threadcount = (int)hListThread.size();
    for(int i = 0; i < threadcount; i++)
        if(hListThread.at(i).hThread == hThread && ResumeThread(hThread) != -1)
            return true;
    return false;
}

__declspec(dllexport) bool TITCALL ThreaderTerminateThread(HANDLE hThread, DWORD ThreadExitCode)
{
    int threadcount = (int)hListThread.size();
    for(int i = 0; i < threadcount; i++)
        if(hListThread.at(i).hThread == hThread && TerminateThread(hThread, ThreadExitCode) != NULL)
        {
            hListThread.erase(hListThread.begin() + i);
            return true;
        }
    return false;
}

__declspec(dllexport) bool TITCALL ThreaderPauseAllThreads(bool LeaveMainRunning)
{
    bool ret = true;
    int threadcount = (int)hListThread.size();
    for(int i = 0; i < threadcount; i++)
    {
        DWORD suspended;
        if(LeaveMainRunning && hListThread.at(i).hThread != dbgProcessInformation.hThread)
            suspended = SuspendThread(hListThread.at(i).hThread);
        else
            suspended = SuspendThread(hListThread.at(i).hThread);
        if(suspended == -1)
            ret = false;
    }
    return ret;
}

__declspec(dllexport) bool TITCALL ThreaderResumeAllThreads(bool LeaveMainPaused)
{
    bool ret = true;
    int threadcount = (int)hListThread.size();
    for(int i = 0; i < threadcount; i++)
    {
        DWORD resumed;
        if(LeaveMainPaused && hListThread.at(i).hThread != dbgProcessInformation.hThread)
            resumed = ResumeThread(hListThread.at(i).hThread);
        else
            resumed = ResumeThread(hListThread.at(i).hThread);
        if(resumed == -1)
            ret = false;
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

__declspec(dllexport) ULONG_PTR TITCALL ThreaderCreateRemoteThread(ULONG_PTR ThreadStartAddress, bool AutoCloseTheHandle, LPVOID ThreadPassParameter, LPDWORD ThreadId)
{
    return ThreaderCreateRemoteThreadEx(dbgProcessInformation.hProcess, ThreadStartAddress, AutoCloseTheHandle, ThreadPassParameter, ThreadId);
}

__declspec(dllexport) bool TITCALL ThreaderInjectAndExecuteCode(LPVOID InjectCode, DWORD StartDelta, DWORD InjectSize)
{
    return ThreaderInjectAndExecuteCodeEx(dbgProcessInformation.hProcess, InjectCode, StartDelta, InjectSize);
}

__declspec(dllexport) ULONG_PTR TITCALL ThreaderCreateRemoteThreadEx(HANDLE hProcess, ULONG_PTR ThreadStartAddress, bool AutoCloseTheHandle, LPVOID ThreadPassParameter, LPDWORD ThreadId)
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
        return false; //meaning the thread is not active
    }
    ResumeThread(hThread); //decrement suspend count
    return true;
}

__declspec(dllexport) bool TITCALL ThreaderIsAnyThreadActive()
{
    int threadcount = (int)hListThread.size();
    for(int i = 0; i < threadcount; i++)
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

__declspec(dllexport) ULONG_PTR TITCALL ThreaderGetOpenHandleForThread(DWORD ThreadId)
{
    int threadcount = (int)hListThread.size();
    for(int i = 0; i < threadcount; i++)
        if(hListThread.at(i).dwThreadId == ThreadId)
            return (ULONG_PTR)hListThread.at(i).hThread;
    return 0;
}

__declspec(dllexport) bool TITCALL ThreaderIsExceptionInMainThread()
{
    LPDEBUG_EVENT myDBGEvent = (LPDEBUG_EVENT)GetDebugData();

    return (myDBGEvent->dwThreadId == dbgProcessInformation.dwThreadId);
}
