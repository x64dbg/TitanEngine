#include "stdafx.h"
#include "definitions.h"
#include "Global.Debugger.h"
#include "Global.Engine.h"
#include "Global.Breakpoints.h"

HARDWARE_DATA DebugRegister[4] = {};
PROCESS_INFORMATION dbgProcessInformation = {};
CustomHandler myDBGCustomHandler = {};
PCustomHandler DBGCustomHandler = &myDBGCustomHandler;
ExpertDebug expertDebug = {};
STARTUPINFOW dbgStartupInfo = {};
LPVOID DebugModuleEntryPointCallBack;
LPVOID DebugExeFileEntryPointCallBack;
ULONG_PTR DebugModuleEntryPoint;
ULONG_PTR DebugModuleImageBase;
ULONG_PTR DebugAttachedProcessCallBack = NULL;
ULONG_PTR DebugReserveModuleBase = NULL;
ULONG_PTR DebugDebuggingMainModuleBase = NULL;
ULONG_PTR DebugDebuggingDLLBase = NULL;
HANDLE DebugDLLFileMapping;
bool DebugAttachedToProcess = false;
bool DebugRemoveDebugPrivilege = false;
bool DebugDebuggingDLL = false;
wchar_t* DebugDebuggingDLLFullFileName;
wchar_t* DebugDebuggingDLLFileName;
DEBUG_EVENT DBGEvent = {};
DEBUG_EVENT TerminateDBGEvent = {};
DWORD ProcessExitCode = 0;
HANDLE DBGFileHandle;
std::vector<ULONG_PTR> tlsCallBackList;
std::vector<PROCESS_ITEM_DATA> hListProcess;
DWORD engineStepCount = 0;
LPVOID engineStepCallBack = NULL;
bool engineStepActive = false;
bool engineProcessIsNowDetached = false;
DWORD DBGCode = DBG_CONTINUE;
bool engineFileIsBeingDebugged = false;
ULONG_PTR engineFakeDLLHandle = NULL;
LPVOID engineAttachedProcessDebugInfo = NULL;
wchar_t szDebuggerName[512];
bool DebugStepFinal = false;
LPVOID StepOutCallBack = NULL;

// Global.Debugger.functions:
long DebugLoopInSecondThread(LPVOID InputParameter)
{
    if(InputParameter == NULL) //IsFileDll
    {
        InitDebugExW(expertDebug.szFileName, expertDebug.szCommandLine, expertDebug.szCurrentFolder, expertDebug.EntryCallBack);
    }
    else
    {
        InitDLLDebugW(expertDebug.szFileName, expertDebug.ReserveModuleBase, expertDebug.szCommandLine, expertDebug.szCurrentFolder, expertDebug.EntryCallBack);
    }
    DebugLoop();
    return NULL;
}

void DebuggerReset()
{
    if(engineResetCustomHandler)
    {
        RtlZeroMemory(&myDBGCustomHandler, sizeof CustomHandler);
    }
    std::vector<BreakPointDetail>().swap(BreakPointBuffer);
}

void ClearProcessList()
{
    std::vector<PROCESS_ITEM_DATA>().swap(hListProcess);
}

void ClearTlsCallBackList()
{
    std::vector<ULONG_PTR>().swap(tlsCallBackList);
}

void StepOutStepCallBack()
{
    BYTE cipch = 0x90;
    MemoryReadSafe(dbgProcessInformation.hProcess, (void*)GetContextData(UE_CIP), &cipch, sizeof(cipch), 0);
    if(cipch == 0xC3 || cipch == 0xC2) //ret
    {
        if(DebugStepFinal)
            StepOver(StepOutCallBack);
        else
        {
            typedef void(TITCALL * fCustomBreakPoint)();
            ((fCustomBreakPoint)StepOutCallBack)();
        }
    }
    else
        StepOver(StepOutStepCallBack);
}

static DWORD BaseSetLastNTError(IN NTSTATUS Status)
{
    DWORD dwErrCode;
    dwErrCode = RtlNtStatusToDosError(Status);
    SetLastError(dwErrCode);
    return dwErrCode;
}

static HANDLE WINAPI ProcessIdToHandle(IN DWORD dwProcessId)
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE Handle;
    CLIENT_ID ClientId;

    /* If we don't have a PID, look it up */
    //if (dwProcessId == MAXDWORD) dwProcessId = (DWORD_PTR)CsrGetProcessId();

    /* Open a handle to the process */
    ClientId.UniqueThread = NULL;
    ClientId.UniqueProcess = UlongToHandle(dwProcessId);
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    Status = NtOpenProcess(&Handle,
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ |
        PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION,
        &ObjectAttributes,
        &ClientId);
    if(!NT_SUCCESS(Status))
    {
        /* Fail */
        BaseSetLastNTError(Status);
        return 0;
    }

    /* Return the handle */
    return Handle;
}

static NTSTATUS NTAPI DbgUiIssueRemoteBreakin_(IN HANDLE Process)
{
    HANDLE hThread;
    CLIENT_ID ClientId;
    NTSTATUS Status;

    PUSER_THREAD_START_ROUTINE RemoteBreakFunction = (PUSER_THREAD_START_ROUTINE)DbgUiRemoteBreakin;

    LPVOID RemoteMemory = VirtualAllocEx(Process, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);
    if(RemoteMemory)
    {
        SIZE_T written = 0;
        unsigned char payload[] = { 0xCC, 0xC3 };
        if(WriteProcessMemory(Process, RemoteMemory, payload, sizeof(payload), &written))
        {
            RemoteBreakFunction = (PUSER_THREAD_START_ROUTINE)RemoteMemory;
        }
        else
        {
            VirtualFreeEx(Process, RemoteMemory, 0, MEM_RELEASE);
        }
    }

    /* Create the thread that will do the breakin */
    Status = RtlCreateUserThread(Process,
        NULL,
        FALSE,
        0,
        0,
        0x1000 /* PAGE_SIZE */,
        RemoteBreakFunction,
        NULL,
        &hThread,
        &ClientId);

    /* Close the handle on success */
    if(NT_SUCCESS(Status)) NtClose(hThread);

    /* Return status */
    return Status;
}

static NTSTATUS NTAPI DbgUiDebugActiveProcess_(IN HANDLE Process)
{
    NTSTATUS Status;

    /* Tell the kernel to start debugging */
    Status = NtDebugActiveProcess(Process, NtCurrentTeb()->DbgSsReserved[1]);
    if(NT_SUCCESS(Status))
    {
        /* Now break-in the process */
        Status = DbgUiIssueRemoteBreakin_(Process);
        if(!NT_SUCCESS(Status))
        {
            /* We couldn't break-in, cancel debugging */
            DbgUiStopDebugging(Process);
        }
    }

    /* Return status */
    return Status;
}

// Source: https://github.com/mirror/reactos/blob/c6d2b35ffc91e09f50dfb214ea58237509329d6b/reactos/dll/win32/kernel32/client/debugger.c#L480
BOOL WINAPI DebugActiveProcess_(IN DWORD dwProcessId)
{
    NTSTATUS Status, Status1;
    HANDLE Handle;

    /* Connect to the debugger */
    Status = DbgUiConnectToDbg();
    if(!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    /* Get the process handle */
    Handle = ProcessIdToHandle(dwProcessId);
    if(!Handle) return FALSE;

    /* Now debug the process */
    Status = DbgUiDebugActiveProcess_(Handle);

    /* Close the handle since we're done */
    Status1 = NtClose(Handle);

    /* Check if debugging worked */
    if(!NT_SUCCESS(Status))
    {
        /* Fail */
        BaseSetLastNTError(Status);
        return FALSE;
    }

    /* Success */
    return TRUE;
}