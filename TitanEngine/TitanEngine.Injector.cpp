#include "stdafx.h"
#include "definitions.h"
#include "Global.Injector.h"

// TitanEngine.Injector.functions:
__declspec(dllexport) bool TITCALL RemoteLoadLibrary(HANDLE hProcess, char* szLibraryFile, bool WaitForThreadExit)
{

    wchar_t uniLibraryFile[MAX_PATH] = {};

    if(szLibraryFile != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szLibraryFile, lstrlenA(szLibraryFile) + 1, uniLibraryFile, sizeof(uniLibraryFile) / (sizeof(uniLibraryFile[0])));
        return(RemoteLoadLibraryW(hProcess, uniLibraryFile, WaitForThreadExit));
    }
    else
    {
        return false;
    }
}
__declspec(dllexport) bool TITCALL RemoteLoadLibraryW(HANDLE hProcess, wchar_t* szLibraryFile, bool WaitForThreadExit)
{

    int i;
    InjectCodeData APIData;
    LPVOID remStringData;
    LPVOID remCodeData;
    ULONG_PTR remInjectSize = (ULONG_PTR)((ULONG_PTR)&injectedRemoteFreeLibrary - (ULONG_PTR)&injectedRemoteLoadLibrary);

    ULONG_PTR NumberOfBytesWritten;
    DWORD ThreadId;
    HANDLE hThread;
    DWORD ExitCode;

    if(hProcess != NULL)
    {
        RtlZeroMemory(&APIData, sizeof InjectCodeData);
        APIData.fLoadLibrary = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW"));
        APIData.fFreeLibrary = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeLibrary"));
        APIData.fGetModuleHandle = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetModuleHandleW"));
        APIData.fGetProcAddress = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress"));
        APIData.fVirtualFree = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualFree"));
        APIData.fExitProcess = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitProcess"));
        remCodeData = VirtualAllocEx(hProcess, NULL, remInjectSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        remStringData = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
        if(WriteProcessMemory(hProcess, (LPVOID)((ULONG_PTR)remStringData + sizeof InjectCodeData), (LPCVOID)szLibraryFile, lstrlenW(szLibraryFile) * 2, &NumberOfBytesWritten))
        {
            WriteProcessMemory(hProcess, remStringData, &APIData, sizeof InjectCodeData, &NumberOfBytesWritten);
            WriteProcessMemory(hProcess, remCodeData, (LPCVOID)&injectedRemoteLoadLibrary, remInjectSize, &NumberOfBytesWritten);
            if(WaitForThreadExit)
            {
                hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)remCodeData, remStringData, CREATE_SUSPENDED, &ThreadId);

                NtSetInformationThread(hThread, ThreadHideFromDebugger, NULL, NULL);

                ResumeThread(hThread);
                WaitForSingleObject(hThread, INFINITE);
                VirtualFreeEx(hProcess, remCodeData, NULL, MEM_RELEASE);
                VirtualFreeEx(hProcess, remStringData, NULL, MEM_RELEASE);
                if(GetExitCodeThread(hThread, &ExitCode))
                {
                    if(ExitCode == NULL)
                    {
                        return false;
                    }
                }
            }
            else
            {
                hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)remCodeData, remStringData, NULL, &ThreadId);
                for(i = 0; i < UE_MAX_RESERVED_MEMORY_LEFT; i++)
                {
                    if(engineReservedMemoryLeft[i] == NULL)
                    {
                        break;
                    }
                }
                engineReservedMemoryLeft[i] = (ULONG_PTR)remCodeData;
                engineReservedMemoryProcess = hProcess;
                ThreaderSetCallBackForNextExitThreadEvent((LPVOID)&injectedTerminator);
            }
            return true;
        }
        else
        {
            VirtualFreeEx(hProcess, remCodeData, NULL, MEM_RELEASE);
            VirtualFreeEx(hProcess, remStringData, NULL, MEM_RELEASE);
        }
    }
    return false;
}
__declspec(dllexport) bool TITCALL RemoteFreeLibrary(HANDLE hProcess, HMODULE hModule, char* szLibraryFile, bool WaitForThreadExit)
{

    wchar_t uniLibraryFile[MAX_PATH] = {};

    if(szLibraryFile != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szLibraryFile, lstrlenA(szLibraryFile) + 1, uniLibraryFile, sizeof(uniLibraryFile) / (sizeof(uniLibraryFile[0])));
        return(RemoteFreeLibraryW(hProcess, hModule, uniLibraryFile, WaitForThreadExit));
    }
    else
    {
        return false;
    }
}
__declspec(dllexport) bool TITCALL RemoteFreeLibraryW(HANDLE hProcess, HMODULE hModule, wchar_t* szLibraryFile, bool WaitForThreadExit)
{

    int i;
    InjectCodeData APIData;
    LPVOID remStringData;
    LPVOID remCodeData;
    ULONG_PTR remInjectSize1 = (ULONG_PTR)((ULONG_PTR)&injectedExitProcess - (ULONG_PTR)&injectedRemoteFreeLibrarySimple);
    ULONG_PTR remInjectSize2 = (ULONG_PTR)((ULONG_PTR)&injectedRemoteFreeLibrarySimple - (ULONG_PTR)&injectedRemoteFreeLibrary);
    ULONG_PTR NumberOfBytesWritten;
    DWORD ThreadId;
    HANDLE hThread;
    DWORD ExitCode;

    if(hProcess != NULL)
    {
        RtlZeroMemory(&APIData, sizeof InjectCodeData);
        APIData.fLoadLibrary = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW"));
        APIData.fFreeLibrary = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeLibrary"));
        APIData.fGetModuleHandle = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetModuleHandleW"));
        APIData.fGetProcAddress = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress"));
        APIData.fVirtualFree = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualFree"));
        APIData.fExitProcess = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitProcess"));
        APIData.fFreeLibraryHandle = hModule;
        remCodeData = VirtualAllocEx(hProcess, NULL, remInjectSize1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if(hModule == NULL)
        {
            remStringData = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
            if(WriteProcessMemory(hProcess, (LPVOID)((ULONG_PTR)remStringData + sizeof InjectCodeData), (LPCVOID)szLibraryFile, lstrlenW(szLibraryFile) * 2, &NumberOfBytesWritten))
            {
                WriteProcessMemory(hProcess, remStringData, &APIData, sizeof InjectCodeData, &NumberOfBytesWritten);
                WriteProcessMemory(hProcess, remCodeData, (LPCVOID)&injectedRemoteFreeLibrarySimple, remInjectSize1, &NumberOfBytesWritten);
                if(WaitForThreadExit)
                {
                    hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)remCodeData, remStringData, CREATE_SUSPENDED, &ThreadId);

                    NtSetInformationThread(hThread, ThreadHideFromDebugger, NULL, NULL);

                    ResumeThread(hThread);
                    WaitForSingleObject(hThread, INFINITE);
                    VirtualFreeEx(hProcess, remCodeData, NULL, MEM_RELEASE);
                    VirtualFreeEx(hProcess, remStringData, NULL, MEM_RELEASE);
                    if(GetExitCodeThread(hThread, &ExitCode))
                    {
                        if(ExitCode == NULL)
                        {
                            return false;
                        }
                    }
                }
                else
                {
                    hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)remCodeData, remStringData, NULL, &ThreadId);
                    for(i = 0; i < UE_MAX_RESERVED_MEMORY_LEFT; i++)
                    {
                        if(engineReservedMemoryLeft[i] == NULL)
                        {
                            break;
                        }
                    }
                    engineReservedMemoryLeft[i] = (ULONG_PTR)remCodeData;
                    engineReservedMemoryProcess = hProcess;
                    ThreaderSetCallBackForNextExitThreadEvent((LPVOID)&injectedTerminator);
                }
                return true;
            }
            else
            {
                VirtualFreeEx(hProcess, remCodeData, NULL, MEM_RELEASE);
                VirtualFreeEx(hProcess, remStringData, NULL, MEM_RELEASE);
            }
        }
        else
        {
            remStringData = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
            if(WriteProcessMemory(hProcess, remStringData, &APIData, sizeof InjectCodeData, &NumberOfBytesWritten))
            {
                WriteProcessMemory(hProcess, remCodeData, (LPCVOID)&injectedRemoteFreeLibrary, remInjectSize2, &NumberOfBytesWritten);
                if(WaitForThreadExit)
                {
                    hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)remCodeData, remStringData, CREATE_SUSPENDED, &ThreadId);
                    NtSetInformationThread(hThread, ThreadHideFromDebugger, NULL, NULL);
                    ResumeThread(hThread);
                    WaitForSingleObject(hThread, INFINITE);
                    VirtualFreeEx(hProcess, remCodeData, NULL, MEM_RELEASE);
                    if(GetExitCodeThread(hThread, &ExitCode))
                    {
                        if(ExitCode == NULL)
                        {
                            return false;
                        }
                    }
                }
                else
                {
                    hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)remCodeData, remStringData, NULL, &ThreadId);
                    for(i = 0; i < UE_MAX_RESERVED_MEMORY_LEFT; i++)
                    {
                        if(engineReservedMemoryLeft[i] == NULL)
                        {
                            break;
                        }
                    }
                    engineReservedMemoryLeft[i] = (ULONG_PTR)remCodeData;
                    engineReservedMemoryProcess = hProcess;
                    ThreaderSetCallBackForNextExitThreadEvent((LPVOID)&injectedTerminator);
                }
                return true;
            }
            else
            {
                VirtualFreeEx(hProcess, remCodeData, NULL, MEM_RELEASE);
                VirtualFreeEx(hProcess, remStringData, NULL, MEM_RELEASE);
            }
        }
    }
    return false;
}
__declspec(dllexport) bool TITCALL RemoteExitProcess(HANDLE hProcess, DWORD ExitCode)
{

    InjectCodeData APIData;
    LPVOID remCodeData;
    LPVOID remStringData;
    ULONG_PTR remInjectSize = (ULONG_PTR)((ULONG_PTR)&injectedTerminator - (ULONG_PTR)&injectedExitProcess);
    ULONG_PTR NumberOfBytesWritten;
    DWORD ThreadId;
    HANDLE hThread;

    if(hProcess != NULL)
    {
        RtlZeroMemory(&APIData, sizeof InjectCodeData);
        APIData.fLoadLibrary = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"));
        APIData.fFreeLibrary = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeLibrary"));
        APIData.fGetModuleHandle = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetModuleHandleA"));
        APIData.fGetProcAddress = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress"));
        APIData.fVirtualFree = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualFree"));
        APIData.fExitProcess = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitProcess"));
        APIData.fExitProcessCode = ExitCode;
        remStringData = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
        remCodeData = VirtualAllocEx(hProcess, NULL, remInjectSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if(WriteProcessMemory(hProcess, remCodeData, (LPCVOID)&injectedExitProcess, remInjectSize, &NumberOfBytesWritten))
        {
            WriteProcessMemory(hProcess, remStringData, &APIData, sizeof InjectCodeData, &NumberOfBytesWritten);
            hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)remCodeData, remStringData, NULL, &ThreadId);
            VirtualFreeEx(hProcess, remCodeData, NULL, MEM_RELEASE);
            return true;
        }
        else
        {
            VirtualFreeEx(hProcess, remCodeData, NULL, MEM_RELEASE);
            VirtualFreeEx(hProcess, remStringData, NULL, MEM_RELEASE);
        }
    }
    return false;
}
