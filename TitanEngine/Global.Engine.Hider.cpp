#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.Hider.h"
#include "Global.Engine.h"
#include "Global.Engine.Importer.h"
#include "Global.Debugger.h"

// Global.Engine.Hider.functions:
static bool isAtleastVista()
{
    static bool isAtleastVista = false;
    static bool isSet = false;
    if(isSet)
        return isAtleastVista;
    OSVERSIONINFO versionInfo = {0};
    versionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&versionInfo);
    isAtleastVista = versionInfo.dwMajorVersion >= 6;
    isSet = true;
    return isAtleastVista;
}

//TODO: unclear behaviour, will return true when on wow64, but should not return true, because the system structures are x32 in that case
static bool isWindows64()
{
    SYSTEM_INFO si = {0};
    typedef void (WINAPI * tGetNativeSystemInfo)(LPSYSTEM_INFO lpSystemInfo);
    tGetNativeSystemInfo _GetNativeSystemInfo = (tGetNativeSystemInfo)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetNativeSystemInfo");

    if(_GetNativeSystemInfo)
    {
        _GetNativeSystemInfo(&si);
    }
    else
    {
        GetSystemInfo(&si);
    }

    return (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64);
}

static void FixAntidebugApiInProcess(HANDLE hProcess, bool Hide, bool x64)
{
    const BYTE patchCheckRemoteDebuggerPresent32[5] =
    {
        0x33, 0xC0,      //XOR EAX,EAX
        0xC2, 0x08, 0x00 //RETN 0x8
    };
    const BYTE patchGetTickCount32[3] =
    {
        0x33, 0xC0, //XOR EAX,EAX
        0xC3        //RETN
    };
    const BYTE patchCheckRemoteDebuggerPresent64[4] =
    {
        0x48, 0x31, 0xC0, //XOR RAX,RAX
        0xC3  //RETN
    };
    const BYTE patchGetTickCount64[4] =
    {
        0x48, 0x31, 0xC0, //XOR RAX,RAX
        0xC3 //RETN
    };

    const BYTE* patchCheckRemoteDebuggerPresent;
    int patchCheckRemoteDebuggerPresentSize;
    const BYTE* patchGetTickCount;
    int patchGetTickCountSize;

    if(x64) //x64 patches
    {
        patchCheckRemoteDebuggerPresent = patchCheckRemoteDebuggerPresent64;
        patchCheckRemoteDebuggerPresentSize = sizeof(patchCheckRemoteDebuggerPresent64);
        patchGetTickCount = patchGetTickCount64;
        patchGetTickCountSize = sizeof(patchGetTickCount64);
    }
    else //x86 patches
    {
        patchCheckRemoteDebuggerPresent = patchCheckRemoteDebuggerPresent32;
        patchCheckRemoteDebuggerPresentSize = sizeof(patchCheckRemoteDebuggerPresent32);
        patchGetTickCount = patchGetTickCount32;
        patchGetTickCountSize = sizeof(patchGetTickCount32);
    }

    ULONG_PTR APIPatchAddress = 0;
    DWORD OldProtect = 0;
    SIZE_T ueNumberOfBytesRead = 0;

    if(Hide)
    {
        APIPatchAddress = EngineGetProcAddressRemote(hProcess, L"kernel32.dll", "CheckRemoteDebuggerPresent");
        if(VirtualProtectEx(hProcess, (LPVOID)APIPatchAddress, patchCheckRemoteDebuggerPresentSize, PAGE_EXECUTE_READWRITE, &OldProtect))
        {
            WriteProcessMemory(hProcess, (LPVOID)(APIPatchAddress), &patchCheckRemoteDebuggerPresent, patchCheckRemoteDebuggerPresentSize, &ueNumberOfBytesRead);
            VirtualProtectEx(hProcess, (LPVOID)APIPatchAddress, patchCheckRemoteDebuggerPresentSize, OldProtect, &OldProtect);
        }

        APIPatchAddress = EngineGetProcAddressRemote(hProcess, L"kernel32.dll", "GetTickCount");
        if(VirtualProtectEx(hProcess, (LPVOID)APIPatchAddress, patchGetTickCountSize, PAGE_EXECUTE_READWRITE, &OldProtect))
        {
            WriteProcessMemory(hProcess, (LPVOID)(APIPatchAddress), &patchGetTickCount, patchGetTickCountSize, &ueNumberOfBytesRead);
            VirtualProtectEx(hProcess, (LPVOID)APIPatchAddress, patchGetTickCountSize, OldProtect, &OldProtect);
        }
    }
    else
    {
        APIPatchAddress = EngineGetProcAddressRemote(hProcess, L"kernel32.dll", "CheckRemoteDebuggerPresent");
        if(VirtualProtectEx(hProcess, (LPVOID)APIPatchAddress, patchCheckRemoteDebuggerPresentSize, PAGE_EXECUTE_READWRITE, &OldProtect))
        {
            WriteProcessMemory(hProcess, (LPVOID)(APIPatchAddress), (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CheckRemoteDebuggerPresent"), patchCheckRemoteDebuggerPresentSize, &ueNumberOfBytesRead);
            VirtualProtectEx(hProcess, (LPVOID)APIPatchAddress, patchCheckRemoteDebuggerPresentSize, OldProtect, &OldProtect);
        }

        APIPatchAddress = EngineGetProcAddressRemote(hProcess, L"kernel32.dll", "GetTickCount");
        if(VirtualProtectEx(hProcess, (LPVOID)APIPatchAddress, patchGetTickCountSize, PAGE_EXECUTE_READWRITE, &OldProtect))
        {
            WriteProcessMemory(hProcess, (LPVOID)(APIPatchAddress), (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetTickCount"), patchGetTickCountSize, &ueNumberOfBytesRead);
            VirtualProtectEx(hProcess, (LPVOID)APIPatchAddress, patchGetTickCountSize, OldProtect, &OldProtect);
        }
    }

    FlushInstructionCache(hProcess, NULL, 0);
}

//Quote from The Ultimate Anti-Debugging Reference by Peter Ferrie
//Flags field exists at offset 0x0C in the heap on the 32-bit versions of Windows NT, Windows 2000, and Windows XP; and at offset 0x40 on the 32-bit versions of Windows Vista and later.
//Flags field exists at offset 0x14 in the heap on the 64-bit versions of Windows XP, and at offset 0x70 in the heap on the 64-bit versions of Windows Vista and later.
//ForceFlags field exists at offset 0x10 in the heap on the 32-bit versions of Windows NT, Windows 2000, and Windows XP; and at offset 0x44 on the 32-bit versions of Windows Vista and later.
//ForceFlags field exists at offset 0x18 in the heap on the 64-bit versions of Windows XP, and at offset 0x74 in the heap on the 64-bit versions of Windows Vista and later.

static int getHeapFlagsOffset(bool x64)
{
    if(x64)  //x64 offsets
    {
        if(isAtleastVista())
        {
            return 0x70;
        }
        else
        {
            return 0x14;
        }
    }
    else //x86 offsets
    {
        if(isAtleastVista())
        {
            return 0x40;
        }
        else
        {
            return 0x0C;
        }
    }
}

static int getHeapForceFlagsOffset(bool x64)
{
    if(x64)  //x64 offsets
    {
        if(isAtleastVista())
        {
            return 0x74;
        }
        else
        {
            return 0x18;
        }
    }
    else //x86 offsets
    {
        if(isAtleastVista())
        {
            return 0x44;
        }
        else
        {
            return 0x10;
        }
    }
}

static bool FixPebInProcess(HANDLE hProcess, bool Hide)
{
    PEB_CURRENT myPEB = {0};
    SIZE_T ueNumberOfBytesRead = 0;
    void* heapFlagsAddress = 0;
    DWORD heapFlags = 0;
    void* heapForceFlagsAddress = 0;
    DWORD heapForceFlags = 0;

#ifndef _WIN64
    PEB64 myPEB64 = {0};
    void* AddressOfPEB64 = GetPEBLocation64(hProcess);
#endif

    void* AddressOfPEB = GetPEBLocation(hProcess);

    if(!AddressOfPEB)
        return false;

    if(ReadProcessMemory(hProcess, AddressOfPEB, (void*)&myPEB, sizeof(PEB_CURRENT), &ueNumberOfBytesRead))
    {
#ifndef _WIN64
        if(AddressOfPEB64)
        {
            ReadProcessMemory(hProcess, AddressOfPEB64, (void*)&myPEB64, sizeof(PEB64), &ueNumberOfBytesRead);
        }
#endif

        if(Hide)
        {
            //TODO: backup GlobalFlag
            myPEB.BeingDebugged = FALSE;
            myPEB.NtGlobalFlag &= ~0x70;

#ifndef _WIN64
            myPEB64.BeingDebugged = FALSE;
            myPEB64.NtGlobalFlag &= ~0x70;
#endif

            //TODO: backup heap flags
#ifdef _WIN64
            heapFlagsAddress = (void*)((LONG_PTR)myPEB.ProcessHeap + getHeapFlagsOffset(true));
            heapForceFlagsAddress = (void*)((LONG_PTR)myPEB.ProcessHeap + getHeapForceFlagsOffset(true));
#else
            heapFlagsAddress = (void*)((LONG_PTR)myPEB.ProcessHeap + getHeapFlagsOffset(false));
            heapForceFlagsAddress = (void*)((LONG_PTR)myPEB.ProcessHeap + getHeapForceFlagsOffset(false));
#endif //_WIN64
            ReadProcessMemory(hProcess, heapFlagsAddress, &heapFlags, sizeof(DWORD), 0);
            ReadProcessMemory(hProcess, heapForceFlagsAddress, &heapForceFlags, sizeof(DWORD), 0);

            heapFlags &= HEAP_GROWABLE;
            heapForceFlags = 0;

            WriteProcessMemory(hProcess, heapFlagsAddress, &heapFlags, sizeof(DWORD), 0);
            WriteProcessMemory(hProcess, heapForceFlagsAddress, &heapForceFlags, sizeof(DWORD), 0);
        }
        else
        {
            myPEB.BeingDebugged = TRUE;
#ifndef _WIN64
            myPEB64.BeingDebugged = TRUE;
#endif
        }

        if(WriteProcessMemory(hProcess, AddressOfPEB, (void*)&myPEB, sizeof(PEB_CURRENT), &ueNumberOfBytesRead))
        {
#ifndef _WIN64
            if(AddressOfPEB64)
            {
                WriteProcessMemory(hProcess, AddressOfPEB64, (void*)&myPEB64, sizeof(PEB64), &ueNumberOfBytesRead);
            }
#endif
            return true;
        }
    }
    return false;
}

bool ChangeHideDebuggerState(HANDLE hProcess, DWORD PatchAPILevel, bool Hide)
{
    if(hProcess)
    {
        if(FixPebInProcess(hProcess, Hide))
        {
            if(PatchAPILevel == UE_HIDE_BASIC)
            {
#ifdef _WIN64
                FixAntidebugApiInProcess(hProcess, Hide, true);
#else
                FixAntidebugApiInProcess(hProcess, Hide, false);
#endif
            }
            return true;
        }
    }

    return false;
}

#ifndef _WIN64
bool IsThisProcessWow64()
{
    typedef BOOL (WINAPI * tIsWow64Process)(HANDLE hProcess, PBOOL Wow64Process);
    BOOL bIsWow64 = FALSE;
    tIsWow64Process fnIsWow64Process = (tIsWow64Process)GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsWow64Process");

    if(fnIsWow64Process)
    {
        fnIsWow64Process(GetCurrentProcess(), &bIsWow64);
    }

    return (bIsWow64 != FALSE);
}
#endif