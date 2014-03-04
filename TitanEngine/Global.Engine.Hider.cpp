#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.Hider.h"
#include "Global.Engine.h"
#include "Global.Debugger.h"

// Global.Engine.Hider.functions:
static bool isAtleastVista()
{
    static bool isAtleastVista=false;
    static bool isSet=false;
    if(isSet)
        return isAtleastVista;
    OSVERSIONINFO versionInfo= {0};
    versionInfo.dwOSVersionInfoSize=sizeof(OSVERSIONINFO);
    GetVersionEx(&versionInfo);
    isAtleastVista=versionInfo.dwMajorVersion >= 6;
    isSet=true;
    return isAtleastVista;
}

static bool isWindows64() //TODO: unclear behaviour, will return true when on wow64, but should not return true, because the system structures are x32 in that case
{
#ifdef _WIN64
    return true;
#else
    return false;
#endif;
    SYSTEM_INFO si = {0};
    typedef void (WINAPI *tGetNativeSystemInfo)(LPSYSTEM_INFO lpSystemInfo);
    tGetNativeSystemInfo _GetNativeSystemInfo = (tGetNativeSystemInfo)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetNativeSystemInfo");

    if (_GetNativeSystemInfo)
    {
        _GetNativeSystemInfo(&si);
    }
    else
    {
        GetSystemInfo(&si);
    }

    return (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64);
}

void FixAntidebugApiInProcess32(HANDLE hProcess, bool Hide)
{
    const BYTE patchCheckRemoteDebuggerPresent[5] =
    {
        0x33, 0xC0, //XOR EAX,EAX
        0xC2, 0x08, 0x00
    }; //RETN 0x8

    const BYTE patchGetTickCount[3] =
    {
        0x33, 0xC0, //XOR EAX,EAX
        0xC3
    }; //RETN

    ULONG_PTR APIPatchAddress = 0;
    DWORD OldProtect = 0;
    SIZE_T ueNumberOfBytesRead = 0;

    if(Hide)
    {
        APIPatchAddress = (ULONG_PTR)EngineGlobalAPIHandler(hProcess, NULL, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"),"CheckRemoteDebuggerPresent"), NULL, UE_OPTION_IMPORTER_REALIGN_APIADDRESS);

        if (VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)APIPatchAddress, sizeof(patchCheckRemoteDebuggerPresent), PAGE_EXECUTE_READWRITE, &OldProtect))
        {
            WriteProcessMemory(hProcess, (LPVOID)(APIPatchAddress), &patchCheckRemoteDebuggerPresent, sizeof(patchCheckRemoteDebuggerPresent), &ueNumberOfBytesRead);
            VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)APIPatchAddress, sizeof(patchCheckRemoteDebuggerPresent), OldProtect, &OldProtect);
        }


        APIPatchAddress = (ULONG_PTR)EngineGlobalAPIHandler(hProcess, NULL, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"),"GetTickCount"), NULL, UE_OPTION_IMPORTER_REALIGN_APIADDRESS);

        if (VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)APIPatchAddress, sizeof(patchGetTickCount), PAGE_EXECUTE_READWRITE, &OldProtect))
        {
            WriteProcessMemory(hProcess, (LPVOID)(APIPatchAddress), &patchGetTickCount, sizeof(patchGetTickCount), &ueNumberOfBytesRead);
            VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)APIPatchAddress, sizeof(patchGetTickCount), OldProtect, &OldProtect);
        }
    }
    else
    {
        APIPatchAddress = (ULONG_PTR)EngineGlobalAPIHandler(hProcess, NULL, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"),"CheckRemoteDebuggerPresent"), NULL, UE_OPTION_IMPORTER_REALIGN_APIADDRESS);

        if (VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)APIPatchAddress, sizeof(patchCheckRemoteDebuggerPresent), PAGE_EXECUTE_READWRITE, &OldProtect))
        {
            WriteProcessMemory(hProcess, (LPVOID)(APIPatchAddress), (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"),"CheckRemoteDebuggerPresent"), sizeof(patchCheckRemoteDebuggerPresent), &ueNumberOfBytesRead);
            VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)APIPatchAddress, sizeof(patchCheckRemoteDebuggerPresent), OldProtect, &OldProtect);
        }

        APIPatchAddress = (ULONG_PTR)EngineGlobalAPIHandler(hProcess, NULL, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"),"GetTickCount"), NULL, UE_OPTION_IMPORTER_REALIGN_APIADDRESS);

        if (VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)APIPatchAddress, sizeof(patchGetTickCount), PAGE_EXECUTE_READWRITE, &OldProtect))
        {
            WriteProcessMemory(hProcess, (LPVOID)(APIPatchAddress), (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"),"GetTickCount"), sizeof(patchGetTickCount), &ueNumberOfBytesRead);
            VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)APIPatchAddress, sizeof(patchGetTickCount), OldProtect, &OldProtect);
        }
    }
}


//Quote from The Ultimate Anti-Debugging Reference by Peter Ferrie
//Flags field exists at offset 0x0C in the heap on the 32-bit versions of Windows NT, Windows 2000, and Windows XP; and at offset 0x40 on the 32-bit versions of Windows Vista and later.
//Flags field exists at offset 0x14 in the heap on the 64-bit versions of Windows XP, and at offset 0x70 in the heap on the 64-bit versions of Windows Vista and later.
//ForceFlags field exists at offset 0x10 in the heap on the 32-bit versions of Windows NT, Windows 2000, and Windows XP; and at offset 0x44 on the 32-bit versions of Windows Vista and later.
//ForceFlags field exists at offset 0x18 in the heap on the 64-bit versions of Windows XP, and at offset 0x74 in the heap on the 64-bit versions of Windows Vista and later.

int getHeapFlagsOffset()
{
    if (isWindows64())
    {
        if (isAtleastVista())
        {
            return 0x70;
        }
        else
        {
            return 0x14;
        }
    }
    else
    {
        if (isAtleastVista())
        {
            return 0x40;
        }
        else
        {
            return 0x0C;
        }
    }
}

int getHeapForceFlagsOffset()
{
    if (isWindows64())
    {
        if (isAtleastVista())
        {
            return 0x74;
        }
        else
        {
            return 0x18;
        }
    }
    else
    {
        if (isAtleastVista())
        {
            return 0x44;
        }
        else
        {
            return 0x10;
        }
    }
}

bool FixPebInProcess(HANDLE hProcess, bool Hide)
{
    PEB_CURRENT myPEB = {0};
    SIZE_T ueNumberOfBytesRead = 0;
    void * heapFlagsAddress = 0;
    DWORD heapFlags = 0;
    void * heapForceFlagsAddress = 0;
    DWORD heapForceFlags = 0;

#ifndef _WIN64
    PEB64 myPEB64 = {0};
    void * AddressOfPEB64 = GetPEBLocation64(hProcess);
#endif

    void * AddressOfPEB = GetPEBLocation(hProcess);

    if (!AddressOfPEB)
        return false;

    if(ReadProcessMemory(hProcess, AddressOfPEB, (void*)&myPEB, sizeof(PEB_CURRENT), &ueNumberOfBytesRead))
    {
#ifndef _WIN64
        if (AddressOfPEB64)
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

            heapFlagsAddress = (void *)((LONG_PTR)myPEB.ProcessHeap + getHeapFlagsOffset());
            heapForceFlagsAddress = (void *)((LONG_PTR)myPEB.ProcessHeap + getHeapForceFlagsOffset());
            //TODO: finish Heap Flag Anti-Anti-Debug

            /*
            *(ULONG*)flagPtr_ &= HEAP_GROWABLE;
	        *(ULONG*)forceFlagPtr_ = 0;
            */

            //TODO: backup heap flags
            ULONG flagPtr_=0;
            ReadProcessMemory(hProcess, heapFlagsAddress, &flagPtr_, sizeof(ULONG), 0);
            ULONG forceFlagPtr_=0;
            ReadProcessMemory(hProcess, heapForceFlagsAddress, &forceFlagPtr_, sizeof(ULONG), 0);

            flagPtr_&=HEAP_GROWABLE;
            forceFlagPtr_=0;

            WriteProcessMemory(hProcess, heapFlagsAddress, &flagPtr_, sizeof(ULONG), 0);
            WriteProcessMemory(hProcess, heapForceFlagsAddress, &forceFlagPtr_, sizeof(ULONG), 0);
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
            if (AddressOfPEB64)
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
        if (FixPebInProcess(hProcess, Hide))
        {
            if(PatchAPILevel == UE_HIDE_BASIC)
            {
#ifndef _WIN64
                FixAntidebugApiInProcess32(hProcess, Hide);
#endif
            }

            return true;
        }
    }

    return false;
}

#ifndef _WIN64
typedef BOOL (WINAPI * tIsWow64Process)(HANDLE hProcess,PBOOL Wow64Process);

bool IsThisProcessWow64()
{
    BOOL bIsWow64 = FALSE;
    tIsWow64Process fnIsWow64Process = (tIsWow64Process)GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsWow64Process");

    if (fnIsWow64Process)
    {
        fnIsWow64Process(GetCurrentProcess(), &bIsWow64);
    }

    return (bIsWow64 != FALSE);
}

#endif