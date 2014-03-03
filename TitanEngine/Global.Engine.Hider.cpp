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

bool ChangeHideDebuggerState(HANDLE hProcess, DWORD PatchAPILevel, bool Hide)
{
    static ULONG OldHeapFlags=0;
    static ULONG OldForceFlag=0;
    ULONG_PTR AddressOfPEB = NULL;
    ULONG_PTR ueNumberOfBytesRead = NULL;
    BYTE patchCheckRemoteDebuggerPresent[5] = {0x33, 0xC0, 0xC2, 0x08, 0x00};
    BYTE patchGetTickCount[3] = {0x33, 0xC0, 0xC3};
    MEMORY_BASIC_INFORMATION MemInfo;
    ULONG_PTR APIPatchAddress = NULL;
    DWORD OldProtect;
    NTPEB myPEB = {};

    if(hProcess != NULL)
    {
        AddressOfPEB = (ULONG_PTR)GetPEBLocation(hProcess);
        if(ReadProcessMemory(hProcess, (void*)AddressOfPEB, (void*)&myPEB, sizeof NTPEB, &ueNumberOfBytesRead))
        {
            if(Hide)
            {
                myPEB.BeingDebugged = false;
                myPEB.NtGlobalFlag = NULL;
                //Fix heap flags: https://github.com/eschweiler/ProReversing
                BYTE* Heap=(BYTE*)myPEB.ProcessHeap;

                if(WriteProcessMemory(hProcess, (void*)AddressOfPEB, (void*)&myPEB, sizeof NTPEB, &ueNumberOfBytesRead))
                {
                    if(PatchAPILevel == UE_HIDE_BASIC)
                    {
                        APIPatchAddress = (ULONG_PTR)EngineGlobalAPIHandler(hProcess, NULL, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"),"CheckRemoteDebuggerPresent"), NULL, UE_OPTION_IMPORTER_REALIGN_APIADDRESS);
                        VirtualQueryEx(dbgProcessInformation.hProcess, (LPVOID)APIPatchAddress, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
                        OldProtect = MemInfo.Protect;
                        VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)APIPatchAddress, 5, PAGE_EXECUTE_READWRITE, &OldProtect);
                        WriteProcessMemory(hProcess, (LPVOID)(APIPatchAddress), &patchCheckRemoteDebuggerPresent, 5, &ueNumberOfBytesRead);

                        APIPatchAddress = (ULONG_PTR)EngineGlobalAPIHandler(hProcess, NULL, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"),"GetTickCount"), NULL, UE_OPTION_IMPORTER_REALIGN_APIADDRESS);
                        VirtualQueryEx(dbgProcessInformation.hProcess, (LPVOID)APIPatchAddress, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
                        OldProtect = MemInfo.Protect;
                        VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)APIPatchAddress, 3, PAGE_EXECUTE_READWRITE, &OldProtect);
                        WriteProcessMemory(hProcess, (LPVOID)(APIPatchAddress), &patchGetTickCount, 3, &ueNumberOfBytesRead);
                    }
                    return(true);
                }
                else
                {
                    return(false);
                }
            }
            else
            {
                myPEB.BeingDebugged = true;
                if(WriteProcessMemory(hProcess, (void*)AddressOfPEB, (void*)&myPEB, sizeof NTPEB, &ueNumberOfBytesRead))
                {
                    if(PatchAPILevel == UE_HIDE_BASIC)
                    {
                        APIPatchAddress = (ULONG_PTR)EngineGlobalAPIHandler(hProcess, NULL, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"),"CheckRemoteDebuggerPresent"), NULL, UE_OPTION_IMPORTER_REALIGN_APIADDRESS);
                        VirtualQueryEx(dbgProcessInformation.hProcess, (LPVOID)APIPatchAddress, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
                        OldProtect = MemInfo.Protect;
                        VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)APIPatchAddress, 5, PAGE_EXECUTE_READWRITE, &OldProtect);
                        WriteProcessMemory(hProcess, (LPVOID)(APIPatchAddress), (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"),"CheckRemoteDebuggerPresent"), 5, &ueNumberOfBytesRead);

                        APIPatchAddress = (ULONG_PTR)EngineGlobalAPIHandler(hProcess, NULL, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"),"GetTickCount"), NULL, UE_OPTION_IMPORTER_REALIGN_APIADDRESS);
                        VirtualQueryEx(dbgProcessInformation.hProcess, (LPVOID)APIPatchAddress, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
                        OldProtect = MemInfo.Protect;
                        VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)APIPatchAddress, 3, PAGE_EXECUTE_READWRITE, &OldProtect);
                        WriteProcessMemory(hProcess, (LPVOID)(APIPatchAddress), (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"),"GetTickCount"), 3, &ueNumberOfBytesRead);
                    }
                    return(true);
                }
                else
                {
                    return(false);
                }
            }
        }
        else
        {
            return(false);
        }
    }
    else
    {
        return(false);
    }
    return(false);
}