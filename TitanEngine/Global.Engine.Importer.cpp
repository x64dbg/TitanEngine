#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.Importer.h"
#include "Global.Debugger.h"
#include <psapi.h>

ULONG_PTR EngineGetProcAddressRemote(HANDLE hProcess, const WCHAR * szDLLName, const char* szAPIName)
{
    if(!hProcess) //no process specified
    {
        if(!dbgProcessInformation.hProcess)
            hProcess = GetCurrentProcess();
        else
            hProcess = dbgProcessInformation.hProcess;
    }
    DWORD cbNeeded=0;
    if(EnumProcessModules(hProcess, 0, 0, &cbNeeded))
    {
        HMODULE* hMods=(HMODULE*)malloc(cbNeeded*sizeof(HMODULE));
        if(EnumProcessModules(hProcess, hMods, cbNeeded, &cbNeeded))
        {
            for(unsigned int i=0; i<cbNeeded/sizeof(HMODULE); i++)
            {
                wchar_t szModuleName[MAX_PATH]=L"";
                if(GetModuleFileNameExW(hProcess, hMods[i], szModuleName, _countof(szModuleName)))
                {
                    wchar_t* dllName=wcsrchr(szModuleName, L'\\');
                    if(dllName)
                    {
                        dllName++;
                        if(!_wcsicmp(dllName, szDLLName))
                        {
                            HMODULE hModule = LoadLibraryExW(szModuleName, 0, DONT_RESOLVE_DLL_REFERENCES|LOAD_LIBRARY_AS_DATAFILE);
                            if (hModule)
                            {
                                ULONG_PTR funcAddress=(ULONG_PTR)GetProcAddress(hModule, szAPIName);
                                if(funcAddress)
                                {
                                    funcAddress-=(ULONG_PTR)hModule; //rva
                                    FreeLibrary(hModule);
                                    return funcAddress+(ULONG_PTR)hMods[i]; //va
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }
        free(hMods);
    }
    return 0;
}

ULONG_PTR EngineGetProcAddressRemote(const WCHAR * szDLLName, const char* szAPIName)
{
    return EngineGetProcAddressRemote(0, szDLLName, szAPIName);
}

ULONG_PTR EngineGetProcAddressRemote(HANDLE hProcess, const char * szDLLName, const char* szAPIName)
{
    WCHAR uniDLLName[MAX_PATH] = {0};
    if (MultiByteToWideChar(CP_ACP, NULL, szDLLName, -1, uniDLLName, _countof(uniDLLName)))
    {
        return EngineGetProcAddressRemote(hProcess, uniDLLName, szAPIName);
    }
    else
    {
        return 0;
    }
}

ULONG_PTR EngineGetProcAddressRemote(const char * szDLLName, const char* szAPIName)
{
    return EngineGetProcAddressRemote(0, szDLLName, szAPIName);
}

ULONG_PTR EngineGetModuleBaseRemote(HANDLE hProcess, ULONG_PTR APIAddress)
{
    if(!hProcess) //no process specified
    {
        if(!dbgProcessInformation.hProcess)
            hProcess = GetCurrentProcess();
        else
            hProcess = dbgProcessInformation.hProcess;
    }
    DWORD cbNeeded=0;
    if(EnumProcessModules(hProcess, 0, 0, &cbNeeded))
    {
        HMODULE* hMods=(HMODULE*)malloc(cbNeeded*sizeof(HMODULE));
        if(EnumProcessModules(hProcess, hMods, cbNeeded, &cbNeeded))
        {
            for(unsigned int i=0; i<cbNeeded/sizeof(HMODULE); i++)
            {
                MODULEINFO modinfo;
                memset(&modinfo, 0, sizeof(MODULEINFO));
                if(GetModuleInformation(hProcess, hMods[i], &modinfo, sizeof(MODULEINFO)))
                {
                    ULONG_PTR start=(ULONG_PTR)hMods[i];
                    ULONG_PTR end=modinfo.SizeOfImage;
                    if(APIAddress>=start && APIAddress<end)
                        return start;
                }
            }
        }
        free(hMods);
    }
    return 0;
}
