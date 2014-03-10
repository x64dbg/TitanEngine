#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.Importer.h"
#include "Global.Debugger.h"
#include <psapi.h>

ULONG_PTR EngineGetProcAddressRemote(HANDLE hProcess, const WCHAR * szDLLName, const char* szAPIName)
{
    if(!hProcess) //no process specified
    {
        if(dbgProcessInformation.hProcess == 0)
        {
            hProcess = GetCurrentProcess();
        }
        else
        {
            hProcess = dbgProcessInformation.hProcess;
        }
    }
    DWORD cbNeeded = 0;
    HMODULE EnumeratedModules[1024] = {0};
    WCHAR RemoteDLLPath[MAX_PATH] = {0};
    HMODULE hModuleLocal = GetModuleHandleW(szDLLName);
    WCHAR * dllName;

    if(EnumProcessModules(hProcess, EnumeratedModules, sizeof(EnumeratedModules), &cbNeeded))
    {
        for(int i = 0; i < (int)(cbNeeded / sizeof(HMODULE)); i++)
        {
            RemoteDLLPath[0] = 0;
            if(GetModuleFileNameExW(hProcess, EnumeratedModules[i], RemoteDLLPath, _countof(RemoteDLLPath)) > 0)
            {
                dllName = wcsrchr(RemoteDLLPath, L'\\');
                if (dllName)
                {
                    dllName++;
                    if(_wcsicmp(dllName, szDLLName) == 0)
                    {
                        LONG_PTR funcAddress = 0;

                        if (hModuleLocal)
                        {
                            funcAddress = (LONG_PTR)GetProcAddress(hModuleLocal, szAPIName);
                            if (funcAddress)
                            {
                                return (LONG_PTR)funcAddress - (LONG_PTR)hModuleLocal + (LONG_PTR)EnumeratedModules[i];
                            }
                        }
                        else
                        {
                            hModuleLocal = LoadLibraryExW(RemoteDLLPath, 0, DONT_RESOLVE_DLL_REFERENCES);
                            if (hModuleLocal)
                            {
                                funcAddress = (LONG_PTR)GetProcAddress(hModuleLocal, szAPIName);
                                funcAddress = (LONG_PTR)funcAddress - (LONG_PTR)hModuleLocal + (LONG_PTR)EnumeratedModules[i];
                                FreeLibrary(hModuleLocal);
                                return funcAddress;
                            }
                        }
                        break;
                    }
                }
            }
        }
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