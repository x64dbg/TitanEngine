#include "stdafx.h"
#include "definitions.h"
#include "Global.Handle.h"
#include "Global.Engine.h"
#include <psapi.h>

// TitanEngine.Process.functions:
__declspec(dllexport) long TITCALL GetActiveProcessId(char* szImageName)
{

    wchar_t uniImageName[MAX_PATH] = {};

    if(szImageName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szImageName, lstrlenA(szImageName)+1, uniImageName, sizeof(uniImageName)/(sizeof(uniImageName[0])));
        return(GetActiveProcessIdW(uniImageName));
    }
    else
    {
        return(NULL);
    }
}

__declspec(dllexport) long TITCALL GetActiveProcessIdW(wchar_t* szImageName)
{

    int i;
    wchar_t* szTranslatedProcName;
    DWORD bProcessId[1024] = {};
    wchar_t szProcessPath[1024] = {};
    DWORD pProcessIdCount = NULL;
    HANDLE hProcess;

    if(EnumProcesses(bProcessId, sizeof bProcessId, &pProcessIdCount))
    {
        for(i = 0; i < (int)pProcessIdCount; i++)
        {
            if(bProcessId[i] != NULL)
            {
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, bProcessId[i]);
                if(hProcess != NULL)
                {
                    if(GetProcessImageFileNameW(hProcess, szProcessPath, 1024) > NULL)
                    {
                        szTranslatedProcName = (wchar_t*)TranslateNativeNameW(szProcessPath);
                        lstrcpyW(szProcessPath, szTranslatedProcName);
                        VirtualFree((void*)szTranslatedProcName, NULL, MEM_RELEASE);
                        EngineCloseHandle(hProcess);
                        if(lstrcmpiW(szProcessPath, szImageName) == NULL)
                        {
                            return(bProcessId[i]);
                        }
                        else if(lstrcmpiW(EngineExtractFileNameW(szProcessPath), szImageName) == NULL)
                        {
                            return(bProcessId[i]);
                        }
                    }
                    else
                    {
                        EngineCloseHandle(hProcess);
                    }
                }
            }
        }
    }
    return(NULL);
}

__declspec(dllexport) void TITCALL EnumProcessesWithLibrary(char* szLibraryName, void* EnumFunction)
{

    int i;
    int j;
    typedef void(TITCALL *fEnumFunction)(DWORD ProcessId, HMODULE ModuleBaseAddress);
    fEnumFunction myEnumFunction = (fEnumFunction)EnumFunction;
    HMODULE EnumeratedModules[1024] = {};
    DWORD bProcessId[1024] = {};
    char szModuleName[1024] = {};
    DWORD pProcessIdCount = NULL;
    DWORD pModuleCount;
    HANDLE hProcess;

    if(EnumFunction != NULL)
    {
        if(EnumProcesses(bProcessId, sizeof bProcessId, &pProcessIdCount))
        {
            for(i = 0; i < (int)pProcessIdCount; i++)
            {
                if(bProcessId[i] != NULL)
                {
                    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, bProcessId[i]);
                    if(hProcess != NULL)
                    {
                        RtlZeroMemory(&EnumeratedModules[0], sizeof EnumeratedModules);
                        if(EnumProcessModules(hProcess, (HMODULE*)EnumeratedModules, sizeof EnumeratedModules, &pModuleCount))
                        {
                            for(j = 0; j < (int)pModuleCount; j++)
                            {
                                if(EnumeratedModules[j] != NULL)
                                {
                                    if(GetModuleBaseNameA(hProcess, EnumeratedModules[j], szModuleName, 1024) > NULL)
                                    {
                                        if(lstrcmpiA(szModuleName, szLibraryName) == NULL)
                                        {
                                            __try
                                            {
                                                myEnumFunction(bProcessId[i], EnumeratedModules[j]);
                                            }
                                            __except(EXCEPTION_EXECUTE_HANDLER)
                                            {
                                                EngineCloseHandle(hProcess);
                                                return;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        EngineCloseHandle(hProcess);
                    }
                }
            }
        }
    }
}