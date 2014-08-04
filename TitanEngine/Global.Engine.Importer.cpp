#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.h"
#include "Global.Engine.Importer.h"
#include "Global.Debugger.h"
#include "Global.Mapping.h"

ULONG_PTR EngineGetProcAddressRemote(HANDLE hProcess, const wchar_t* szDLLName, const char* szAPIName)
{
    if(!hProcess) //no process specified
    {
        if(!dbgProcessInformation.hProcess)
            hProcess = GetCurrentProcess();
        else
            hProcess = dbgProcessInformation.hProcess;
    }
    DWORD cbNeeded = 0;
    if(EnumProcessModules(hProcess, 0, 0, &cbNeeded))
    {
        HMODULE* hMods = (HMODULE*)malloc(cbNeeded * sizeof(HMODULE));
        if(EnumProcessModules(hProcess, hMods, cbNeeded, &cbNeeded))
        {
            for(unsigned int i = 0; i < cbNeeded / sizeof(HMODULE); i++)
            {
                wchar_t szModuleName[MAX_PATH] = L"";
                if(GetModuleFileNameExW(hProcess, hMods[i], szModuleName, _countof(szModuleName)))
                {
                    wchar_t* dllName = wcsrchr(szModuleName, L'\\');
                    if(dllName)
                    {
                        dllName++;
                        if(!_wcsicmp(dllName, szDLLName))
                        {
                            HMODULE hModule = LoadLibraryExW(szModuleName, 0, DONT_RESOLVE_DLL_REFERENCES | LOAD_LIBRARY_AS_DATAFILE);
                            if(hModule)
                            {
                                ULONG_PTR funcAddress = (ULONG_PTR)GetProcAddress(hModule, szAPIName);
                                if(funcAddress)
                                {
                                    funcAddress -= (ULONG_PTR)hModule; //rva
                                    FreeLibrary(hModule);
                                    return funcAddress + (ULONG_PTR)hMods[i]; //va
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

ULONG_PTR EngineGetProcAddressRemote(HANDLE hProcess, const char* szDLLName, const char* szAPIName)
{
    WCHAR uniDLLName[MAX_PATH] = {0};
    if(MultiByteToWideChar(CP_ACP, NULL, szDLLName, -1, uniDLLName, _countof(uniDLLName)))
    {
        return EngineGetProcAddressRemote(hProcess, uniDLLName, szAPIName);
    }
    else
    {
        return 0;
    }
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
    DWORD cbNeeded = 0;
    if(EnumProcessModules(hProcess, 0, 0, &cbNeeded))
    {
        HMODULE* hMods = (HMODULE*)malloc(cbNeeded * sizeof(HMODULE));
        if(EnumProcessModules(hProcess, hMods, cbNeeded, &cbNeeded))
        {
            for(unsigned int i = 0; i < cbNeeded / sizeof(HMODULE); i++)
            {
                MODULEINFO modinfo;
                memset(&modinfo, 0, sizeof(MODULEINFO));
                if(GetModuleInformation(hProcess, hMods[i], &modinfo, sizeof(MODULEINFO)))
                {
                    ULONG_PTR start = (ULONG_PTR)hMods[i];
                    ULONG_PTR end = start + modinfo.SizeOfImage;
                    if(APIAddress >= start && APIAddress < end)
                        return start;
                }
            }
        }
        free(hMods);
    }
    return 0;
}

ULONG_PTR EngineGetModuleBaseRemote(HANDLE hProcess, const wchar_t* szDLLName)
{
    if(!hProcess) //no process specified
    {
        if(!dbgProcessInformation.hProcess)
            hProcess = GetCurrentProcess();
        else
            hProcess = dbgProcessInformation.hProcess;
    }
    DWORD cbNeeded = 0;
    if(EnumProcessModules(hProcess, 0, 0, &cbNeeded))
    {
        HMODULE* hMods = (HMODULE*)malloc(cbNeeded * sizeof(HMODULE));
        if(EnumProcessModules(hProcess, hMods, cbNeeded, &cbNeeded))
        {
            for(unsigned int i = 0; i < cbNeeded / sizeof(HMODULE); i++)
            {
                wchar_t szModuleName[MAX_PATH] = L"";
                if(GetModuleFileNameExW(hProcess, hMods[i], szModuleName, _countof(szModuleName)))
                {
                    wchar_t* dllName = wcsrchr(szModuleName, L'\\');
                    if(dllName)
                    {
                        dllName++;
                        if(!_wcsicmp(dllName, szDLLName))
                        {
                            return (ULONG_PTR)hMods[i];
                        }
                    }
                }
            }
        }
        free(hMods);
    }
    return 0;
}

ULONG_PTR EngineGetModuleBaseRemote(HANDLE hProcess, const char* szDLLName)
{
    WCHAR uniDLLName[MAX_PATH] = {0};
    if(MultiByteToWideChar(CP_ACP, NULL, szDLLName, -1, uniDLLName, _countof(uniDLLName)))
    {
        return EngineGetModuleBaseRemote(hProcess, szDLLName);
    }
    else
    {
        return 0;
    }
}

ULONG_PTR EngineGetAddressRemote(HANDLE hProcess, ULONG_PTR Address)
{
    HMODULE localModuleBase = (HMODULE)EngineGetModuleBaseRemote(GetCurrentProcess(), Address);
    if(localModuleBase)
    {
        wchar_t szModuleName[MAX_PATH] = L"";
        if(GetModuleFileNameExW(hProcess, localModuleBase, szModuleName, _countof(szModuleName)))
        {
            wchar_t* dllName = wcsrchr(szModuleName, L'\\');
            if(dllName)
            {
                dllName++;
                ULONG_PTR remoteModuleBase = EngineGetModuleBaseRemote(hProcess, dllName);
                if(remoteModuleBase)
                {
                    Address -= (ULONG_PTR)localModuleBase; //rva
                    return Address + remoteModuleBase;
                }
            }
        }
    }
    return 0;
}

ULONG_PTR EngineGetAddressLocal(HANDLE hProcess, ULONG_PTR Address)
{
    HMODULE remoteModuleBase = (HMODULE)EngineGetModuleBaseRemote(hProcess, Address);
    if(remoteModuleBase)
    {
        wchar_t szModuleName[MAX_PATH] = L"";
        if(GetModuleFileNameExW(hProcess, remoteModuleBase, szModuleName, _countof(szModuleName)))
        {
            wchar_t* dllName = wcsrchr(szModuleName, L'\\');
            if(dllName)
            {
                dllName++;
                ULONG_PTR localModuleBase = EngineGetModuleBaseRemote(GetCurrentProcess(), dllName);
                if(localModuleBase)
                {
                    Address -= (ULONG_PTR)remoteModuleBase; //rva
                    return Address + localModuleBase;
                }
            }
        }
    }
    return 0;
}

bool EngineGetAPINameRemote(HANDLE hProcess, ULONG_PTR APIAddress, char* APIName, DWORD APINameSize, DWORD* APINameSizeNeeded)
{
    if(!hProcess) //no process specified
    {
        if(!dbgProcessInformation.hProcess)
            hProcess = GetCurrentProcess();
        else
            hProcess = dbgProcessInformation.hProcess;
    }
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    ULONG_PTR ModuleBase = EngineGetModuleBaseRemote(hProcess, APIAddress);
    if(!ModuleBase)
        return false;
    wchar_t szModulePath[MAX_PATH] = L"";
    if(!GetModuleFileNameExW(hProcess, (HMODULE)ModuleBase, szModulePath, _countof(szModulePath)))
        return false;
    if(MapFileExW(szModulePath, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, 0))
    {
        PIMAGE_DOS_HEADER DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
        if(EngineValidateHeader(FileMapVA, NULL, NULL, DOSHeader, true))
        {
            PIMAGE_NT_HEADERS32 PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            PIMAGE_NT_HEADERS64 PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            ULONG_PTR ExportDirectoryVA;
            DWORD ExportDirectorySize;
            ULONG_PTR ImageBase;
            if(PEHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            {
                ImageBase = PEHeader32->OptionalHeader.ImageBase;
                ExportDirectoryVA = (ULONG_PTR)PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                ExportDirectorySize = (ULONG_PTR)PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            }
            else //x64
            {
                ImageBase = (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase;
                ExportDirectoryVA = (ULONG_PTR)PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                ExportDirectorySize = (ULONG_PTR)PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            }
            PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)ConvertVAtoFileOffset(FileMapVA, ExportDirectoryVA + ImageBase, true);
            if(ExportDirectory)
            {
                DWORD* AddrOfFunctions = (DWORD*)ConvertVAtoFileOffset(FileMapVA, ExportDirectory->AddressOfFunctions + ImageBase, true);
                DWORD* AddrOfNames = (DWORD*)ConvertVAtoFileOffset(FileMapVA, ExportDirectory->AddressOfNames + ImageBase, true);
                SHORT* AddrOfNameOrdinals = (SHORT*)ConvertVAtoFileOffset(FileMapVA, ExportDirectory->AddressOfNameOrdinals + ImageBase, true);
                if(AddrOfFunctions && AddrOfNames && AddrOfNameOrdinals)
                {
                    unsigned int NumberOfNames = ExportDirectory->NumberOfNames;
                    for(unsigned int i = 0; i < NumberOfNames; i++)
                    {
                        const char* curName = (const char*)ConvertVAtoFileOffset(FileMapVA, AddrOfNames[i] + ImageBase, true);
                        if(!curName)
                            continue;
                        unsigned int curRva = AddrOfFunctions[AddrOfNameOrdinals[i]];
                        if(curRva < ExportDirectoryVA || curRva >= ExportDirectoryVA + ExportDirectorySize) //non-forwarded exports
                        {
                            if(curRva + ModuleBase == APIAddress)
                            {
                                if(APIName && APINameSize > strlen(curName))
                                {
                                    strcpy(APIName, curName);
                                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                                    return true;
                                }
                                if(APINameSizeNeeded)
                                {
                                    *APINameSizeNeeded = (DWORD)strlen(curName);
                                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
    }
    return false;
}

DWORD EngineGetAPIOrdinalRemote(HANDLE hProcess, ULONG_PTR APIAddress)
{
    if(!hProcess) //no process specified
    {
        if(!dbgProcessInformation.hProcess)
            hProcess = GetCurrentProcess();
        else
            hProcess = dbgProcessInformation.hProcess;
    }
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    ULONG_PTR ModuleBase = EngineGetModuleBaseRemote(hProcess, APIAddress);
    if(!ModuleBase)
        return 0;
    wchar_t szModulePath[MAX_PATH] = L"";
    if(!GetModuleFileNameExW(hProcess, (HMODULE)ModuleBase, szModulePath, _countof(szModulePath)))
        return 0;
    if(MapFileExW(szModulePath, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, 0))
    {
        PIMAGE_DOS_HEADER DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
        if(EngineValidateHeader(FileMapVA, NULL, NULL, DOSHeader, true))
        {
            PIMAGE_NT_HEADERS32 PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            PIMAGE_NT_HEADERS64 PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            ULONG_PTR ExportDirectoryVA;
            DWORD ExportDirectorySize;
            ULONG_PTR ImageBase;
            if(PEHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            {
                ImageBase = PEHeader32->OptionalHeader.ImageBase;
                ExportDirectoryVA = (ULONG_PTR)PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                ExportDirectorySize = (ULONG_PTR)PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            }
            else //x64
            {
                ImageBase = (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase;
                ExportDirectoryVA = (ULONG_PTR)PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                ExportDirectorySize = (ULONG_PTR)PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            }
            PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)ConvertVAtoFileOffset(FileMapVA, ExportDirectoryVA + ImageBase, true);
            if(ExportDirectory)
            {
                DWORD* AddrOfFunctions = (DWORD*)ConvertVAtoFileOffset(FileMapVA, ExportDirectory->AddressOfFunctions + ImageBase, true);
                if(AddrOfFunctions)
                {
                    unsigned int NumberOfFunctions = ExportDirectory->NumberOfFunctions;
                    for(unsigned int i = 0, j = 0; i < NumberOfFunctions; i++)
                    {
                        unsigned int curRva = AddrOfFunctions[i];
                        if(!curRva)
                            continue;
                        j++; //ordinal
                        if(curRva < ExportDirectoryVA || curRva >= ExportDirectoryVA + ExportDirectorySize) //non-forwarded exports
                        {
                            if(curRva + ModuleBase == APIAddress)
                            {
                                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                                return j;
                            }
                        }
                    }
                }
            }
        }
        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
    }
    return 0;
}
