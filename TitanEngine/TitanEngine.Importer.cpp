#include "stdafx.h"
#include "definitions.h"
#include "Global.Mapping.h"
#include "Global.Engine.h"
#include "Global.Librarian.h"
#include "Global.Engine.Importer.h"
#include "Global.Debugger.h"
#include "scylla_wrapper.h"

// TitanEngine.Importer.functions:
__declspec(dllexport) void TITCALL ImporterAddNewDll(char* szDLLName, ULONG_PTR FirstThunk)
{
    wchar_t uniDLLName[MAX_PATH] = {};

    MultiByteToWideChar(CP_ACP, NULL, szDLLName, lstrlenA(szDLLName) + 1, uniDLLName, sizeof(uniDLLName) / (sizeof(uniDLLName[0])));

    scylla_addModule(uniDLLName, FirstThunk);
}

__declspec(dllexport) void TITCALL ImporterAddNewAPI(char* szAPIName, ULONG_PTR ThunkValue)
{
    wchar_t uniAPIName[MAX_PATH] = {};

    MultiByteToWideChar(CP_ACP, NULL, szAPIName, lstrlenA(szAPIName) + 1, uniAPIName, sizeof(uniAPIName) / (sizeof(uniAPIName[0])));

    scylla_addImport(uniAPIName, ThunkValue);
}

__declspec(dllexport) void TITCALL ImporterAddNewOrdinalAPI(ULONG_PTR OrdinalNumber, ULONG_PTR ThunkValue)
{
    ImporterAddNewAPI((char*)(OrdinalNumber & ~IMAGE_ORDINAL_FLAG), ThunkValue);
}

__declspec(dllexport) long TITCALL ImporterGetAddedDllCount()
{
    return scylla_getModuleCount();
}

__declspec(dllexport) long TITCALL ImporterGetAddedAPICount()
{
    return scylla_getImportCount();
}

__declspec(dllexport) bool TITCALL ImporterExportIAT(ULONG_PTR StorePlace, ULONG_PTR FileMapVA, HANDLE hFileMap)
{
    return (scylla_fixMappedDump(StorePlace, FileMapVA, hFileMap) == SCY_ERROR_SUCCESS);
}

__declspec(dllexport) long TITCALL ImporterEstimatedSize()
{
    return scylla_estimatedIATSize();
}

__declspec(dllexport) bool TITCALL ImporterExportIATEx(char* szDumpFileName, char* szExportFileName, char* szSectionName)
{
    wchar_t uniExportFileName[MAX_PATH] = {};
    wchar_t uniDumpFileName[MAX_PATH] = {};
    wchar_t uniSectionName[MAX_PATH] = {};
    if(szExportFileName != NULL && szDumpFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szExportFileName, lstrlenA(szExportFileName) + 1, uniExportFileName, sizeof(uniExportFileName) / (sizeof(uniExportFileName[0])));
        MultiByteToWideChar(CP_ACP, NULL, szDumpFileName, lstrlenA(szDumpFileName) + 1, uniDumpFileName, sizeof(uniDumpFileName) / (sizeof(uniDumpFileName[0])));
        MultiByteToWideChar(CP_ACP, NULL, szSectionName, lstrlenA(szSectionName) + 1, uniSectionName, sizeof(uniSectionName) / (sizeof(uniSectionName[0])));
        return ImporterExportIATExW(uniDumpFileName, uniExportFileName, uniSectionName);
    }
    return false;
}

__declspec(dllexport) bool TITCALL ImporterExportIATExW(wchar_t* szDumpFileName, wchar_t* szExportFileName, wchar_t* szSectionName)
{
    return (scylla_fixDump(szDumpFileName, szExportFileName, szSectionName) == SCY_ERROR_SUCCESS);
}

__declspec(dllexport) ULONG_PTR TITCALL ImporterFindAPIWriteLocation(char* szAPIName)
{
    return scylla_findImportWriteLocation(szAPIName);
}

__declspec(dllexport) ULONG_PTR TITCALL ImporterFindOrdinalAPIWriteLocation(ULONG_PTR OrdinalNumber)
{
    return scylla_findOrdinalImportWriteLocation(OrdinalNumber);
}

__declspec(dllexport) ULONG_PTR TITCALL ImporterFindAPIByWriteLocation(ULONG_PTR APIWriteLocation)
{
    return scylla_findImportNameByWriteLocation(APIWriteLocation);
}

__declspec(dllexport) ULONG_PTR TITCALL ImporterFindDLLByWriteLocation(ULONG_PTR APIWriteLocation)
{
    return scylla_findModuleNameByWriteLocation(APIWriteLocation);
}

__declspec(dllexport) void* TITCALL ImporterGetDLLName(ULONG_PTR APIAddress)
{
    return ImporterGetDLLNameFromDebugee(GetCurrentProcess(), APIAddress);
}

__declspec(dllexport) void* TITCALL ImporterGetDLLNameW(ULONG_PTR APIAddress)
{
    return ImporterGetDLLNameFromDebugeeW(GetCurrentProcess(), APIAddress);
}

__declspec(dllexport) ULONG_PTR TITCALL ImporterGetRemoteAPIAddress(HANDLE hProcess, ULONG_PTR APIAddress)
{
    return EngineGetAddressRemote(hProcess, APIAddress);
}

__declspec(dllexport) ULONG_PTR TITCALL ImporterGetRemoteAPIAddressEx(char* szDLLName, char* szAPIName)
{
    return EngineGetProcAddressRemote(0, szDLLName, szAPIName);
}

__declspec(dllexport) ULONG_PTR TITCALL ImporterGetLocalAPIAddress(HANDLE hProcess, ULONG_PTR APIAddress)
{
    return EngineGetAddressLocal(hProcess, APIAddress);
}

__declspec(dllexport) void* TITCALL ImporterGetDLLNameFromDebugee(HANDLE hProcess, ULONG_PTR APIAddress)
{
    ULONG_PTR moduleBase = EngineGetModuleBaseRemote(hProcess, APIAddress);
    if(moduleBase)
    {
        static char szModuleName[MAX_PATH] = "";
        if(GetModuleFileNameExA(hProcess, (HMODULE)moduleBase, szModuleName, _countof(szModuleName)))
            return szModuleName;
    }
    return 0;
}

__declspec(dllexport) void* TITCALL ImporterGetDLLNameFromDebugeeW(HANDLE hProcess, ULONG_PTR APIAddress)
{
    ULONG_PTR moduleBase = EngineGetModuleBaseRemote(hProcess, APIAddress);
    if(moduleBase)
    {
        static wchar_t szModuleName[MAX_PATH] = L"";
        if(GetModuleFileNameExW(hProcess, (HMODULE)moduleBase, szModuleName, _countof(szModuleName)))
            return szModuleName;
    }
    return 0;
}

__declspec(dllexport) void* TITCALL ImporterGetRemoteDLLBaseExW(HANDLE hProcess, WCHAR* szModuleName)
{
    return (void*)EngineGetModuleBaseRemote(hProcess, szModuleName);
}

__declspec(dllexport) ULONG_PTR TITCALL ImporterGetRemoteDLLBaseEx(HANDLE hProcess, char* szModuleName)
{
    return EngineGetModuleBaseRemote(hProcess, szModuleName);
}

__declspec(dllexport) ULONG_PTR TITCALL ImporterGetRemoteDLLBase(HANDLE hProcess, HMODULE LocalModuleBase)
{
    return EngineGetAddressRemote(hProcess, (ULONG_PTR)LocalModuleBase);
}

__declspec(dllexport) void* TITCALL ImporterGetAPIName(ULONG_PTR APIAddress)
{
    return ImporterGetAPINameFromDebugee(GetCurrentProcess(), APIAddress);
}

__declspec(dllexport) ULONG_PTR TITCALL ImporterGetAPIOrdinalNumber(ULONG_PTR APIAddress)
{
    return ImporterGetAPIOrdinalNumberFromDebugee(GetCurrentProcess(), APIAddress);
}

__declspec(dllexport) void* TITCALL ImporterGetAPINameEx(ULONG_PTR APIAddress, ULONG_PTR DLLBasesList)
{
    //TODO: remove?
    return ImporterGetAPIName(APIAddress);
}

__declspec(dllexport) void* TITCALL ImporterGetAPINameFromDebugee(HANDLE hProcess, ULONG_PTR APIAddress)
{
    static char APIName[5000] = "";
    if(EngineGetAPINameRemote(hProcess, APIAddress, APIName, _countof(APIName), 0))
        return APIName;
    return 0;
}

__declspec(dllexport) ULONG_PTR TITCALL ImporterGetAPIOrdinalNumberFromDebugee(HANDLE hProcess, ULONG_PTR APIAddress)
{
    return EngineGetAPIOrdinalRemote(hProcess, APIAddress);
}

__declspec(dllexport) long TITCALL ImporterGetDLLIndexEx(ULONG_PTR APIAddress, ULONG_PTR DLLBasesList)
{
    //TODO: remove?
    return((DWORD)EngineGlobalAPIHandler(NULL, DLLBasesList, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_DLLINDEX));
}

__declspec(dllexport) long TITCALL ImporterGetDLLIndex(HANDLE hProcess, ULONG_PTR APIAddress, ULONG_PTR DLLBasesList)
{
    //TODO: remove?
    return((DWORD)EngineGlobalAPIHandler(hProcess, DLLBasesList, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_DLLINDEX));
}

__declspec(dllexport) bool TITCALL ImporterIsForwardedAPI(HANDLE hProcess, ULONG_PTR APIAddress)
{
    if((ULONG_PTR)EngineGlobalAPIHandler(hProcess, NULL, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_FORWARDER_DLLINDEX) > NULL)
    {
        return true;
    }
    else
    {
        return false;
    }
}
__declspec(dllexport) void* TITCALL ImporterGetForwardedAPIName(HANDLE hProcess, ULONG_PTR APIAddress)
{
    return((LPVOID)EngineGlobalAPIHandler(hProcess, NULL, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_FORWARDER_APINAME));
}
__declspec(dllexport) void* TITCALL ImporterGetForwardedDLLName(HANDLE hProcess, ULONG_PTR APIAddress)
{
    return((LPVOID)EngineGlobalAPIHandler(hProcess, NULL, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_FORWARDER_DLLNAME));
}
__declspec(dllexport) long TITCALL ImporterGetForwardedDLLIndex(HANDLE hProcess, ULONG_PTR APIAddress, ULONG_PTR DLLBasesList)
{
    //TODO: remove?
    return((DWORD)EngineGlobalAPIHandler(hProcess, NULL, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_FORWARDER_DLLINDEX));
}
__declspec(dllexport) ULONG_PTR TITCALL ImporterGetForwardedAPIOrdinalNumber(HANDLE hProcess, ULONG_PTR APIAddress)
{
    return((DWORD)EngineGlobalAPIHandler(hProcess, NULL, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_FORWARDER_API_ORDINAL_NUMBER));
}
__declspec(dllexport) ULONG_PTR TITCALL ImporterGetNearestAPIAddress(HANDLE hProcess, ULONG_PTR APIAddress)
{
    return((ULONG_PTR)EngineGlobalAPIHandler(hProcess, NULL, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_NEAREST_APIADDRESS));
}
__declspec(dllexport) void* TITCALL ImporterGetNearestAPIName(HANDLE hProcess, ULONG_PTR APIAddress)
{
    return((LPVOID)EngineGlobalAPIHandler(hProcess, NULL, APIAddress, NULL, UE_OPTION_IMPORTER_RETURN_NEAREST_APINAME));
}
__declspec(dllexport) bool TITCALL ImporterCopyOriginalIAT(char* szOriginalFile, char* szDumpFile)
{

    wchar_t uniDumpFile[MAX_PATH] = {};
    wchar_t uniOriginalFile[MAX_PATH] = {};

    if(szOriginalFile != NULL && szDumpFile != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpFile, lstrlenA(szDumpFile) + 1, uniDumpFile, sizeof(uniDumpFile) / (sizeof(uniDumpFile[0])));
        MultiByteToWideChar(CP_ACP, NULL, szOriginalFile, lstrlenA(szOriginalFile) + 1, uniOriginalFile, sizeof(uniOriginalFile) / (sizeof(uniOriginalFile[0])));
        return(ImporterCopyOriginalIATW(uniOriginalFile, uniDumpFile));
    }
    else
    {
        return false;
    }
}
__declspec(dllexport) bool TITCALL ImporterCopyOriginalIATW(wchar_t* szOriginalFile, wchar_t* szDumpFile)
{

    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    BOOL FileIs64;
    HANDLE FileHandle = 0;
    DWORD FileSize;
    HANDLE FileMap = 0;
    ULONG_PTR FileMapVA;
    HANDLE FileHandle1 = 0;
    DWORD FileSize1;
    HANDLE FileMap1 = 0;
    ULONG_PTR FileMapVA1;
    ULONG_PTR IATPointer;
    ULONG_PTR IATWritePointer;
    ULONG_PTR IATCopyStart;
    DWORD IATSection;
    DWORD IATCopySize;
    DWORD IATHeaderData;

    if(MapFileExW(szOriginalFile, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        if(MapFileExW(szDumpFile, UE_ACCESS_ALL, &FileHandle1, &FileSize1, &FileMap1, &FileMapVA1, NULL))
        {
            DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
            if(EngineValidateHeader(FileMapVA, FileHandle, NULL, DOSHeader, true))
            {
                PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
                PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
                if(PEHeader32->OptionalHeader.Magic == 0x10B)
                {
                    FileIs64 = false;
                }
                else if(PEHeader32->OptionalHeader.Magic == 0x20B)
                {
                    FileIs64 = true;
                }
                else
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    UnMapFileEx(FileHandle1, FileSize1, FileMap1, FileMapVA1);
                    return false;
                }
                if(!FileIs64)
                {
                    IATPointer = (ULONG_PTR)(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + PEHeader32->OptionalHeader.ImageBase);
                }
                else
                {
                    IATPointer = (ULONG_PTR)(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + PEHeader64->OptionalHeader.ImageBase);
                }
                IATSection = GetPE32SectionNumberFromVA(FileMapVA, IATPointer);
                IATPointer = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, IATPointer, true);
                if((int)IATSection >= NULL)
                {
                    IATWritePointer = (ULONG_PTR)GetPE32DataFromMappedFile(FileMapVA1, IATSection, UE_SECTIONRAWOFFSET) + FileMapVA1;
                    IATCopyStart = (ULONG_PTR)GetPE32DataFromMappedFile(FileMapVA, IATSection, UE_SECTIONRAWOFFSET) + FileMapVA;
                    IATCopySize = (DWORD)GetPE32DataFromMappedFile(FileMapVA1, IATSection, UE_SECTIONRAWSIZE);
                    __try
                    {
                        RtlMoveMemory((LPVOID)IATWritePointer, (LPVOID)IATCopyStart, IATCopySize);
                        IATHeaderData = (DWORD)GetPE32DataFromMappedFile(FileMapVA, NULL, UE_IMPORTTABLEADDRESS);
                        SetPE32DataForMappedFile(FileMapVA1, NULL, UE_IMPORTTABLEADDRESS, (ULONG_PTR)IATHeaderData);
                        IATHeaderData = (DWORD)GetPE32DataFromMappedFile(FileMapVA, NULL, UE_IMPORTTABLESIZE);
                        SetPE32DataForMappedFile(FileMapVA1, NULL, UE_IMPORTTABLESIZE, (ULONG_PTR)IATHeaderData);
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        UnMapFileEx(FileHandle1, FileSize1, FileMap1, FileMapVA1);
                        return true;
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        UnMapFileEx(FileHandle1, FileSize1, FileMap1, FileMapVA1);
                        return false;
                    }
                }
            }
            UnMapFileEx(FileHandle1, FileSize1, FileMap1, FileMapVA1);
        }
        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
    }

    return false;
}
__declspec(dllexport) bool TITCALL ImporterLoadImportTable(char* szFileName)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return(ImporterLoadImportTableW(uniFileName));
    }
    else
    {
        return false;
    }
}
__declspec(dllexport) bool TITCALL ImporterLoadImportTableW(wchar_t* szFileName)
{
    //TODO scylla enable
    return false;
    /*
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_IMPORT_DESCRIPTOR ImportIID;
    PIMAGE_THUNK_DATA32 ThunkData32;
    PIMAGE_THUNK_DATA64 ThunkData64;
    ULONG_PTR CurrentThunk;
    BOOL FileIs64;
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;

    if(MapFileExW(szFileName, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
        if(EngineValidateHeader(FileMapVA, FileHandle, NULL, DOSHeader, true))
        {
            PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            if(PEHeader32->OptionalHeader.Magic == 0x10B)
            {
                FileIs64 = false;
            }
            else if(PEHeader32->OptionalHeader.Magic == 0x20B)
            {
                FileIs64 = true;
            }
            else
            {
                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                return false;
            }
            if(!FileIs64)
            {
                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != NULL)
                {
                    ImporterInit(MAX_IMPORT_ALLOC, (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase);
                    ImportIID = (PIMAGE_IMPORT_DESCRIPTOR)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + PEHeader32->OptionalHeader.ImageBase), true);
                    __try
                    {
                        while(ImportIID->FirstThunk != NULL)
                        {
                            ImporterAddNewDll((char*)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ImportIID->Name + PEHeader32->OptionalHeader.ImageBase), true), NULL);
                            if(ImportIID->OriginalFirstThunk != NULL)
                            {
                                ThunkData32 = (PIMAGE_THUNK_DATA32)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ImportIID->OriginalFirstThunk + PEHeader32->OptionalHeader.ImageBase), true);
                                CurrentThunk = (ULONG_PTR)ImportIID->FirstThunk;
                            }
                            else
                            {
                                ThunkData32 = (PIMAGE_THUNK_DATA32)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ImportIID->FirstThunk + PEHeader32->OptionalHeader.ImageBase), true);
                                CurrentThunk = (ULONG_PTR)ImportIID->FirstThunk;
                            }
                            while(ThunkData32->u1.AddressOfData != NULL)
                            {
                                if(ThunkData32->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
                                {
                                    ImporterAddNewAPI((char*)(ThunkData32->u1.Ordinal ^ IMAGE_ORDINAL_FLAG32), (ULONG_PTR)CurrentThunk + PEHeader32->OptionalHeader.ImageBase);
                                }
                                else
                                {
                                    ImporterAddNewAPI((char*)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ThunkData32->u1.AddressOfData + 2 + PEHeader32->OptionalHeader.ImageBase), true), (ULONG_PTR)CurrentThunk + PEHeader32->OptionalHeader.ImageBase);
                                }
                                CurrentThunk = CurrentThunk + 4;
                                ThunkData32 = (PIMAGE_THUNK_DATA32)((ULONG_PTR)ThunkData32 + sizeof IMAGE_THUNK_DATA32);
                            }
                            ImportIID = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)ImportIID + sizeof IMAGE_IMPORT_DESCRIPTOR);
                        }
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return true;
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        ImporterCleanup();
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return false;
                    }
                }
            }
            else
            {
                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != NULL)
                {
                    ImporterInit(MAX_IMPORT_ALLOC, (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase);
                    ImportIID = (PIMAGE_IMPORT_DESCRIPTOR)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + PEHeader64->OptionalHeader.ImageBase), true);
                    __try
                    {
                        while(ImportIID->FirstThunk != NULL)
                        {
                            ImporterAddNewDll((char*)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ImportIID->Name + PEHeader64->OptionalHeader.ImageBase), true), NULL);
                            if(ImportIID->OriginalFirstThunk != NULL)
                            {
                                ThunkData64 = (PIMAGE_THUNK_DATA64)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ImportIID->OriginalFirstThunk + PEHeader64->OptionalHeader.ImageBase), true);
                                CurrentThunk = (ULONG_PTR)ImportIID->OriginalFirstThunk;
                            }
                            else
                            {
                                ThunkData64 = (PIMAGE_THUNK_DATA64)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ImportIID->FirstThunk + PEHeader64->OptionalHeader.ImageBase), true);
                                CurrentThunk = (ULONG_PTR)ImportIID->FirstThunk;
                            }
                            while(ThunkData64->u1.AddressOfData != NULL)
                            {
                                if(ThunkData64->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                                {
                                    ImporterAddNewAPI((char*)(ThunkData64->u1.Ordinal ^ (ULONG_PTR)IMAGE_ORDINAL_FLAG64), (ULONG_PTR)CurrentThunk + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase);
                                }
                                else
                                {
                                    ImporterAddNewAPI((char*)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ThunkData64->u1.AddressOfData + 2 + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase), true), (ULONG_PTR)CurrentThunk + (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase);
                                }
                                CurrentThunk = CurrentThunk + 8;
                                ThunkData64 = (PIMAGE_THUNK_DATA64)((ULONG_PTR)ThunkData64 + sizeof IMAGE_THUNK_DATA64);
                            }
                            ImportIID = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)ImportIID + sizeof IMAGE_IMPORT_DESCRIPTOR);
                        }
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return true;
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        ImporterCleanup();
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return false;
                    }
                }
            }
        }
        else
        {
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            return false;
        }
    }
    else
    {
        return false;
    }
    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
    return false;
    */
}
__declspec(dllexport) bool TITCALL ImporterMoveOriginalIAT(char* szOriginalFile, char* szDumpFile, char* szSectionName)
{
    /*
    if(ImporterLoadImportTable(szOriginalFile))
    {
        return(ImporterExportIATEx(szDumpFile, szSectionName));
    }*/
    return false;
}
__declspec(dllexport) bool TITCALL ImporterMoveOriginalIATW(wchar_t* szOriginalFile, wchar_t* szDumpFile, char* szSectionName)
{
    /*
    if(ImporterLoadImportTableW(szOriginalFile))
    {
        return(ImporterExportIATExW(szDumpFile, szSectionName));
    }*/
    return false;
}
__declspec(dllexport) void TITCALL ImporterAutoSearchIAT(DWORD ProcessId, char* szFileName, ULONG_PTR SearchStart, LPVOID pIATStart, LPVOID pIATSize)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return(ImporterAutoSearchIATW(ProcessId, uniFileName, SearchStart, pIATStart, pIATSize));
    }
}
__declspec(dllexport) void TITCALL ImporterAutoSearchIATW(DWORD ProcessId, wchar_t* szFileName, ULONG_PTR SearchStart, LPVOID pIATStart, LPVOID pIATSize)
{
    ULONG_PTR iatStart = NULL;
    DWORD iatSize = NULL;

    scylla_searchIAT(ProcessId, iatStart, iatSize, SearchStart, false);

    //we also try to automatically read imports so following call to ExportIAT has a chance
    if(iatStart != NULL && iatSize != NULL)
    {
        scylla_getImports(iatStart, iatSize, ProcessId);
    }

    RtlMoveMemory(pIATStart, &iatStart, sizeof ULONG_PTR);
    RtlMoveMemory(pIATSize, &iatSize, sizeof ULONG_PTR);

    return;
}
__declspec(dllexport) void TITCALL ImporterAutoSearchIATEx(DWORD ProcessId, ULONG_PTR ImageBase, ULONG_PTR SearchStart, LPVOID pIATStart, LPVOID pIATSize)
{

    wchar_t szTempName[MAX_PATH];
    wchar_t szTempFolder[MAX_PATH];

    RtlZeroMemory(&szTempName, sizeof szTempName);
    RtlZeroMemory(&szTempFolder, sizeof szTempFolder);
    if(GetTempPathW(MAX_PATH, szTempFolder) < MAX_PATH)
    {
        if(GetTempFileNameW(szTempFolder, L"DumpTemp", GetTickCount() + 102, szTempName))
        {
            HANDLE hProcess = EngineOpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, ProcessId);

            DumpProcessW(hProcess, (LPVOID)ImageBase, szTempName, NULL);
            ImporterAutoSearchIATW(ProcessId, szTempName, SearchStart, pIATStart, pIATSize);
            DeleteFileW(szTempName);
        }
    }
}
__declspec(dllexport) void TITCALL ImporterEnumAddedData(LPVOID EnumCallBack)
{
    return scylla_enumImportTree(EnumCallBack);
}
__declspec(dllexport) long TITCALL ImporterAutoFixIATEx(DWORD ProcessId, char* szDumpedFile, char* szSectionName, bool DumpRunningProcess, bool RealignFile, ULONG_PTR EntryPointAddress, ULONG_PTR ImageBase, ULONG_PTR SearchStart, bool TryAutoFix, bool FixEliminations, LPVOID UnknownPointerFixCallback)
{

    wchar_t uniDumpedFile[MAX_PATH] = {};
    wchar_t uniSectionName[MAX_PATH] = {};

    if(szDumpedFile != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpedFile, lstrlenA(szDumpedFile) + 1, uniDumpedFile, sizeof(uniDumpedFile) / (sizeof(uniDumpedFile[0])));
        MultiByteToWideChar(CP_ACP, NULL, szSectionName, lstrlenA(szSectionName) + 1, uniSectionName, sizeof(uniSectionName) / (sizeof(uniSectionName[0])));
        return(ImporterAutoFixIATExW(ProcessId, uniDumpedFile, uniSectionName, DumpRunningProcess, RealignFile, EntryPointAddress, ImageBase, SearchStart, TryAutoFix, FixEliminations, UnknownPointerFixCallback));
    }
    else
    {
        return(NULL);   // Critical error! *just to be safe, but it should never happen!
    }
}
__declspec(dllexport) long TITCALL ImporterAutoFixIATExW(DWORD ProcessId, wchar_t* szDumpedFile, wchar_t* szSectionName, bool DumpRunningProcess, bool RealignFile, ULONG_PTR EntryPointAddress, ULONG_PTR ImageBase, ULONG_PTR SearchStart,  bool TryAutoFix, bool FixEliminations, LPVOID UnknownPointerFixCallback)
{
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    ULONG_PTR iatStart = NULL;
    DWORD iatSize = NULL;
    WCHAR IatFixFileName[MAX_PATH];
    WCHAR DumpFileName[MAX_PATH];

    lstrcpyW(DumpFileName, szDumpedFile);

    WCHAR* Extension = wcsrchr(DumpFileName, L'.');
    WCHAR Bak = *Extension;
    *Extension = 0;
    lstrcpyW(IatFixFileName, DumpFileName);
    *Extension = Bak;
    lstrcatW(IatFixFileName, L"_scy");
    lstrcatW(IatFixFileName, Extension);
    lstrcatW(DumpFileName, Extension);

    //do we need to dump first?
    if(DumpRunningProcess)
    {
        HANDLE hProcess = EngineOpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, ProcessId);

        if(!DumpProcessW(hProcess, (LPVOID)ImageBase, szDumpedFile, EntryPointAddress))
        {
            return(NULL);   // Critical error! *just to be safe, but it should never happen!
        }
    }

    //we need to fix iat, thats for sure
    int ret = scylla_searchIAT(ProcessId, iatStart, iatSize, SearchStart, false);

    if(ret != SCY_ERROR_SUCCESS)
    {
        if(ret == SCY_ERROR_PROCOPEN)
        {
            return (0x401); //error proc terminated
        }
        if(ret == SCY_ERROR_IATNOTFOUND || ret == SCY_ERROR_IATSEARCH)
        {
            return (0x405); //no API found
        }
    }

    scylla_getImports(iatStart, iatSize, ProcessId, UnknownPointerFixCallback);

    if(!scylla_importsValid())
    {
        return (0x405);
    }

    ret = scylla_fixDump(szDumpedFile, IatFixFileName, szSectionName);

    if(ret == SCY_ERROR_IATWRITE)
    {
        return (0x407);
    }

    //do we need to realign ?
    if(RealignFile)
    {
        if(MapFileExW(szDumpedFile, UE_ACCESS_ALL, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
        {
            FileSize = RealignPE(FileMapVA, FileSize, NULL);
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
        }
        else
        {
            return(0x406);  // Success, but realign failed!
        }
    }
    return(0x400);  // Success!
}
__declspec(dllexport) long TITCALL ImporterAutoFixIAT(DWORD ProcessId, char* szDumpedFile, ULONG_PTR SearchStart)
{
    return(ImporterAutoFixIATEx(ProcessId, szDumpedFile, ".RL!TEv2", false, false, NULL, NULL, SearchStart, false, false, NULL));
}
__declspec(dllexport) long TITCALL ImporterAutoFixIATW(DWORD ProcessId, wchar_t* szDumpedFile, ULONG_PTR SearchStart)
{
    return(ImporterAutoFixIATExW(ProcessId, szDumpedFile, L".RL!TEv2", false, false, NULL, NULL, SearchStart, false, false, NULL));
}
__declspec(dllexport) bool TITCALL ImporterDeleteAPI(DWORD_PTR apiAddr)
{
    return scylla_cutImport(apiAddr);
}
