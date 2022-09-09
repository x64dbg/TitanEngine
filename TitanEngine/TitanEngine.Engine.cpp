#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.h"
#include "Global.Mapping.h"
#include "Global.Engine.Hook.h"
#include "Global.Engine.GUI.h"
#include "Global.Engine.Extension.h"
#include "Global.Debugger.h"

// TitanEngine.Engine.functions:
__declspec(dllexport) void TITCALL SetEngineVariable(DWORD VariableId, bool VariableSet)
{

    if(VariableId == UE_ENGINE_ALOW_MODULE_LOADING)
    {
        engineAlowModuleLoading = VariableSet;
    }
    else if(VariableId == UE_ENGINE_AUTOFIX_FORWARDERS)
    {
        engineCheckForwarders = VariableSet;
    }
    else if(VariableId == UE_ENGINE_PASS_ALL_EXCEPTIONS)
    {
        enginePassAllExceptions = VariableSet;
    }
    else if(VariableId == UE_ENGINE_NO_CONSOLE_WINDOW)
    {
        engineRemoveConsoleForDebugee = VariableSet;
    }
    else if(VariableId == UE_ENGINE_BACKUP_FOR_CRITICAL_FUNCTIONS)
    {
        engineBackupForCriticalFunctions = VariableSet;
    }
    else if(VariableId == UE_ENGINE_RESET_CUSTOM_HANDLER)
    {
        engineResetCustomHandler = VariableSet;
    }
    else if(VariableId == UE_ENGINE_CALL_PLUGIN_DEBUG_CALLBACK)
    {
        engineExecutePluginCallBack = VariableSet;
    }
    else if(VariableId == UE_ENGINE_SET_DEBUG_PRIVILEGE)
    {
        engineEnableDebugPrivilege = VariableSet;
        EngineSetDebugPrivilege(GetCurrentProcess(), VariableSet);
    }
    else if(VariableId == UE_ENGINE_SAFE_ATTACH)
    {
        engineSafeAttach = VariableSet;
    }
    else if(VariableId == UE_ENGINE_MEMBP_ALT)
    {
        engineMembpAlt = VariableSet;
    }
    else if(VariableId == UE_ENGINE_DISABLE_ASLR)
    {
        engineDisableAslr = VariableSet;
    }
    else if (VariableId == UE_ENGINE_SAFE_STEP)
    {
        engineSafeStep = VariableSet;
    }
}

__declspec(dllexport) bool TITCALL EngineCreateMissingDependencies(char* szFileName, char* szOutputFolder, bool LogCreatedFiles)
{

    wchar_t uniFileName[MAX_PATH] = {};
    wchar_t uniOutputFolder[MAX_PATH] = {};

    if(szFileName != NULL && szOutputFolder != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        MultiByteToWideChar(CP_ACP, NULL, szOutputFolder, lstrlenA(szOutputFolder) + 1, uniOutputFolder, sizeof(uniOutputFolder) / (sizeof(uniOutputFolder[0])));
        return(EngineCreateMissingDependenciesW(uniFileName, uniOutputFolder, LogCreatedFiles));
    }
    else
    {
        return(NULL);
    }
}

__declspec(dllexport) bool TITCALL EngineCreateMissingDependenciesW(wchar_t* szFileName, wchar_t* szOutputFolder, bool LogCreatedFiles)
{

    char* ImportDllName;
    wchar_t ImportDllNameW[512];
    wchar_t BuildExportName[512];
    PIMAGE_THUNK_DATA32 ImportThunkX86;
    PIMAGE_THUNK_DATA64 ImportThunkX64;
    PIMAGE_IMPORT_DESCRIPTOR ImportPointer;
    ULONG_PTR ImportTableAddress = NULL;
    ULONG_PTR ImportThunkName = NULL;
    DWORD ImportThunkAddress = NULL;
    ULONG_PTR ImageBase = NULL;
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    BOOL FileIs64;

    if(MapFileExW(szFileName, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
        if(DOSHeader->e_lfanew < 0x1000 - 108)
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
            if(LogCreatedFiles)
            {
                if(engineDependencyFiles != NULL)
                {
                    VirtualFree(engineDependencyFiles, NULL, MEM_RELEASE);
                }
                engineDependencyFiles = VirtualAlloc(NULL, 20 * 1024, MEM_COMMIT, PAGE_READWRITE);
                engineDependencyFilesCWP = engineDependencyFiles;
            }
            if(!FileIs64)
            {
                ImageBase = (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase;
                ImportTableAddress = (ULONG_PTR)PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                ImportTableAddress = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, ImportTableAddress + ImageBase, true);
                ImportPointer = (PIMAGE_IMPORT_DESCRIPTOR)ImportTableAddress;
                while(ImportPointer && ImportPointer->FirstThunk != NULL)
                {
                    ImportDllName = (PCHAR)((ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, ImportPointer->Name + ImageBase, true));
                    if(ImportDllName)
                    {
                        MultiByteToWideChar(CP_ACP, NULL, ImportDllName, lstrlenA(ImportDllName) + 1, ImportDllNameW, sizeof(ImportDllNameW) / (sizeof(ImportDllNameW[0])));
                        if(!EngineIsDependencyPresentW(ImportDllNameW, szFileName, szOutputFolder))
                        {
                            RtlZeroMemory(&BuildExportName, sizeof(BuildExportName));
                            lstrcatW(BuildExportName, szOutputFolder);
                            if(BuildExportName[lstrlenW(BuildExportName) - 1] != 0x5C)
                            {
                                BuildExportName[lstrlenW(BuildExportName)] = 0x5C;
                            }
                            lstrcatW(BuildExportName, ImportDllNameW);
                            if(LogCreatedFiles)
                            {
                                RtlMoveMemory(engineDependencyFilesCWP, &BuildExportName, lstrlenW(BuildExportName) * 2);
                                engineDependencyFilesCWP = (LPVOID)((ULONG_PTR)engineDependencyFilesCWP + (lstrlenW(BuildExportName) * 2) + 2);
                            }
                            EngineExtractResource("MODULEx86", BuildExportName);
                            ExporterInit(20 * 1024, (ULONG_PTR)GetPE32DataW(BuildExportName, NULL, UE_IMAGEBASE), NULL, ImportDllName);
                            ImportThunkAddress = ImportPointer->FirstThunk;
                            if(ImportPointer->OriginalFirstThunk != NULL)
                            {
                                ImportThunkX86 = (PIMAGE_THUNK_DATA32)((ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, ImportPointer->OriginalFirstThunk + ImageBase, true));
                            }
                            else
                            {
                                ImportThunkX86 = (PIMAGE_THUNK_DATA32)((ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, ImportPointer->FirstThunk + ImageBase, true));
                            }
                            while(ImportThunkX86 && ImportThunkX86->u1.Function != NULL)
                            {
                                if(ImportThunkX86->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
                                {
                                    ExporterAddNewOrdinalExport(ImportThunkX86->u1.Ordinal ^ IMAGE_ORDINAL_FLAG32, 0x1000);
                                }
                                else
                                {
                                    ImportThunkName = (ULONG_PTR)(ConvertVAtoFileOffset(FileMapVA, ImportThunkX86->u1.AddressOfData + ImageBase, true) + 2);
                                    if(ImportThunkName)
                                        ExporterAddNewExport((PCHAR)ImportThunkName, 0x1000);
                                }
                                ImportThunkX86 = (PIMAGE_THUNK_DATA32)((ULONG_PTR)ImportThunkX86 + 4);
                                ImportThunkAddress = ImportThunkAddress + 4;
                            }
                            ExporterBuildExportTableExW(BuildExportName, ".export");
                        }
                        ImportPointer = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)ImportPointer + sizeof IMAGE_IMPORT_DESCRIPTOR);
                    }
                }
            }
            else
            {
                ImageBase = (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase;
                ImportTableAddress = (ULONG_PTR)PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                ImportTableAddress = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, ImportTableAddress + ImageBase, true);
                ImportPointer = (PIMAGE_IMPORT_DESCRIPTOR)ImportTableAddress;
                while(ImportPointer && ImportPointer->FirstThunk != NULL)
                {
                    ImportDllName = (PCHAR)((ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, ImportPointer->Name + ImageBase, true));
                    if(ImportDllName)
                    {
                        MultiByteToWideChar(CP_ACP, NULL, ImportDllName, lstrlenA(ImportDllName) + 1, ImportDllNameW, sizeof(ImportDllNameW) / (sizeof(ImportDllNameW[0])));
                        if(!EngineIsDependencyPresentW(ImportDllNameW, szFileName, szOutputFolder))
                        {
                            RtlZeroMemory(&BuildExportName, sizeof(BuildExportName));
                            lstrcatW(BuildExportName, szOutputFolder);
                            if(BuildExportName[lstrlenW(BuildExportName) - 1] != 0x5C)
                            {
                                BuildExportName[lstrlenW(BuildExportName)] = 0x5C;
                            }
                            lstrcatW(BuildExportName, ImportDllNameW);
                            if(LogCreatedFiles)
                            {
                                RtlMoveMemory(engineDependencyFilesCWP, &BuildExportName, lstrlenW(BuildExportName) * 2);
                                engineDependencyFilesCWP = (LPVOID)((ULONG_PTR)engineDependencyFilesCWP + (lstrlenW(BuildExportName) * 2) + 2);
                            }
                            EngineExtractResource("MODULEx64", BuildExportName);
                            ExporterInit(20 * 1024, (ULONG_PTR)GetPE32DataW(BuildExportName, NULL, UE_IMAGEBASE), NULL, ImportDllName);
                            ImportThunkAddress = ImportPointer->FirstThunk;
                            if(ImportPointer->OriginalFirstThunk != NULL)
                            {
                                ImportThunkX64 = (PIMAGE_THUNK_DATA64)((ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, ImportPointer->OriginalFirstThunk + ImageBase, true));
                            }
                            else
                            {
                                ImportThunkX64 = (PIMAGE_THUNK_DATA64)((ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, ImportPointer->FirstThunk + ImageBase, true));
                            }
                            while(ImportThunkX64 && ImportThunkX64->u1.Function != NULL)
                            {
                                if(ImportThunkX64->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                                {
                                    ExporterAddNewOrdinalExport((DWORD)(ImportThunkX64->u1.Ordinal ^ IMAGE_ORDINAL_FLAG64), 0x1000);
                                }
                                else
                                {
                                    ImportThunkName = (ULONG_PTR)(ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(ImportThunkX64->u1.AddressOfData + ImageBase), true) + 2);
                                    if(ImportThunkName)
                                        ExporterAddNewExport((PCHAR)ImportThunkName, 0x1000);
                                }
                                ImportThunkX64 = (PIMAGE_THUNK_DATA64)((ULONG_PTR)ImportThunkX64 + 8);
                                ImportThunkAddress = ImportThunkAddress + 8;
                            }
                            ExporterBuildExportTableExW(BuildExportName, ".export");
                        }
                        ImportPointer = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)ImportPointer + sizeof IMAGE_IMPORT_DESCRIPTOR);
                    }
                }
            }
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            return true;
        }
        else
        {
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            return false;
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL EngineFakeMissingDependencies(HANDLE hProcess)
{

    if(hProcess != NULL)
    {
        SetAPIBreakPoint("ntdll.dll", "LdrLoadDll", UE_BREAKPOINT, UE_APIEND, (LPVOID)&EngineFakeLoadLibraryReturn);
        SetAPIBreakPoint("ntdll.dll", "LdrGetProcedureAddress", UE_BREAKPOINT, UE_APIEND, (LPVOID)&EngineFakeGetProcAddressReturn);
    }
    return false;
}

__declspec(dllexport) bool TITCALL EngineDeleteCreatedDependencies()
{

    wchar_t szTempName[MAX_PATH];
    wchar_t szTempFolder[MAX_PATH];

    if(engineDependencyFiles != NULL)
    {
        engineDependencyFilesCWP = engineDependencyFiles;
        while(*((char*)engineDependencyFilesCWP) != 0)
        {
            RtlZeroMemory(&szTempName, sizeof szTempName);
            RtlZeroMemory(&szTempFolder, sizeof szTempFolder);
            if(GetTempPathW(MAX_PATH, szTempFolder) < MAX_PATH)
            {
                if(GetTempFileNameW(szTempFolder, L"DeleteTempGenFile", GetTickCount(), szTempName))
                {
                    DeleteFileW(szTempName);
                    if(!MoveFileW((LPCWSTR)engineDependencyFilesCWP, szTempName))
                    {
                        DeleteFileW((LPCWSTR)engineDependencyFilesCWP);
                    }
                    else
                    {
                        DeleteFileW(szTempName);
                    }
                }
            }
            engineDependencyFilesCWP = (LPVOID)((ULONG_PTR)engineDependencyFilesCWP + (lstrlenW((PWCHAR)engineDependencyFilesCWP) * 2) + 2);
        }
        VirtualFree(engineDependencyFiles, NULL, MEM_RELEASE);
        engineDependencyFiles = NULL;
        engineDependencyFilesCWP = NULL;
        return true;
    }
    return false;
}

__declspec(dllexport) bool TITCALL EngineCreateUnpackerWindow(char* WindowUnpackerTitle, char* WindowUnpackerLongTitle, char* WindowUnpackerName, char* WindowUnpackerAuthor, void* StartUnpackingCallBack)
{
    if(!WindowUnpackerTitle || !WindowUnpackerLongTitle || !WindowUnpackerName || !WindowUnpackerAuthor || !StartUnpackingCallBack)
        return false;
    EngineStartUnpackingCallBack = StartUnpackingCallBack;
    lstrcpyA(szWindowUnpackerTitle, WindowUnpackerTitle);
    lstrcpyA(szWindowUnpackerLongTitle, WindowUnpackerLongTitle);
    lstrcpyA(szWindowUnpackerAuthor, WindowUnpackerAuthor);
    lstrcpyA(szWindowUnpackerName, WindowUnpackerName);
    if(DialogBoxParamA((HINSTANCE)engineHandle, MAKEINTRESOURCEA(IDD_MAINWINDOW), NULL, (DLGPROC)EngineWndProc, NULL) != -1)
    {
        return true;
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) void TITCALL EngineAddUnpackerWindowLogMessage(char* szLogMessage)
{
    int cSelect;

    SendMessageA(EngineBoxHandle, LB_ADDSTRING, NULL, (LPARAM)szLogMessage);
    cSelect = (int)SendMessageA(EngineBoxHandle, LB_GETCOUNT, NULL, NULL);
    cSelect--;
    SendMessageA(EngineBoxHandle, LB_SETCURSEL, (WPARAM)cSelect, NULL);
}

__declspec(dllexport) bool TITCALL EngineCheckStructAlignment(DWORD StructureType, ULONG_PTR StructureSize)
{
    int blub = 1;
    switch(StructureType)
    {
    case UE_STRUCT_PE32STRUCT:
        return (sizeof(PE32Struct) == StructureSize);
    case UE_STRUCT_PE64STRUCT:
        return (sizeof(PE64Struct) == StructureSize);
    case UE_STRUCT_PESTRUCT:
        return (sizeof(PEStruct) == StructureSize);
    case UE_STRUCT_IMPORTENUMDATA:
        return (sizeof(ImportEnumData) == StructureSize);
    case UE_STRUCT_THREAD_ITEM_DATA:
        return (sizeof(THREAD_ITEM_DATA) == StructureSize);
    case UE_STRUCT_LIBRARY_ITEM_DATA:
        return (sizeof(LIBRARY_ITEM_DATA) == StructureSize);
    case UE_STRUCT_LIBRARY_ITEM_DATAW:
        return (sizeof(LIBRARY_ITEM_DATAW) == StructureSize);
    case UE_STRUCT_PROCESS_ITEM_DATA:
        return (sizeof(PROCESS_ITEM_DATA) == StructureSize);
    case UE_STRUCT_HANDLERARRAY:
        return (sizeof(HandlerArray) == StructureSize);
    case UE_STRUCT_PLUGININFORMATION:
        return (sizeof(PluginInformation) == StructureSize);
    case UE_STRUCT_HOOK_ENTRY:
        return (sizeof(HOOK_ENTRY) == StructureSize);
    case UE_STRUCT_FILE_STATUS_INFO:
        return (sizeof(FILE_STATUS_INFO) == StructureSize);
    case UE_STRUCT_FILE_FIX_INFO:
        return (sizeof(FILE_FIX_INFO) == StructureSize);
    case UE_STRUCT_X87FPUREGISTER:
        return (sizeof(x87FPURegister_t) == StructureSize);
    case UE_STRUCT_X87FPU:
        return (sizeof(x87FPU_t) == StructureSize);
    case UE_STRUCT_TITAN_ENGINE_CONTEXT:
        return (sizeof(TITAN_ENGINE_CONTEXT_t) == StructureSize);
    }
    return false;
}
