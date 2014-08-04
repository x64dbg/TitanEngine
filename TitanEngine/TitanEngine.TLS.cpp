#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.h"
#include "Global.Mapping.h"
#include "Global.Debugger.h"
#include "Global.TLS.h"

static bool engineBackupTLSx64 = false;
static IMAGE_TLS_DIRECTORY32 engineBackupTLSDataX86 = {};
static IMAGE_TLS_DIRECTORY64 engineBackupTLSDataX64 = {};
static DWORD engineBackupNumberOfCallBacks = NULL;
static std::vector<ULONG_PTR> engineBackupArrayOfCallBacks;
static DWORD engineBackupTLSAddress = NULL;

// TitanEngine.TLS.functions:
__declspec(dllexport) bool TITCALL TLSBreakOnCallBack(LPVOID ArrayOfCallBacks, DWORD NumberOfCallBacks, LPVOID bpxCallBack)
{
    ULONG_PTR* ReadArrayOfCallBacks = (ULONG_PTR*)ArrayOfCallBacks;

    if(NumberOfCallBacks && EngineIsValidReadPtrEx(ReadArrayOfCallBacks, sizeof(ULONG_PTR)*NumberOfCallBacks) && bpxCallBack)
    {
        ClearTlsCallBackList(); //clear TLS cb list
        for(unsigned int i = 0; i < NumberOfCallBacks; i++)
            tlsCallBackList.push_back(ReadArrayOfCallBacks[i]);
        engineTLSBreakOnCallBackAddress = (ULONG_PTR)bpxCallBack;
        engineTLSBreakOnCallBack = true;
        return true;
    }
    return false;
}

__declspec(dllexport) bool TITCALL TLSGrabCallBackData(char* szFileName, LPVOID ArrayOfCallBacks, LPDWORD NumberOfCallBacks)
{
    wchar_t uniFileName[MAX_PATH] = {};
    if(szFileName)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return TLSGrabCallBackDataW(uniFileName, ArrayOfCallBacks, NumberOfCallBacks);
    }
    return false;
}
__declspec(dllexport) bool TITCALL TLSGrabCallBackDataW(wchar_t* szFileName, LPVOID ArrayOfCallBacks, LPDWORD NumberOfCallBacks)
{
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;

    if(MapFileExW(szFileName, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        PIMAGE_DOS_HEADER DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
        if(EngineValidateHeader(FileMapVA, FileHandle, NULL, DOSHeader, true))
        {
            DWORD NumberOfTLSCallBacks = 0;
            PIMAGE_NT_HEADERS32 PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            PIMAGE_NT_HEADERS64 PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            bool FileIs64;
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
            if(!FileIs64) //x86
            {
                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                {
                    ULONG_PTR TLSDirectoryAddress = (ULONG_PTR)((ULONG_PTR)PEHeader32->OptionalHeader.ImageBase + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                    PIMAGE_TLS_DIRECTORY32 TLSDirectoryX86 = (PIMAGE_TLS_DIRECTORY32)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryAddress, true);
                    if(TLSDirectoryX86 && TLSDirectoryX86->AddressOfCallBacks != NULL)
                    {
                        ULONG_PTR TLSCompareData = 0;
                        ULONG_PTR TLSCallBackAddress = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryX86->AddressOfCallBacks, true);
                        if(TLSCallBackAddress)
                        {
                            while(memcmp((LPVOID)TLSCallBackAddress, &TLSCompareData, sizeof ULONG_PTR) != NULL)
                            {
                                if(ArrayOfCallBacks)
                                {
                                    RtlMoveMemory(ArrayOfCallBacks, (LPVOID)TLSCallBackAddress, sizeof ULONG_PTR);
                                    ArrayOfCallBacks = (LPVOID)((ULONG_PTR)ArrayOfCallBacks + sizeof ULONG_PTR);
                                }
                                TLSCallBackAddress = TLSCallBackAddress + sizeof ULONG_PTR;
                                NumberOfTLSCallBacks++;
                            }
                            if(NumberOfCallBacks)
                                *NumberOfCallBacks = NumberOfTLSCallBacks;
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return true;
                        }
                        else
                        {
                            if(NumberOfCallBacks)
                                *NumberOfCallBacks = 0;
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return false;
                        }
                    }
                    else
                    {
                        if(NumberOfCallBacks)
                            *NumberOfCallBacks = 0;
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return false;
                    }
                }
                else
                {
                    if(NumberOfCallBacks)
                        *NumberOfCallBacks = 0;
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return false;
                }
            }
            else //x64
            {
                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                {
                    ULONG_PTR TLSDirectoryAddress = (ULONG_PTR)((ULONG_PTR)PEHeader64->OptionalHeader.ImageBase + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                    PIMAGE_TLS_DIRECTORY64 TLSDirectoryX64 = (PIMAGE_TLS_DIRECTORY64)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryAddress, true);
                    if(TLSDirectoryX64 && TLSDirectoryX64->AddressOfCallBacks != NULL)
                    {
                        ULONG_PTR TLSCompareData = NULL;
                        ULONG_PTR TLSCallBackAddress = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryX64->AddressOfCallBacks, true);
                        if(TLSCallBackAddress)
                        {
                            while(memcmp((LPVOID)TLSCallBackAddress, &TLSCompareData, sizeof ULONG_PTR) != NULL)
                            {
                                if(ArrayOfCallBacks)
                                {
                                    RtlMoveMemory(ArrayOfCallBacks, (LPVOID)TLSCallBackAddress, sizeof ULONG_PTR);
                                    ArrayOfCallBacks = (LPVOID)((ULONG_PTR)ArrayOfCallBacks + sizeof ULONG_PTR);
                                }
                                TLSCallBackAddress = TLSCallBackAddress + sizeof ULONG_PTR;
                                NumberOfTLSCallBacks++;
                            }
                            if(NumberOfCallBacks)
                                *NumberOfCallBacks = NumberOfTLSCallBacks;
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return true;
                        }
                        else
                        {
                            if(NumberOfCallBacks)
                                *NumberOfCallBacks = 0;
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return false;
                        }
                    }
                    else
                    {
                        if(NumberOfCallBacks)
                            *NumberOfCallBacks = 0;
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return false;
                    }
                }
                else
                {
                    if(NumberOfCallBacks)
                        *NumberOfCallBacks = 0;
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return false;
                }
            }
        }
        else
        {
            if(NumberOfCallBacks)
                *NumberOfCallBacks = 0;
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            return false;
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL TLSBreakOnCallBackEx(char* szFileName, LPVOID bpxCallBack)
{
    wchar_t uniFileName[MAX_PATH] = {};
    if(szFileName)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return TLSBreakOnCallBackExW(uniFileName, bpxCallBack);
    }
    return false;
}

__declspec(dllexport) bool TITCALL TLSBreakOnCallBackExW(wchar_t* szFileName, LPVOID bpxCallBack)
{
    DWORD NumberOfCallBacks;
    if(TLSGrabCallBackDataW(szFileName, NULL, &NumberOfCallBacks))
    {
        DynBuf TlsArrayOfCallBacks(NumberOfCallBacks * sizeof(ULONG_PTR));
        if(TLSGrabCallBackDataW(szFileName, TlsArrayOfCallBacks.GetPtr(), &NumberOfCallBacks))
        {
            return TLSBreakOnCallBack(TlsArrayOfCallBacks.GetPtr(), NumberOfCallBacks, bpxCallBack);
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL TLSRemoveCallback(char* szFileName)
{
    wchar_t uniFileName[MAX_PATH] = {};
    if(szFileName)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return TLSRemoveCallbackW(uniFileName);
    }
    return false;
}

__declspec(dllexport) bool TITCALL TLSRemoveCallbackW(wchar_t* szFileName)
{
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    if(MapFileExW(szFileName, UE_ACCESS_ALL, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        PIMAGE_DOS_HEADER DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
        if(EngineValidateHeader(FileMapVA, FileHandle, NULL, DOSHeader, true))
        {
            PIMAGE_NT_HEADERS32 PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            PIMAGE_NT_HEADERS64 PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            bool FileIs64;
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
                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                {
                    __try
                    {
                        ULONG_PTR TLSDirectoryAddress = (ULONG_PTR)((ULONG_PTR)PEHeader32->OptionalHeader.ImageBase + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                        PIMAGE_TLS_DIRECTORY32 TLSDirectoryX86 = (PIMAGE_TLS_DIRECTORY32)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryAddress, true);
                        if(TLSDirectoryX86->AddressOfCallBacks != NULL)
                        {
                            TLSDirectoryX86->AddressOfCallBacks = NULL;
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return true;
                        }
                        else
                        {
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return false;
                        }
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return false;
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
                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                {
                    __try
                    {
                        ULONG_PTR TLSDirectoryAddress = (ULONG_PTR)((ULONG_PTR)PEHeader64->OptionalHeader.ImageBase + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                        PIMAGE_TLS_DIRECTORY64 TLSDirectoryX64 = (PIMAGE_TLS_DIRECTORY64)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryAddress, true);
                        if(TLSDirectoryX64->AddressOfCallBacks != NULL)
                        {
                            TLSDirectoryX64->AddressOfCallBacks = NULL;
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return true;
                        }
                        else
                        {
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return false;
                        }
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return false;
                    }
                }
                else
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return false;
                }
            }
        }
        else
        {
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            return false;
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL TLSRemoveTable(char* szFileName)
{
    wchar_t uniFileName[MAX_PATH] = {};
    if(szFileName)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return TLSRemoveTableW(uniFileName);
    }
    return false;
}

__declspec(dllexport) bool TITCALL TLSRemoveTableW(wchar_t* szFileName)
{
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    if(MapFileExW(szFileName, UE_ACCESS_ALL, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        PIMAGE_DOS_HEADER DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
        if(EngineValidateHeader(FileMapVA, FileHandle, NULL, DOSHeader, true))
        {
            PIMAGE_NT_HEADERS32 PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            PIMAGE_NT_HEADERS64 PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            bool FileIs64;
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
                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                {
                    __try
                    {
                        ULONG_PTR TLSDirectoryAddress = (ULONG_PTR)((ULONG_PTR)PEHeader32->OptionalHeader.ImageBase + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                        PIMAGE_TLS_DIRECTORY32 TLSDirectoryX86 = (PIMAGE_TLS_DIRECTORY32)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryAddress, true);
                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = NULL;
                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = NULL;
                        RtlZeroMemory(TLSDirectoryX86, sizeof IMAGE_TLS_DIRECTORY32);
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return true;
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return false;
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
                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                {
                    __try
                    {
                        ULONG_PTR TLSDirectoryAddress = (ULONG_PTR)((ULONG_PTR)PEHeader64->OptionalHeader.ImageBase + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                        PIMAGE_TLS_DIRECTORY64 TLSDirectoryX64 = (PIMAGE_TLS_DIRECTORY64)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryAddress, true);
                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = NULL;
                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = NULL;
                        RtlZeroMemory(TLSDirectoryX64, sizeof IMAGE_TLS_DIRECTORY64);
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return true;
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return false;
                    }
                }
                else
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return false;
                }
            }
        }
        else
        {
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            return false;
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL TLSBackupData(char* szFileName)
{
    wchar_t uniFileName[MAX_PATH] = {};
    if(szFileName)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return TLSBackupDataW(uniFileName);
    }
    return false;
}

__declspec(dllexport) bool TITCALL TLSBackupDataW(wchar_t* szFileName)
{
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    if(MapFileExW(szFileName, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        PIMAGE_DOS_HEADER DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
        if(EngineValidateHeader(FileMapVA, FileHandle, NULL, DOSHeader, true))
        {
            DWORD NumberOfTLSCallBacks = NULL;
            engineBackupTLSAddress = NULL;
            RtlZeroMemory(&engineBackupTLSDataX86, sizeof IMAGE_TLS_DIRECTORY32);
            RtlZeroMemory(&engineBackupTLSDataX64, sizeof IMAGE_TLS_DIRECTORY64);
            ClearTlsVector(&engineBackupArrayOfCallBacks); //clear backup array

            std::vector<ULONG_PTR>* ArrayOfCallBacks = &engineBackupArrayOfCallBacks;
            LPDWORD NumberOfCallBacks = &engineBackupNumberOfCallBacks;

            PIMAGE_NT_HEADERS32 PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            PIMAGE_NT_HEADERS64 PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            bool FileIs64;
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
            if(!FileIs64) //x86
            {
                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                {
                    __try
                    {
                        engineBackupTLSx64 = false;
                        engineBackupTLSAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
                        ULONG_PTR TLSDirectoryAddress = (ULONG_PTR)((ULONG_PTR)PEHeader32->OptionalHeader.ImageBase + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                        PIMAGE_TLS_DIRECTORY32 TLSDirectoryX86 = (PIMAGE_TLS_DIRECTORY32)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryAddress, true);
                        RtlMoveMemory(&engineBackupTLSDataX86, (LPVOID)TLSDirectoryX86, sizeof IMAGE_TLS_DIRECTORY32);
                        if(TLSDirectoryX86->AddressOfCallBacks != NULL)
                        {
                            ULONG_PTR TLSCompareData = 0;
                            ULONG_PTR* TLSCallBackAddress = (ULONG_PTR*)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryX86->AddressOfCallBacks, true);
                            while(memcmp((LPVOID)TLSCallBackAddress, &TLSCompareData, sizeof ULONG_PTR) != NULL)
                            {
                                ArrayOfCallBacks->push_back(*TLSCallBackAddress);
                                TLSCallBackAddress++; //next callback
                                NumberOfTLSCallBacks++;
                            }
                            *NumberOfCallBacks = NumberOfTLSCallBacks;
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return true;
                        }
                        else
                        {
                            *NumberOfCallBacks = NULL;
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return false;
                        }
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        *NumberOfCallBacks = NULL;
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return false;
                    }
                }
                else
                {
                    *NumberOfCallBacks = NULL;
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return false;
                }
            }
            else //x64
            {
                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                {
                    __try
                    {
                        engineBackupTLSx64 = true;
                        engineBackupTLSAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
                        ULONG_PTR TLSDirectoryAddress = (ULONG_PTR)((ULONG_PTR)PEHeader64->OptionalHeader.ImageBase + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                        PIMAGE_TLS_DIRECTORY64 TLSDirectoryX64 = (PIMAGE_TLS_DIRECTORY64)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryAddress, true);
                        RtlMoveMemory(&engineBackupTLSDataX64, (LPVOID)TLSDirectoryX64, sizeof IMAGE_TLS_DIRECTORY64);
                        if(TLSDirectoryX64->AddressOfCallBacks != NULL)
                        {
                            ULONG_PTR TLSCompareData = 0;
                            ULONG_PTR* TLSCallBackAddress = (ULONG_PTR*)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryX64->AddressOfCallBacks, true);
                            while(memcmp((LPVOID)TLSCallBackAddress, &TLSCompareData, sizeof ULONG_PTR) != NULL)
                            {
                                ArrayOfCallBacks->push_back(*TLSCallBackAddress);
                                TLSCallBackAddress++; //next callback
                                NumberOfTLSCallBacks++;
                            }
                            *NumberOfCallBacks = NumberOfTLSCallBacks;
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return true;
                        }
                        else
                        {
                            *NumberOfCallBacks = NULL;
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return false;
                        }
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        *NumberOfCallBacks = NULL;
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return false;
                    }
                }
                else
                {
                    *NumberOfCallBacks = NULL;
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return false;
                }
            }
        }
        else
        {
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            return false;
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL TLSRestoreData()
{
    ULONG_PTR ueNumberOfBytesRead = NULL;
    if(dbgProcessInformation.hProcess != NULL && engineBackupTLSAddress != NULL)
    {
        if(engineBackupTLSx64)
        {
            if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)(engineBackupTLSAddress + GetDebuggedFileBaseAddress()), &engineBackupTLSDataX64, sizeof IMAGE_TLS_DIRECTORY64, &ueNumberOfBytesRead))
            {
                if(engineBackupTLSDataX64.AddressOfCallBacks != NULL && engineBackupNumberOfCallBacks != NULL)
                {
                    DynBuf BackupData(sizeof(ULONG_PTR)*engineBackupArrayOfCallBacks.size());
                    ULONG_PTR* Backup = (ULONG_PTR*)BackupData.GetPtr();
                    for(unsigned int i = 0; i < engineBackupArrayOfCallBacks.size(); i++)
                        Backup[i] = engineBackupArrayOfCallBacks.at(i);
                    if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)(engineBackupTLSDataX64.AddressOfCallBacks + GetDebuggedFileBaseAddress()), Backup, BackupData.Size(), &ueNumberOfBytesRead))
                    {
                        engineBackupTLSAddress = NULL;
                        return true;
                    }
                }
                else
                {
                    engineBackupTLSAddress = NULL;
                    return true;
                }
            }
        }
        else
        {
            if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)(engineBackupTLSAddress + GetDebuggedFileBaseAddress()), &engineBackupTLSDataX86, sizeof IMAGE_TLS_DIRECTORY32, &ueNumberOfBytesRead))
            {
                if(engineBackupTLSDataX86.AddressOfCallBacks != NULL && engineBackupNumberOfCallBacks != NULL)
                {
                    DynBuf BackupData(sizeof(ULONG_PTR)*engineBackupArrayOfCallBacks.size());
                    ULONG_PTR* Backup = (ULONG_PTR*)BackupData.GetPtr();
                    for(unsigned int i = 0; i < engineBackupArrayOfCallBacks.size(); i++)
                        Backup[i] = engineBackupArrayOfCallBacks.at(i);
                    if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)(engineBackupTLSDataX86.AddressOfCallBacks + GetDebuggedFileBaseAddress()), Backup, BackupData.Size(), &ueNumberOfBytesRead))
                    {
                        engineBackupTLSAddress = NULL;
                        return true;
                    }
                }
                else
                {
                    engineBackupTLSAddress = NULL;
                    return true;
                }
            }
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL TLSBuildNewTable(ULONG_PTR FileMapVA, ULONG_PTR StorePlace, ULONG_PTR StorePlaceRVA, LPVOID ArrayOfCallBacks, DWORD NumberOfCallBacks)
{
    if(FileMapVA != NULL)
    {
        PIMAGE_DOS_HEADER DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
        if(EngineValidateHeader(FileMapVA, NULL, NULL, DOSHeader, true))
        {
            PIMAGE_NT_HEADERS32 PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            PIMAGE_NT_HEADERS64 PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
            bool FileIs64;
            ULONG_PTR TLSWriteData = StorePlaceRVA;
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
                return false;
            }
            if(!FileIs64)
            {
                __try
                {
                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = (DWORD)StorePlaceRVA;
                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = sizeof IMAGE_TLS_DIRECTORY32;
                    PIMAGE_TLS_DIRECTORY32 TLSDirectoryX86 = (PIMAGE_TLS_DIRECTORY32)StorePlace;
                    TLSDirectoryX86->StartAddressOfRawData = (DWORD)TLSWriteData;
                    TLSDirectoryX86->EndAddressOfRawData = (DWORD)TLSWriteData + 0x10;
                    TLSDirectoryX86->AddressOfIndex = (DWORD)TLSWriteData + 0x14;
                    TLSDirectoryX86->AddressOfCallBacks = (DWORD)TLSWriteData  + sizeof IMAGE_TLS_DIRECTORY32 + 8;
                    RtlMoveMemory((LPVOID)(StorePlace + sizeof IMAGE_TLS_DIRECTORY32 + 8), ArrayOfCallBacks, NumberOfCallBacks * 4);
                    return true;
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    return false;
                }
            }
            else
            {
                __try
                {
                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = (DWORD)StorePlaceRVA;
                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = sizeof IMAGE_TLS_DIRECTORY64;
                    PIMAGE_TLS_DIRECTORY64 TLSDirectoryX64 = (PIMAGE_TLS_DIRECTORY64)StorePlace;
                    TLSDirectoryX64->StartAddressOfRawData = TLSWriteData;
                    TLSDirectoryX64->EndAddressOfRawData = TLSWriteData + 0x20;
                    TLSDirectoryX64->AddressOfIndex = TLSWriteData + 0x28;
                    TLSDirectoryX64->AddressOfCallBacks = TLSWriteData  + sizeof IMAGE_TLS_DIRECTORY64 + 12;
                    RtlMoveMemory((LPVOID)(StorePlace + sizeof IMAGE_TLS_DIRECTORY64 + 12), ArrayOfCallBacks, NumberOfCallBacks * 8);
                    return true;
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    return false;
                }
            }
        }
        else
        {
            return false;
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL TLSBuildNewTableEx(char* szFileName, char* szSectionName, LPVOID ArrayOfCallBacks, DWORD NumberOfCallBacks)
{
    wchar_t uniFileName[MAX_PATH] = {};
    if(szFileName)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return TLSBuildNewTableExW(uniFileName, szSectionName, ArrayOfCallBacks, NumberOfCallBacks);
    }
    return false;
}

__declspec(dllexport) bool TITCALL TLSBuildNewTableExW(wchar_t* szFileName, char* szSectionName, LPVOID ArrayOfCallBacks, DWORD NumberOfCallBacks)
{
    ULONG_PTR tlsImageBase = (ULONG_PTR)GetPE32DataW(szFileName, NULL, UE_IMAGEBASE);
    DWORD NewSectionVO = AddNewSectionW(szFileName, szSectionName, sizeof IMAGE_TLS_DIRECTORY64 * 2);
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    if(MapFileExW(szFileName, UE_ACCESS_ALL, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        DWORD NewSectionFO = (DWORD)ConvertVAtoFileOffset(FileMapVA, NewSectionVO + tlsImageBase, true);
        bool ReturnValue = false;
        if(NewSectionFO)
            ReturnValue = TLSBuildNewTable(FileMapVA, NewSectionFO, NewSectionVO, ArrayOfCallBacks, NumberOfCallBacks);
        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
        if(ReturnValue)
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    return false;
}
