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
static LPVOID engineBackupArrayOfCallBacks = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
static DWORD engineBackupTLSAddress = NULL;

// TitanEngine.TLSFixer.functions:
__declspec(dllexport) bool TITCALL TLSBreakOnCallBack(LPVOID ArrayOfCallBacks, DWORD NumberOfCallBacks, LPVOID bpxCallBack)
{

    unsigned int i;
    LPVOID ReadArrayOfCallBacks = ArrayOfCallBacks;

    if(NumberOfCallBacks > NULL)
    {
        for(i = 0; i < NumberOfCallBacks; i++)
        {
            RtlMoveMemory(&tlsCallBackList[i], ReadArrayOfCallBacks, sizeof ULONG_PTR);
            ReadArrayOfCallBacks = (LPVOID)((ULONG_PTR)ReadArrayOfCallBacks + sizeof ULONG_PTR);
        }
        engineTLSBreakOnCallBackAddress = (ULONG_PTR)bpxCallBack;
        engineTLSBreakOnCallBack = true;
        return(true);
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL TLSGrabCallBackData(char* szFileName, LPVOID ArrayOfCallBacks, LPDWORD NumberOfCallBacks)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        return(TLSGrabCallBackDataW(uniFileName, ArrayOfCallBacks, NumberOfCallBacks));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL TLSGrabCallBackDataW(wchar_t* szFileName, LPVOID ArrayOfCallBacks, LPDWORD NumberOfCallBacks)
{

    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    BOOL FileIs64;
    PIMAGE_TLS_DIRECTORY32 TLSDirectoryX86;
    PIMAGE_TLS_DIRECTORY64 TLSDirectoryX64;
    ULONG_PTR TLSDirectoryAddress;
    ULONG_PTR TLSCallBackAddress;
    ULONG_PTR TLSCompareData = NULL;
    DWORD NumberOfTLSCallBacks = NULL;

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
                return(false);
            }
            if(!FileIs64)
            {
                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                {
                    TLSDirectoryAddress = (ULONG_PTR)((ULONG_PTR)PEHeader32->OptionalHeader.ImageBase + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                    TLSDirectoryX86 = (PIMAGE_TLS_DIRECTORY32)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryAddress, true);
                    if(TLSDirectoryX86->AddressOfCallBacks != NULL)
                    {
                        TLSCallBackAddress = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryX86->AddressOfCallBacks, true);
                        while(memcmp((LPVOID)TLSCallBackAddress, &TLSCompareData, sizeof ULONG_PTR) != NULL)
                        {
                            RtlMoveMemory(ArrayOfCallBacks, (LPVOID)TLSCallBackAddress, sizeof ULONG_PTR);
                            ArrayOfCallBacks = (LPVOID)((ULONG_PTR)ArrayOfCallBacks + sizeof ULONG_PTR);
                            TLSCallBackAddress = TLSCallBackAddress + sizeof ULONG_PTR;
                            NumberOfTLSCallBacks++;
                        }
                        *NumberOfCallBacks = NumberOfTLSCallBacks;
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(true);
                    }
                    else
                    {
                        *NumberOfCallBacks = NULL;
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(false);
                    }
                }
                else
                {
                    *NumberOfCallBacks = NULL;
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return(false);
                }
            }
            else
            {
                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                {
                    TLSDirectoryAddress = (ULONG_PTR)((ULONG_PTR)PEHeader64->OptionalHeader.ImageBase + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                    TLSDirectoryX64 = (PIMAGE_TLS_DIRECTORY64)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryAddress, true);
                    if(TLSDirectoryX64->AddressOfCallBacks != NULL)
                    {
                        TLSCallBackAddress = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryX64->AddressOfCallBacks, true);
                        while(memcmp((LPVOID)TLSCallBackAddress, &TLSCompareData, sizeof ULONG_PTR) != NULL)
                        {
                            RtlMoveMemory(ArrayOfCallBacks, (LPVOID)TLSCallBackAddress, sizeof ULONG_PTR);
                            ArrayOfCallBacks = (LPVOID)((ULONG_PTR)ArrayOfCallBacks + sizeof ULONG_PTR);
                            TLSCallBackAddress = TLSCallBackAddress + sizeof ULONG_PTR;
                            NumberOfTLSCallBacks++;
                        }
                        *NumberOfCallBacks = NumberOfTLSCallBacks;
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(true);
                    }
                    else
                    {
                        *NumberOfCallBacks = NULL;
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(false);
                    }
                }
                else
                {
                    *NumberOfCallBacks = NULL;
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return(false);
                }
            }
        }
        else
        {
            *NumberOfCallBacks = NULL;
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            return(false);
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL TLSBreakOnCallBackEx(char* szFileName, LPVOID bpxCallBack)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        return(TLSBreakOnCallBackExW(uniFileName, bpxCallBack));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL TLSBreakOnCallBackExW(wchar_t* szFileName, LPVOID bpxCallBack)
{

    ULONG_PTR TlsArrayOfCallBacks[100];
    DWORD TlsNumberOfCallBacks;

    RtlZeroMemory(&TlsArrayOfCallBacks, 100 * sizeof ULONG_PTR);
    if(szFileName != NULL)
    {
        if(TLSGrabCallBackDataW(szFileName, &TlsArrayOfCallBacks, &TlsNumberOfCallBacks))
        {
            TLSBreakOnCallBack(&TlsArrayOfCallBacks, TlsNumberOfCallBacks, bpxCallBack);
            return(true);
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
}
__declspec(dllexport) bool TITCALL TLSRemoveCallback(char* szFileName)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        return(TLSRemoveCallbackW(uniFileName));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL TLSRemoveCallbackW(wchar_t* szFileName)
{

    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    BOOL FileIs64;
    PIMAGE_TLS_DIRECTORY32 TLSDirectoryX86;
    PIMAGE_TLS_DIRECTORY64 TLSDirectoryX64;
    ULONG_PTR TLSDirectoryAddress;

    if(MapFileExW(szFileName, UE_ACCESS_ALL, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
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
                return(false);
            }
            if(!FileIs64)
            {
                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                {
                    __try
                    {
                        TLSDirectoryAddress = (ULONG_PTR)((ULONG_PTR)PEHeader32->OptionalHeader.ImageBase + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                        TLSDirectoryX86 = (PIMAGE_TLS_DIRECTORY32)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryAddress, true);
                        if(TLSDirectoryX86->AddressOfCallBacks != NULL)
                        {
                            TLSDirectoryX86->AddressOfCallBacks = NULL;
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return(true);
                        }
                        else
                        {
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return(false);
                        }
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(false);
                    }
                }
                else
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return(false);
                }
            }
            else
            {
                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                {
                    __try
                    {
                        TLSDirectoryAddress = (ULONG_PTR)((ULONG_PTR)PEHeader64->OptionalHeader.ImageBase + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                        TLSDirectoryX64 = (PIMAGE_TLS_DIRECTORY64)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryAddress, true);
                        if(TLSDirectoryX64->AddressOfCallBacks != NULL)
                        {
                            TLSDirectoryX64->AddressOfCallBacks = NULL;
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return(true);
                        }
                        else
                        {
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return(false);
                        }
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(false);
                    }
                }
                else
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return(false);
                }
            }
        }
        else
        {
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            return(false);
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL TLSRemoveTable(char* szFileName)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        return(TLSRemoveTableW(uniFileName));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL TLSRemoveTableW(wchar_t* szFileName)
{

    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    BOOL FileIs64;
    PIMAGE_TLS_DIRECTORY32 TLSDirectoryX86;
    PIMAGE_TLS_DIRECTORY64 TLSDirectoryX64;
    ULONG_PTR TLSDirectoryAddress;

    if(MapFileExW(szFileName, UE_ACCESS_ALL, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
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
                return(false);
            }
            if(!FileIs64)
            {
                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                {
                    __try
                    {
                        TLSDirectoryAddress = (ULONG_PTR)((ULONG_PTR)PEHeader32->OptionalHeader.ImageBase + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                        TLSDirectoryX86 = (PIMAGE_TLS_DIRECTORY32)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryAddress, true);
                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = NULL;
                        PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = NULL;
                        RtlZeroMemory(TLSDirectoryX86, sizeof IMAGE_TLS_DIRECTORY32);
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(true);
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(false);
                    }
                }
                else
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return(false);
                }
            }
            else
            {
                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                {
                    __try
                    {
                        TLSDirectoryAddress = (ULONG_PTR)((ULONG_PTR)PEHeader64->OptionalHeader.ImageBase + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                        TLSDirectoryX64 = (PIMAGE_TLS_DIRECTORY64)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryAddress, true);
                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = NULL;
                        PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = NULL;
                        RtlZeroMemory(TLSDirectoryX64, sizeof IMAGE_TLS_DIRECTORY64);
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(true);
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(false);
                    }
                }
                else
                {
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return(false);
                }
            }
        }
        else
        {
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            return(false);
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL TLSBackupData(char* szFileName)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        return(TLSBackupDataW(uniFileName));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL TLSBackupDataW(wchar_t* szFileName)
{

    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    BOOL FileIs64;
    PIMAGE_TLS_DIRECTORY32 TLSDirectoryX86;
    PIMAGE_TLS_DIRECTORY64 TLSDirectoryX64;
    ULONG_PTR TLSDirectoryAddress;
    ULONG_PTR TLSCallBackAddress;
    ULONG_PTR TLSCompareData = NULL;
    DWORD NumberOfTLSCallBacks = NULL;
    LPVOID ArrayOfCallBacks = &engineBackupArrayOfCallBacks;
    LPDWORD NumberOfCallBacks = &engineBackupNumberOfCallBacks;

    engineBackupTLSAddress = NULL;
    RtlZeroMemory(engineBackupArrayOfCallBacks, 0x1000);
    RtlZeroMemory(&engineBackupTLSDataX86, sizeof IMAGE_TLS_DIRECTORY32);
    RtlZeroMemory(&engineBackupTLSDataX64, sizeof IMAGE_TLS_DIRECTORY64);
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
                return(false);
            }
            if(!FileIs64)
            {
                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                {
                    __try
                    {
                        engineBackupTLSx64 = false;
                        engineBackupTLSAddress = PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
                        TLSDirectoryAddress = (ULONG_PTR)((ULONG_PTR)PEHeader32->OptionalHeader.ImageBase + PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                        TLSDirectoryX86 = (PIMAGE_TLS_DIRECTORY32)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryAddress, true);
                        RtlMoveMemory(&engineBackupTLSDataX86, (LPVOID)TLSDirectoryX86, sizeof IMAGE_TLS_DIRECTORY32);
                        if(TLSDirectoryX86->AddressOfCallBacks != NULL)
                        {
                            TLSCallBackAddress = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryX86->AddressOfCallBacks, true);
                            while(memcmp((LPVOID)TLSCallBackAddress, &TLSCompareData, sizeof ULONG_PTR) != NULL)
                            {
                                RtlMoveMemory(ArrayOfCallBacks, (LPVOID)TLSCallBackAddress, sizeof ULONG_PTR);
                                ArrayOfCallBacks = (LPVOID)((ULONG_PTR)ArrayOfCallBacks + sizeof ULONG_PTR);
                                TLSCallBackAddress = TLSCallBackAddress + sizeof ULONG_PTR;
                                NumberOfTLSCallBacks++;
                            }
                            *NumberOfCallBacks = NumberOfTLSCallBacks;
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return(true);
                        }
                        else
                        {
                            *NumberOfCallBacks = NULL;
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return(false);
                        }
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        *NumberOfCallBacks = NULL;
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(false);
                    }
                }
                else
                {
                    *NumberOfCallBacks = NULL;
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return(false);
                }
            }
            else
            {
                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != NULL)
                {
                    __try
                    {
                        engineBackupTLSx64 = true;
                        engineBackupTLSAddress = PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
                        TLSDirectoryAddress = (ULONG_PTR)((ULONG_PTR)PEHeader64->OptionalHeader.ImageBase + PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
                        TLSDirectoryX64 = (PIMAGE_TLS_DIRECTORY64)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryAddress, true);
                        RtlMoveMemory(&engineBackupTLSDataX64, (LPVOID)TLSDirectoryX64, sizeof IMAGE_TLS_DIRECTORY64);
                        if(TLSDirectoryX64->AddressOfCallBacks != NULL)
                        {
                            TLSCallBackAddress = (ULONG_PTR)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)TLSDirectoryX64->AddressOfCallBacks, true);
                            while(memcmp((LPVOID)TLSCallBackAddress, &TLSCompareData, sizeof ULONG_PTR) != NULL)
                            {
                                RtlMoveMemory(ArrayOfCallBacks, (LPVOID)TLSCallBackAddress, sizeof ULONG_PTR);
                                ArrayOfCallBacks = (LPVOID)((ULONG_PTR)ArrayOfCallBacks + sizeof ULONG_PTR);
                                TLSCallBackAddress = TLSCallBackAddress + sizeof ULONG_PTR;
                                NumberOfTLSCallBacks++;
                            }
                            *NumberOfCallBacks = NumberOfTLSCallBacks;
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return(true);
                        }
                        else
                        {
                            *NumberOfCallBacks = NULL;
                            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                            return(false);
                        }
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        *NumberOfCallBacks = NULL;
                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                        return(false);
                    }
                }
                else
                {
                    *NumberOfCallBacks = NULL;
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    return(false);
                }
            }
        }
        else
        {
            *NumberOfCallBacks = NULL;
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            return(false);
        }
    }
    return(false);
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
                    if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)(engineBackupTLSDataX64.AddressOfCallBacks + GetDebuggedFileBaseAddress()), engineBackupArrayOfCallBacks, sizeof IMAGE_TLS_DIRECTORY64, &ueNumberOfBytesRead))
                    {
                        engineBackupTLSAddress = NULL;
                        return(true);
                    }
                }
                else
                {
                    engineBackupTLSAddress = NULL;
                    return(true);
                }
            }
        }
        else
        {
            if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)(engineBackupTLSAddress + GetDebuggedFileBaseAddress()), &engineBackupTLSDataX86, sizeof IMAGE_TLS_DIRECTORY32, &ueNumberOfBytesRead))
            {
                if(engineBackupTLSDataX86.AddressOfCallBacks != NULL && engineBackupNumberOfCallBacks != NULL)
                {
                    if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)(engineBackupTLSDataX86.AddressOfCallBacks + GetDebuggedFileBaseAddress()), engineBackupArrayOfCallBacks, sizeof IMAGE_TLS_DIRECTORY32, &ueNumberOfBytesRead))
                    {
                        engineBackupTLSAddress = NULL;
                        return(true);
                    }
                }
                else
                {
                    engineBackupTLSAddress = NULL;
                    return(true);
                }
            }
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL TLSBuildNewTable(ULONG_PTR FileMapVA, ULONG_PTR StorePlace, ULONG_PTR StorePlaceRVA, LPVOID ArrayOfCallBacks, DWORD NumberOfCallBacks)
{

    BOOL FileIs64;
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_TLS_DIRECTORY32 TLSDirectoryX86;
    PIMAGE_TLS_DIRECTORY64 TLSDirectoryX64;
    ULONG_PTR TLSWriteData = StorePlaceRVA;

    if(FileMapVA != NULL)
    {
        DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
        if(EngineValidateHeader(FileMapVA, NULL, NULL, DOSHeader, true))
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
                return(false);
            }
            if(!FileIs64)
            {
                __try
                {
                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = (DWORD)StorePlaceRVA;
                    PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = sizeof IMAGE_TLS_DIRECTORY32;
                    TLSDirectoryX86 = (PIMAGE_TLS_DIRECTORY32)StorePlace;
                    TLSDirectoryX86->StartAddressOfRawData = (DWORD)TLSWriteData;
                    TLSDirectoryX86->EndAddressOfRawData = (DWORD)TLSWriteData + 0x10;
                    TLSDirectoryX86->AddressOfIndex = (DWORD)TLSWriteData + 0x14;
                    TLSDirectoryX86->AddressOfCallBacks = (DWORD)TLSWriteData  + sizeof IMAGE_TLS_DIRECTORY32 + 8;
                    RtlMoveMemory((LPVOID)(StorePlace + sizeof IMAGE_TLS_DIRECTORY32 + 8), ArrayOfCallBacks, NumberOfCallBacks * 4);
                    return(true);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    return(false);
                }
            }
            else
            {
                __try
                {
                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = (DWORD)StorePlaceRVA;
                    PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = sizeof IMAGE_TLS_DIRECTORY64;
                    TLSDirectoryX64 = (PIMAGE_TLS_DIRECTORY64)StorePlace;
                    TLSDirectoryX64->StartAddressOfRawData = TLSWriteData;
                    TLSDirectoryX64->EndAddressOfRawData = TLSWriteData + 0x20;
                    TLSDirectoryX64->AddressOfIndex = TLSWriteData + 0x28;
                    TLSDirectoryX64->AddressOfCallBacks = TLSWriteData  + sizeof IMAGE_TLS_DIRECTORY64 + 12;
                    RtlMoveMemory((LPVOID)(StorePlace + sizeof IMAGE_TLS_DIRECTORY64 + 12), ArrayOfCallBacks, NumberOfCallBacks * 8);
                    return(true);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
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
    return(false);
}
__declspec(dllexport) bool TITCALL TLSBuildNewTableEx(char* szFileName, char* szSectionName, LPVOID ArrayOfCallBacks, DWORD NumberOfCallBacks)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName)+1, uniFileName, sizeof(uniFileName)/(sizeof(uniFileName[0])));
        return(TLSBuildNewTableExW(uniFileName, szSectionName, ArrayOfCallBacks, NumberOfCallBacks));
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL TLSBuildNewTableExW(wchar_t* szFileName, char* szSectionName, LPVOID ArrayOfCallBacks, DWORD NumberOfCallBacks)
{

    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    DWORD NewSectionVO = NULL;
    DWORD NewSectionFO = NULL;
    bool ReturnValue = false;
    ULONG_PTR tlsImageBase;

    tlsImageBase = (ULONG_PTR)GetPE32DataW(szFileName, NULL, UE_IMAGEBASE);
    NewSectionVO = AddNewSectionW(szFileName, szSectionName, sizeof IMAGE_TLS_DIRECTORY64 * 2);
    if(MapFileExW(szFileName, UE_ACCESS_ALL, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        NewSectionFO = (DWORD)ConvertVAtoFileOffset(FileMapVA, NewSectionVO + tlsImageBase, true);
        ReturnValue = TLSBuildNewTable(FileMapVA, NewSectionFO, NewSectionVO, ArrayOfCallBacks, NumberOfCallBacks);
        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
        if(ReturnValue)
        {
            return(true);
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
}