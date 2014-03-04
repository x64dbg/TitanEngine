#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.h"
#include "Global.Handle.h"
#include <psapi.h>

//TitanEngine.Dumper.functions:
__declspec(dllexport) bool TITCALL DumpProcess(HANDLE hProcess, LPVOID ImageBase, char* szDumpFileName, ULONG_PTR EntryPoint)
{
    wchar_t uniDumpFileName[MAX_PATH] = {};
    if(szDumpFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpFileName, lstrlenA(szDumpFileName)+1, uniDumpFileName, sizeof(uniDumpFileName)/(sizeof(uniDumpFileName[0])));
        return DumpProcessW(hProcess, ImageBase, uniDumpFileName, EntryPoint);
    }
    return false;
}

__declspec(dllexport) bool TITCALL DumpProcessW(HANDLE hProcess, LPVOID ImageBase, wchar_t* szDumpFileName, ULONG_PTR EntryPoint)
{
    int i = 0;
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_DOS_HEADER DOSFixHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_NT_HEADERS32 PEFixHeader32;
    PIMAGE_NT_HEADERS64 PEFixHeader64;
    PIMAGE_SECTION_HEADER PESections;
    PIMAGE_SECTION_HEADER PEFixSection;
    ULONG_PTR ueNumberOfBytesRead = 0;
    DWORD uedNumberOfBytesRead = 0;
    DWORD SizeOfImageDump = 0;
    int NumberOfSections = 0;
    BOOL FileIs64 = false;
    HANDLE hFile = 0;
    DWORD RealignedVirtualSize = 0;
    ULONG_PTR ProcReadBase = 0;
    LPVOID ReadBase = ImageBase;
    SIZE_T CalculatedHeaderSize = NULL;
    SIZE_T AlignedHeaderSize = NULL;
    LPVOID ueReadBuffer = VirtualAlloc(NULL, 0x2000, MEM_COMMIT, PAGE_READWRITE);
    LPVOID ueCopyBuffer = VirtualAlloc(NULL, 0x2000, MEM_COMMIT, PAGE_READWRITE);
    MEMORY_BASIC_INFORMATION MemInfo;

    if(ReadProcessMemory(hProcess, ImageBase, ueReadBuffer, 0x1000, &ueNumberOfBytesRead))
    {
        DOSHeader = (PIMAGE_DOS_HEADER)ueReadBuffer;
        CalculatedHeaderSize = DOSHeader->e_lfanew + sizeof IMAGE_DOS_HEADER + sizeof IMAGE_NT_HEADERS64;
        if(CalculatedHeaderSize > 0x1000)
        {
            if(CalculatedHeaderSize % 0x1000 == NULL)
            {
                AlignedHeaderSize = 0x1000;
            }
            else
            {
                AlignedHeaderSize = ((CalculatedHeaderSize / 0x1000) + 1) * 0x1000;
            }
            VirtualFree(ueReadBuffer, NULL, MEM_RELEASE);
            VirtualFree(ueCopyBuffer, NULL, MEM_RELEASE);
            ueReadBuffer = VirtualAlloc(NULL, AlignedHeaderSize, MEM_COMMIT, PAGE_READWRITE);
            ueCopyBuffer = VirtualAlloc(NULL, AlignedHeaderSize, MEM_COMMIT, PAGE_READWRITE);
            if(!ReadProcessMemory(hProcess, ImageBase, ueReadBuffer, AlignedHeaderSize, &ueNumberOfBytesRead))
            {
                VirtualFree(ueReadBuffer, NULL, MEM_RELEASE);
                VirtualFree(ueCopyBuffer, NULL, MEM_RELEASE);
                return false;
            }
            else
            {
                DOSHeader = (PIMAGE_DOS_HEADER)ueReadBuffer;
            }
        }
        else
        {
            CalculatedHeaderSize = 0x1000;
            AlignedHeaderSize = 0x1000;
        }
        if(EngineValidateHeader((ULONG_PTR)ueReadBuffer, hProcess, ImageBase, DOSHeader, false))
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
                VirtualFree(ueReadBuffer, NULL, MEM_RELEASE);
                VirtualFree(ueCopyBuffer, NULL, MEM_RELEASE);
                return false;
            }
            if(!FileIs64)
            {
                PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PEHeader32 + PEHeader32->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4);
                NumberOfSections = PEHeader32->FileHeader.NumberOfSections;
                NumberOfSections++;
                if(PEHeader32->OptionalHeader.SizeOfImage % PEHeader32->OptionalHeader.SectionAlignment == NULL)
                {
                    SizeOfImageDump = ((PEHeader32->OptionalHeader.SizeOfImage / PEHeader32->OptionalHeader.SectionAlignment)) * PEHeader32->OptionalHeader.SectionAlignment;
                }
                else
                {
                    SizeOfImageDump = ((PEHeader32->OptionalHeader.SizeOfImage / PEHeader32->OptionalHeader.SectionAlignment) + 1) * PEHeader32->OptionalHeader.SectionAlignment;
                }
                SizeOfImageDump = SizeOfImageDump - (DWORD)AlignedHeaderSize;
                if(EngineCreatePathForFileW(szDumpFileName))
                {
                    hFile = CreateFileW(szDumpFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                    if(hFile != INVALID_HANDLE_VALUE)
                    {
                        if(ReadProcessMemory(hProcess, ImageBase, ueCopyBuffer, AlignedHeaderSize, &ueNumberOfBytesRead))
                        {
                            __try
                            {
                                DOSFixHeader = (PIMAGE_DOS_HEADER)ueCopyBuffer;
                                PEFixHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSFixHeader + DOSFixHeader->e_lfanew);
                                PEFixSection = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PEFixHeader32 + PEHeader32->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4);
                                if(PEFixHeader32->OptionalHeader.FileAlignment > 0x200)
                                {
                                    PEFixHeader32->OptionalHeader.FileAlignment = PEHeader32->OptionalHeader.SectionAlignment;
                                }
                                PEFixHeader32->OptionalHeader.AddressOfEntryPoint = (DWORD)(EntryPoint - (ULONG_PTR)ImageBase);
                                PEFixHeader32->OptionalHeader.ImageBase = (DWORD)((ULONG_PTR)ImageBase);
                                i = NumberOfSections;
                                while(i >= 1)
                                {
                                    PEFixSection->PointerToRawData = PEFixSection->VirtualAddress;
                                    RealignedVirtualSize = (PEFixSection->Misc.VirtualSize / PEHeader32->OptionalHeader.SectionAlignment) * PEHeader32->OptionalHeader.SectionAlignment;
                                    if(RealignedVirtualSize < PEFixSection->Misc.VirtualSize)
                                    {
                                        RealignedVirtualSize = RealignedVirtualSize + PEHeader32->OptionalHeader.SectionAlignment;
                                    }
                                    PEFixSection->SizeOfRawData = RealignedVirtualSize;
                                    PEFixSection->Misc.VirtualSize = RealignedVirtualSize;
                                    PEFixSection = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PEFixSection + IMAGE_SIZEOF_SECTION_HEADER);
                                    i--;
                                }
                                WriteFile(hFile, ueCopyBuffer, (DWORD)AlignedHeaderSize, &uedNumberOfBytesRead, NULL);
                                ReadBase = (LPVOID)((ULONG_PTR)ReadBase + AlignedHeaderSize - TITANENGINE_PAGESIZE);
                                while(SizeOfImageDump > NULL)
                                {
                                    ProcReadBase = (ULONG_PTR)ReadBase + TITANENGINE_PAGESIZE;
                                    ReadBase = (LPVOID)ProcReadBase;
                                    if(SizeOfImageDump >= TITANENGINE_PAGESIZE)
                                    {
                                        RtlZeroMemory(ueCopyBuffer, AlignedHeaderSize);
                                        if(!ReadProcessMemory(hProcess, ReadBase, ueCopyBuffer, TITANENGINE_PAGESIZE, &ueNumberOfBytesRead))
                                        {
                                            VirtualQueryEx(hProcess, ReadBase, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
                                            VirtualProtectEx(hProcess, ReadBase, TITANENGINE_PAGESIZE, PAGE_EXECUTE_READWRITE, &MemInfo.Protect);
                                            ReadProcessMemory(hProcess, ReadBase, ueCopyBuffer, TITANENGINE_PAGESIZE, &ueNumberOfBytesRead);
                                            VirtualProtectEx(hProcess, ReadBase, TITANENGINE_PAGESIZE, MemInfo.Protect, &MemInfo.Protect);
                                        }
                                        WriteFile(hFile, ueCopyBuffer, TITANENGINE_PAGESIZE, &uedNumberOfBytesRead, NULL);
                                        SizeOfImageDump = SizeOfImageDump - TITANENGINE_PAGESIZE;
                                    }
                                    else
                                    {
                                        RtlZeroMemory(ueCopyBuffer, AlignedHeaderSize);
                                        if(!ReadProcessMemory(hProcess, ReadBase, ueCopyBuffer, SizeOfImageDump, &ueNumberOfBytesRead))
                                        {
                                            VirtualQueryEx(hProcess, ReadBase, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
                                            VirtualProtectEx(hProcess, ReadBase, TITANENGINE_PAGESIZE, PAGE_EXECUTE_READWRITE, &MemInfo.Protect);
                                            ReadProcessMemory(hProcess, ReadBase, ueCopyBuffer, TITANENGINE_PAGESIZE, &ueNumberOfBytesRead);
                                            VirtualProtectEx(hProcess, ReadBase, TITANENGINE_PAGESIZE, MemInfo.Protect, &MemInfo.Protect);
                                        }
                                        WriteFile(hFile, ueCopyBuffer, SizeOfImageDump, &uedNumberOfBytesRead, NULL);
                                        SizeOfImageDump = NULL;
                                    }
                                }
                                EngineCloseHandle(hFile);
                                VirtualFree(ueReadBuffer, NULL, MEM_RELEASE);
                                VirtualFree(ueCopyBuffer, NULL, MEM_RELEASE);
                                return true;
                            }
                            __except(EXCEPTION_EXECUTE_HANDLER)
                            {
                                EngineCloseHandle(hFile);
                                VirtualFree(ueReadBuffer, NULL, MEM_RELEASE);
                                VirtualFree(ueCopyBuffer, NULL, MEM_RELEASE);
                                return false;
                            }
                        }
                        else
                        {
                            EngineCloseHandle(hFile);
                            VirtualFree(ueReadBuffer, NULL, MEM_RELEASE);
                            VirtualFree(ueCopyBuffer, NULL, MEM_RELEASE);
                            return false;
                        }
                    }
                    else
                    {
                        VirtualFree(ueReadBuffer, NULL, MEM_RELEASE);
                        VirtualFree(ueCopyBuffer, NULL, MEM_RELEASE);
                        return false;
                    }
                }
            }
            else
            {
                PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PEHeader64 + PEHeader64->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4);
                NumberOfSections = PEHeader64->FileHeader.NumberOfSections;
                NumberOfSections++;
                if(PEHeader64->OptionalHeader.SizeOfImage % PEHeader64->OptionalHeader.SectionAlignment == NULL)
                {
                    SizeOfImageDump = ((PEHeader64->OptionalHeader.SizeOfImage / PEHeader64->OptionalHeader.SectionAlignment)) * PEHeader64->OptionalHeader.SectionAlignment;
                }
                else
                {
                    SizeOfImageDump = ((PEHeader64->OptionalHeader.SizeOfImage / PEHeader64->OptionalHeader.SectionAlignment) + 1) * PEHeader64->OptionalHeader.SectionAlignment;
                }
                SizeOfImageDump = SizeOfImageDump - (DWORD)AlignedHeaderSize;
                if(EngineCreatePathForFileW(szDumpFileName))
                {
                    hFile = CreateFileW(szDumpFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                    if(hFile != INVALID_HANDLE_VALUE)
                    {
                        if(ReadProcessMemory(hProcess, ImageBase, ueCopyBuffer, AlignedHeaderSize, &ueNumberOfBytesRead))
                        {
                            __try
                            {
                                DOSFixHeader = (PIMAGE_DOS_HEADER)ueCopyBuffer;
                                PEFixHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSFixHeader + DOSFixHeader->e_lfanew);
                                PEFixSection = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PEFixHeader64 + PEHeader64->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4);
                                if(PEFixHeader64->OptionalHeader.FileAlignment > 0x200)
                                {
                                    PEFixHeader64->OptionalHeader.FileAlignment = PEHeader64->OptionalHeader.SectionAlignment;
                                }
                                PEFixHeader64->OptionalHeader.AddressOfEntryPoint = (DWORD)(EntryPoint - (ULONG_PTR)ImageBase);
                                PEFixHeader64->OptionalHeader.ImageBase = (DWORD64)((ULONG_PTR)ImageBase);
                                i = NumberOfSections;
                                while(i >= 1)
                                {
                                    PEFixSection->PointerToRawData = PEFixSection->VirtualAddress;
                                    RealignedVirtualSize = (PEFixSection->Misc.VirtualSize / PEHeader64->OptionalHeader.SectionAlignment) * PEHeader64->OptionalHeader.SectionAlignment;
                                    if(RealignedVirtualSize < PEFixSection->Misc.VirtualSize)
                                    {
                                        RealignedVirtualSize = RealignedVirtualSize + PEHeader64->OptionalHeader.SectionAlignment;
                                    }
                                    PEFixSection->SizeOfRawData = RealignedVirtualSize;
                                    PEFixSection->Misc.VirtualSize = RealignedVirtualSize;
                                    PEFixSection = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PEFixSection + IMAGE_SIZEOF_SECTION_HEADER);
                                    i--;
                                }
                                WriteFile(hFile,ueCopyBuffer, (DWORD)AlignedHeaderSize, &uedNumberOfBytesRead, NULL);
                                ReadBase = (LPVOID)((ULONG_PTR)ReadBase + (DWORD)AlignedHeaderSize - TITANENGINE_PAGESIZE);
                                while(SizeOfImageDump > NULL)
                                {
                                    ProcReadBase = (ULONG_PTR)ReadBase + TITANENGINE_PAGESIZE;
                                    ReadBase = (LPVOID)ProcReadBase;
                                    if(SizeOfImageDump >= TITANENGINE_PAGESIZE)
                                    {
                                        RtlZeroMemory(ueCopyBuffer, AlignedHeaderSize);
                                        if(!ReadProcessMemory(hProcess, ReadBase, ueCopyBuffer, TITANENGINE_PAGESIZE, &ueNumberOfBytesRead))
                                        {
                                            VirtualQueryEx(hProcess, ReadBase, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
                                            VirtualProtectEx(hProcess, ReadBase, TITANENGINE_PAGESIZE, PAGE_EXECUTE_READWRITE, &MemInfo.Protect);
                                            ReadProcessMemory(hProcess, ReadBase, ueCopyBuffer, TITANENGINE_PAGESIZE, &ueNumberOfBytesRead);
                                            VirtualProtectEx(hProcess, ReadBase, TITANENGINE_PAGESIZE, MemInfo.Protect, &MemInfo.Protect);
                                        }
                                        WriteFile(hFile, ueCopyBuffer, TITANENGINE_PAGESIZE, &uedNumberOfBytesRead, NULL);
                                        SizeOfImageDump = SizeOfImageDump - TITANENGINE_PAGESIZE;
                                    }
                                    else
                                    {
                                        RtlZeroMemory(ueCopyBuffer, AlignedHeaderSize);
                                        if(!ReadProcessMemory(hProcess, ReadBase, ueCopyBuffer, SizeOfImageDump, &ueNumberOfBytesRead))
                                        {
                                            VirtualQueryEx(hProcess, ReadBase, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
                                            VirtualProtectEx(hProcess, ReadBase, TITANENGINE_PAGESIZE, PAGE_EXECUTE_READWRITE, &MemInfo.Protect);
                                            ReadProcessMemory(hProcess, ReadBase, ueCopyBuffer, TITANENGINE_PAGESIZE, &ueNumberOfBytesRead);
                                            VirtualProtectEx(hProcess, ReadBase, TITANENGINE_PAGESIZE, MemInfo.Protect, &MemInfo.Protect);
                                        }
                                        WriteFile(hFile, ueCopyBuffer, SizeOfImageDump, &uedNumberOfBytesRead, NULL);
                                        SizeOfImageDump = NULL;
                                    }
                                }
                                EngineCloseHandle(hFile);
                                VirtualFree(ueReadBuffer, NULL, MEM_RELEASE);
                                VirtualFree(ueCopyBuffer, NULL, MEM_RELEASE);
                                return true;
                            }
                            __except(EXCEPTION_EXECUTE_HANDLER)
                            {
                                VirtualFree(ueReadBuffer, NULL, MEM_RELEASE);
                                VirtualFree(ueCopyBuffer, NULL, MEM_RELEASE);
                                return false;
                            }
                        }
                        else
                        {
                            EngineCloseHandle(hFile);
                            VirtualFree(ueReadBuffer, NULL, MEM_RELEASE);
                            VirtualFree(ueCopyBuffer, NULL, MEM_RELEASE);
                            return false;
                        }
                    }
                    else
                    {
                        EngineCloseHandle(hFile);
                        VirtualFree(ueReadBuffer, NULL, MEM_RELEASE);
                        VirtualFree(ueCopyBuffer, NULL, MEM_RELEASE);
                        return false;
                    }
                }
            }
        }
        else
        {
            VirtualFree(ueReadBuffer, NULL, MEM_RELEASE);
            VirtualFree(ueCopyBuffer, NULL, MEM_RELEASE);
            return false;
        }
    }
    else
    {
        VirtualFree(ueReadBuffer, NULL, MEM_RELEASE);
        VirtualFree(ueCopyBuffer, NULL, MEM_RELEASE);
        return false;
    }
    return false;
}

__declspec(dllexport) bool TITCALL DumpProcessEx(DWORD ProcessId, LPVOID ImageBase, char* szDumpFileName, ULONG_PTR EntryPoint)
{

    wchar_t uniDumpFileName[MAX_PATH] = {};

    if(szDumpFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpFileName, lstrlenA(szDumpFileName)+1, uniDumpFileName, sizeof(uniDumpFileName)/(sizeof(uniDumpFileName[0])));
        return(DumpProcessExW(ProcessId, ImageBase, uniDumpFileName, EntryPoint));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL DumpProcessExW(DWORD ProcessId, LPVOID ImageBase, wchar_t* szDumpFileName, ULONG_PTR EntryPoint)
{

    HANDLE hProcess = 0;
    BOOL ReturnValue = false;

    hProcess = OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
    if(hProcess != INVALID_HANDLE_VALUE)
    {
        ReturnValue = DumpProcessW(hProcess, ImageBase, szDumpFileName, EntryPoint);
        EngineCloseHandle(hProcess);
        if(ReturnValue)
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL DumpMemory(HANDLE hProcess, LPVOID MemoryStart, ULONG_PTR MemorySize, char* szDumpFileName)
{

    wchar_t uniDumpFileName[MAX_PATH] = {};

    if(szDumpFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpFileName, lstrlenA(szDumpFileName)+1, uniDumpFileName, sizeof(uniDumpFileName)/(sizeof(uniDumpFileName[0])));
        return(DumpMemoryW(hProcess, MemoryStart, MemorySize, uniDumpFileName));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL DumpMemoryW(HANDLE hProcess, LPVOID MemoryStart, ULONG_PTR MemorySize, wchar_t* szDumpFileName)
{

    ULONG_PTR ueNumberOfBytesRead = 0;
    DWORD uedNumberOfBytesRead = 0;
    HANDLE hFile = 0;
    LPVOID ReadBase = MemoryStart;
    ULONG_PTR ProcReadBase = (ULONG_PTR)ReadBase;
    LPVOID ueCopyBuffer = VirtualAlloc(NULL, 0x2000, MEM_COMMIT, PAGE_READWRITE);
    MEMORY_BASIC_INFORMATION MemInfo;

    if(EngineCreatePathForFileW(szDumpFileName))
    {
        hFile = CreateFileW(szDumpFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if(hFile != INVALID_HANDLE_VALUE)
        {
            while(MemorySize > NULL)
            {
                ReadBase = (LPVOID)ProcReadBase;
                if(MemorySize >= 0x1000)
                {
                    RtlZeroMemory(ueCopyBuffer,0x2000);
                    if(!ReadProcessMemory(hProcess, ReadBase, ueCopyBuffer, 0x1000, &ueNumberOfBytesRead))
                    {
                        VirtualQueryEx(hProcess, ReadBase, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
                        VirtualProtectEx(hProcess, ReadBase, 0x1000, PAGE_EXECUTE_READWRITE, &MemInfo.Protect);
                        ReadProcessMemory(hProcess, ReadBase, ueCopyBuffer, 0x1000, &ueNumberOfBytesRead);
                        VirtualProtectEx(hProcess, ReadBase, 0x1000, MemInfo.Protect, &MemInfo.Protect);
                    }
                    WriteFile(hFile,ueCopyBuffer, 0x1000, &uedNumberOfBytesRead, NULL);
                    MemorySize = MemorySize - 0x1000;
                }
                else
                {
                    RtlZeroMemory(ueCopyBuffer,0x2000);
                    if(!ReadProcessMemory(hProcess, ReadBase, ueCopyBuffer, MemorySize, &ueNumberOfBytesRead))
                    {
                        VirtualQueryEx(hProcess, ReadBase, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
                        VirtualProtectEx(hProcess, ReadBase, 0x1000, PAGE_EXECUTE_READWRITE, &MemInfo.Protect);
                        ReadProcessMemory(hProcess, ReadBase, ueCopyBuffer, 0x1000, &ueNumberOfBytesRead);
                        VirtualProtectEx(hProcess, ReadBase, 0x1000, MemInfo.Protect, &MemInfo.Protect);
                    }
                    WriteFile(hFile, ueCopyBuffer, (DWORD)MemorySize, &uedNumberOfBytesRead, NULL);
                    MemorySize = NULL;
                }
                ProcReadBase = (ULONG_PTR)ReadBase + 0x1000;
            }
            EngineCloseHandle(hFile);
            VirtualFree(ueCopyBuffer, NULL, MEM_RELEASE);
            return true;
        }
        else
        {
            VirtualFree(ueCopyBuffer, NULL, MEM_RELEASE);
            return false;
        }
    }
    return true;
}

__declspec(dllexport) bool TITCALL DumpMemoryEx(DWORD ProcessId, LPVOID MemoryStart, ULONG_PTR MemorySize, char* szDumpFileName)
{

    wchar_t uniDumpFileName[MAX_PATH] = {};

    if(szDumpFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpFileName, lstrlenA(szDumpFileName)+1, uniDumpFileName, sizeof(uniDumpFileName)/(sizeof(uniDumpFileName[0])));
        return(DumpMemoryExW(ProcessId, MemoryStart, MemorySize, uniDumpFileName));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL DumpMemoryExW(DWORD ProcessId, LPVOID MemoryStart, ULONG_PTR MemorySize, wchar_t* szDumpFileName)
{

    HANDLE hProcess = 0;
    BOOL ReturnValue = false;

    hProcess = OpenProcess(PROCESS_VM_READ, FALSE, ProcessId);
    if(hProcess != INVALID_HANDLE_VALUE)
    {
        ReturnValue = DumpMemoryW(hProcess, MemoryStart, MemorySize, szDumpFileName);
        EngineCloseHandle(hProcess);
        if(ReturnValue)
        {
            return true;
        }
    }

    return false;
}

__declspec(dllexport) bool TITCALL DumpRegions(HANDLE hProcess, char* szDumpFolder, bool DumpAboveImageBaseOnly)
{

    wchar_t uniDumpFolder[MAX_PATH] = {};

    if(szDumpFolder != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpFolder, lstrlenA(szDumpFolder)+1, uniDumpFolder, sizeof(uniDumpFolder)/(sizeof(uniDumpFolder[0])));
        return(DumpRegionsW(hProcess, uniDumpFolder, DumpAboveImageBaseOnly));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL DumpRegionsW(HANDLE hProcess, wchar_t* szDumpFolder, bool DumpAboveImageBaseOnly)
{

    int i;
    DWORD Dummy = NULL;
    wchar_t szDumpName[MAX_PATH];
    wchar_t szDumpFileName[MAX_PATH];
    MEMORY_BASIC_INFORMATION MemInfo;
    ULONG_PTR DumpAddress = NULL;
    ULONG_PTR EnumeratedModules[1024];
    bool AddressIsModuleBase = false;

    if(hProcess != NULL)
    {
        EnumProcessModules(hProcess, (HMODULE*)EnumeratedModules, sizeof(EnumeratedModules), &Dummy);
        while(VirtualQueryEx(hProcess, (LPVOID)DumpAddress, &MemInfo, sizeof MEMORY_BASIC_INFORMATION) != NULL)
        {
            AddressIsModuleBase = false;
            for(i = 0; i < 1024; i++)
            {
                if(EnumeratedModules[i] == (ULONG_PTR)MemInfo.AllocationBase)
                {
                    AddressIsModuleBase = true;
                    i = 1024;
                }
                else if(EnumeratedModules[i] == 0)
                {
                    i = 1024;
                }
            }
            if(!(MemInfo.Protect & PAGE_NOACCESS) && AddressIsModuleBase == false)
            {
                if(DumpAboveImageBaseOnly == false || (DumpAboveImageBaseOnly == true && EnumeratedModules[0] < (ULONG_PTR)MemInfo.BaseAddress))
                {
                    RtlZeroMemory(&szDumpName, MAX_PATH);
                    RtlZeroMemory(&szDumpFileName, MAX_PATH);
                    lstrcpyW(szDumpFileName, szDumpFolder);
                    if(szDumpFileName[lstrlenW(szDumpFileName)-1] != 0x5C)
                    {
                        szDumpFileName[lstrlenW(szDumpFileName)] = 0x5C;
                    }
                    wsprintfW(szDumpName, L"Dump-%x_%x.dmp", (ULONG_PTR)MemInfo.BaseAddress, (ULONG_PTR)MemInfo.RegionSize);
                    lstrcatW(szDumpFileName, szDumpName);
                    DumpMemoryW(hProcess, (LPVOID)MemInfo.BaseAddress, (ULONG_PTR)MemInfo.RegionSize, szDumpFileName);
                }
            }
            DumpAddress = DumpAddress + (ULONG_PTR)MemInfo.RegionSize;
        }
        return true;
    }
    return false;
}

__declspec(dllexport) bool TITCALL DumpRegionsEx(DWORD ProcessId, char* szDumpFolder, bool DumpAboveImageBaseOnly)
{

    wchar_t uniDumpFolder[MAX_PATH] = {};

    if(szDumpFolder != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpFolder, lstrlenA(szDumpFolder)+1, uniDumpFolder, sizeof(uniDumpFolder)/(sizeof(uniDumpFolder[0])));
        return(DumpRegionsExW(ProcessId, uniDumpFolder, DumpAboveImageBaseOnly));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL DumpRegionsExW(DWORD ProcessId, wchar_t* szDumpFolder, bool DumpAboveImageBaseOnly)
{

    HANDLE hProcess = 0;
    BOOL ReturnValue = false;

    hProcess = OpenProcess(PROCESS_VM_READ, FALSE, ProcessId);
    if(hProcess != INVALID_HANDLE_VALUE)
    {
        ReturnValue = DumpRegionsW(hProcess, szDumpFolder, DumpAboveImageBaseOnly);
        EngineCloseHandle(hProcess);
        if(ReturnValue)
        {
            return true;
        }
    }

    return false;
}

__declspec(dllexport) bool TITCALL DumpModule(HANDLE hProcess, LPVOID ModuleBase, char* szDumpFileName)
{

    wchar_t uniDumpFileName[MAX_PATH] = {};

    if(szDumpFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpFileName, lstrlenA(szDumpFileName)+1, uniDumpFileName, sizeof(uniDumpFileName)/(sizeof(uniDumpFileName[0])));
        return(DumpModuleW(hProcess, ModuleBase, uniDumpFileName));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL DumpModuleW(HANDLE hProcess, LPVOID ModuleBase, wchar_t* szDumpFileName)
{

    int i;
    DWORD Dummy = NULL;
    MODULEINFO RemoteModuleInfo;
    ULONG_PTR EnumeratedModules[1024];

    if(EnumProcessModules(hProcess, (HMODULE*)EnumeratedModules, sizeof(EnumeratedModules), &Dummy))
    {
        for(i = 0; i < 512; i++)
        {
            if(EnumeratedModules[i] == (ULONG_PTR)ModuleBase)
            {
                GetModuleInformation(hProcess, (HMODULE)EnumeratedModules[i], &RemoteModuleInfo, sizeof MODULEINFO);
                return(DumpMemoryW(hProcess, (LPVOID)EnumeratedModules[i], RemoteModuleInfo.SizeOfImage, szDumpFileName));
            }
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL DumpModuleEx(DWORD ProcessId, LPVOID ModuleBase, char* szDumpFileName)
{

    wchar_t uniDumpFileName[MAX_PATH] = {};

    if(szDumpFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDumpFileName, lstrlenA(szDumpFileName)+1, uniDumpFileName, sizeof(uniDumpFileName)/(sizeof(uniDumpFileName[0])));
        return(DumpModuleExW(ProcessId, ModuleBase, uniDumpFileName));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL DumpModuleExW(DWORD ProcessId, LPVOID ModuleBase, wchar_t* szDumpFileName)
{

    HANDLE hProcess = 0;
    BOOL ReturnValue = false;

    hProcess = OpenProcess(PROCESS_VM_READ, FALSE, ProcessId);
    if(hProcess != INVALID_HANDLE_VALUE)
    {
        ReturnValue = DumpModuleW(hProcess, ModuleBase, szDumpFileName);
        EngineCloseHandle(hProcess);
        if(ReturnValue)
        {
            return true;
        }
    }

    return false;
}
