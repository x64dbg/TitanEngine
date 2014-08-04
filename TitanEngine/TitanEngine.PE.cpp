#include "stdafx.h"
#include "definitions.h"
#include "Global.Handle.h"
#include "Global.Engine.h"

__declspec(dllexport) bool TITCALL PastePEHeader(HANDLE hProcess, LPVOID ImageBase, char* szDebuggedFileName)
{

    wchar_t uniDebuggedFileName[MAX_PATH] = {};

    if(szDebuggedFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szDebuggedFileName, lstrlenA(szDebuggedFileName) + 1, uniDebuggedFileName, sizeof(uniDebuggedFileName) / (sizeof(uniDebuggedFileName[0])));
        return(PastePEHeaderW(hProcess, ImageBase, uniDebuggedFileName));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL PastePEHeaderW(HANDLE hProcess, LPVOID ImageBase, wchar_t* szDebuggedFileName)
{

    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    IMAGE_NT_HEADERS32 RemotePEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    IMAGE_NT_HEADERS64 RemotePEHeader64;
    ULONG_PTR ueNumberOfBytesRead = 0;
    DWORD uedNumberOfBytesRead = 0;
    DWORD FileSize = 0;
    DWORD PEHeaderSize = 0;
    ULONG_PTR dwImageBase = (ULONG_PTR)ImageBase;
    BOOL FileIs64 = false;
    HANDLE hFile = 0;
    SIZE_T CalculatedHeaderSize = NULL;
    DynBuf ueReadBuf;
    LPVOID ueReadBuffer = ueReadBuf.Allocate(0x2000);
    DWORD OldProtect = PAGE_READWRITE;

    hFile = CreateFileW(szDebuggedFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile != INVALID_HANDLE_VALUE)
    {
        FileSize = GetFileSize(hFile, NULL);
        if(FileSize < 0x1000)
        {
            if(!ReadFile(hFile, ueReadBuffer, FileSize, &uedNumberOfBytesRead, NULL))
                return false;
        }
        else
        {
            if(!ReadFile(hFile, ueReadBuffer, 0x1000, &uedNumberOfBytesRead, NULL))
                return false;
        }
        if(FileSize > 0x200)
        {
            DOSHeader = (PIMAGE_DOS_HEADER)ueReadBuffer;
            if(EngineValidateHeader((ULONG_PTR)ueReadBuffer, hProcess, ImageBase, DOSHeader, false))
            {
                PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
                PEHeader64 = (PIMAGE_NT_HEADERS64)((ULONG_PTR)DOSHeader + DOSHeader->e_lfanew);
                CalculatedHeaderSize = DOSHeader->e_lfanew + sizeof IMAGE_DOS_HEADER + sizeof IMAGE_NT_HEADERS64;
                if(CalculatedHeaderSize > 0x1000)
                {
                    SetFilePointer(hFile, NULL, NULL, FILE_BEGIN);
                    ueReadBuffer = ueReadBuf.Allocate(CalculatedHeaderSize);
                    if(!ReadFile(hFile, ueReadBuffer, (DWORD)CalculatedHeaderSize, &uedNumberOfBytesRead, NULL))
                    {
                        EngineCloseHandle(hFile);
                        return false;
                    }
                }
                if(PEHeader32->OptionalHeader.Magic == 0x10B)
                {
                    if(ReadProcessMemory(hProcess, (LPVOID)((ULONG_PTR)ImageBase + DOSHeader->e_lfanew), &RemotePEHeader32, sizeof IMAGE_NT_HEADERS32, &ueNumberOfBytesRead))
                    {
                        PEHeaderSize = PEHeader32->FileHeader.NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER + PEHeader32->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4;
                        FileIs64 = false;
                    }
                }
                else if(PEHeader32->OptionalHeader.Magic == 0x20B)
                {
                    if(ReadProcessMemory(hProcess, (LPVOID)((ULONG_PTR)ImageBase + DOSHeader->e_lfanew), &RemotePEHeader64, sizeof IMAGE_NT_HEADERS32, &ueNumberOfBytesRead))
                    {
                        PEHeaderSize = PEHeader64->FileHeader.NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER + PEHeader64->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4;
                        FileIs64 = true;
                    }
                }
                else
                {
                    EngineCloseHandle(hFile);
                    return false;
                }
                if(!FileIs64)
                {
                    PEHeader32->OptionalHeader.ImageBase = (DWORD)(dwImageBase);
                    if(VirtualProtectEx(hProcess, ImageBase, PEHeaderSize, PAGE_READWRITE, &OldProtect))
                    {
                        if(WriteProcessMemory(hProcess, ImageBase, ueReadBuffer, PEHeaderSize, &ueNumberOfBytesRead))
                        {
                            EngineCloseHandle(hFile);
                            VirtualProtectEx(hProcess, ImageBase, PEHeaderSize, OldProtect, &OldProtect);
                            return true;
                        }
                        else
                        {
                            EngineCloseHandle(hFile);
                            return false;
                        }
                    }
                    else
                    {
                        EngineCloseHandle(hFile);
                        return false;
                    }
                }
                else
                {
                    PEHeader64->OptionalHeader.ImageBase = dwImageBase;
                    if(VirtualProtectEx(hProcess, ImageBase, PEHeaderSize, PAGE_READWRITE, &OldProtect))
                    {
                        if(WriteProcessMemory(hProcess, ImageBase, ueReadBuffer, PEHeaderSize, &ueNumberOfBytesRead))
                        {
                            EngineCloseHandle(hFile);
                            VirtualProtectEx(hProcess, ImageBase, PEHeaderSize, OldProtect, &OldProtect);
                            return true;
                        }
                        else
                        {
                            EngineCloseHandle(hFile);
                            return false;
                        }
                    }
                    else
                    {
                        EngineCloseHandle(hFile);
                        return false;
                    }
                }
            }
            else
            {
                EngineCloseHandle(hFile);
                return false;
            }
        }
        else
        {
            EngineCloseHandle(hFile);
            return false;
        }
    }
    else
    {
        EngineCloseHandle(hFile);
        return false;
    }
    return false;
}
