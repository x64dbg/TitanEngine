#include "stdafx.h"
#include "definitions.h"
#include "Global.Handle.h"
#include "Global.Mapping.h"
#include "Global.Engine.h"

static char* szSharedOverlay = 0;
static wchar_t* szSharedOverlayW = 0;

__declspec(dllexport) bool TITCALL FindOverlay(char* szFileName, LPDWORD OverlayStart, LPDWORD OverlaySize)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return(FindOverlayW(uniFileName, OverlayStart, OverlaySize));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL FindOverlayW(wchar_t* szFileName, LPDWORD OverlayStart, LPDWORD OverlaySize)
{

    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_SECTION_HEADER PESections;
    DWORD SectionNumber = 0;
    DWORD SectionRawOffset = 0;
    DWORD SectionRawSize = 0;
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
                PESections = IMAGE_FIRST_SECTION(PEHeader32);
                SectionNumber = PEHeader32->FileHeader.NumberOfSections;
                __try
                {
                    while(SectionNumber > 0)
                    {
                        if(PESections->PointerToRawData >= SectionRawOffset)
                        {
                            if(PESections->SizeOfRawData != NULL || (SectionRawOffset != PESections->PointerToRawData))
                            {
                                SectionRawSize = PESections->SizeOfRawData;
                            }
                            SectionRawOffset = PESections->PointerToRawData;
                        }
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                        SectionNumber--;
                    }
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    if(SectionRawOffset + SectionRawSize < FileSize)
                    {
                        if(OverlayStart != NULL && OverlaySize != NULL)
                        {
                            *OverlayStart = (DWORD)(SectionRawOffset + SectionRawSize);
                            *OverlaySize = (DWORD)(FileSize - SectionRawOffset - SectionRawSize);
                        }
                        return true;
                    }
                    else
                    {
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
                PESections = IMAGE_FIRST_SECTION(PEHeader64);
                SectionNumber = PEHeader64->FileHeader.NumberOfSections;
                __try
                {
                    while(SectionNumber > 0)
                    {
                        if(PESections->PointerToRawData >= SectionRawOffset)
                        {
                            if(PESections->SizeOfRawData != NULL || (SectionRawOffset != PESections->PointerToRawData))
                            {
                                SectionRawSize = PESections->SizeOfRawData;
                            }
                            SectionRawOffset = PESections->PointerToRawData;
                        }
                        PESections = (PIMAGE_SECTION_HEADER)((ULONG_PTR)PESections + IMAGE_SIZEOF_SECTION_HEADER);
                        SectionNumber--;
                    }
                    UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                    if(SectionRawOffset + SectionRawSize < FileSize)
                    {
                        if(OverlayStart != NULL && OverlaySize != NULL)
                        {
                            *OverlayStart = (DWORD)(SectionRawOffset + SectionRawSize);
                            *OverlaySize = (DWORD)(FileSize - SectionRawOffset - SectionRawSize);
                        }
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
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
__declspec(dllexport) bool TITCALL ExtractOverlay(char* szFileName, char* szExtactedFileName)
{

    wchar_t uniFileName[MAX_PATH] = {};
    wchar_t uniExtactedFileName[MAX_PATH] = {};

    if(szFileName != NULL && szExtactedFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        MultiByteToWideChar(CP_ACP, NULL, szExtactedFileName, lstrlenA(szExtactedFileName) + 1, uniExtactedFileName, sizeof(uniExtactedFileName) / (sizeof(uniExtactedFileName[0])));
        return(ExtractOverlayW(uniFileName, uniExtactedFileName));
    }
    else
    {
        return false;
    }
}
__declspec(dllexport) bool TITCALL ExtractOverlayW(wchar_t* szFileName, wchar_t* szExtactedFileName)
{

    HANDLE hFile = 0;
    HANDLE hFileWrite = 0;
    BOOL Return = false;
    DWORD OverlayStart = 0;
    DWORD OverlaySize = 0;
    DWORD ueNumberOfBytesRead = 0;
    char ueReadBuffer[0x2000] = {0};

    Return = FindOverlayW(szFileName, &OverlayStart, &OverlaySize);
    if(Return)
    {
        hFile = CreateFileW(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if(hFile != INVALID_HANDLE_VALUE)
        {
            EngineCreatePathForFileW(szExtactedFileName);
            hFileWrite = CreateFileW(szExtactedFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if(hFileWrite != INVALID_HANDLE_VALUE)
            {
                SetFilePointer(hFile, OverlayStart, NULL, FILE_BEGIN);
                while(OverlaySize > 0)
                {
                    RtlZeroMemory(ueReadBuffer, sizeof(ueReadBuffer));

                    if(OverlaySize > 0x1000)
                    {
                        if(ReadFile(hFile, ueReadBuffer, 0x1000, &ueNumberOfBytesRead, NULL))
                        {
                            if(!WriteFile(hFileWrite, ueReadBuffer, 0x1000, &ueNumberOfBytesRead, NULL))
                                return false;
                        }
                        else
                        {
                            return false;
                        }

                        OverlaySize = OverlaySize - 0x1000;
                    }
                    else
                    {
                        if(ReadFile(hFile, ueReadBuffer, OverlaySize, &ueNumberOfBytesRead, NULL))
                        {
                            if(!WriteFile(hFileWrite, ueReadBuffer, OverlaySize, &ueNumberOfBytesRead, NULL))
                                return false;
                        }
                        else
                        {
                            return false;
                        }

                        OverlaySize = 0;
                    }
                }
                EngineCloseHandle(hFile);
                EngineCloseHandle(hFileWrite);
                return true;
            }
            else
            {
                EngineCloseHandle(hFile);
                return false;
            }
        }
    }
    return false;
}
__declspec(dllexport) bool TITCALL AddOverlay(char* szFileName, char* szOverlayFileName)
{

    wchar_t uniFileName[MAX_PATH] = {};
    wchar_t uniOverlayFileName[MAX_PATH] = {};

    if(szFileName != NULL && szOverlayFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        MultiByteToWideChar(CP_ACP, NULL, szOverlayFileName, lstrlenA(szOverlayFileName) + 1, uniOverlayFileName, sizeof(uniOverlayFileName) / (sizeof(uniOverlayFileName[0])));
        return(AddOverlayW(uniFileName, uniOverlayFileName));
    }
    else
    {
        return false;
    }
}
__declspec(dllexport) bool TITCALL AddOverlayW(wchar_t* szFileName, wchar_t* szOverlayFileName)
{

    HANDLE hFile = 0;
    HANDLE hFileRead = 0;
    DWORD FileSize = 0;
    DWORD OverlaySize = 0;
    ULONG_PTR ueNumberOfBytesRead = 0;
    DWORD uedNumberOfBytesRead = 0;
    char ueReadBuffer[0x2000] = {0};

    hFile = CreateFileW(szFileName, GENERIC_READ + GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile != INVALID_HANDLE_VALUE)
    {
        hFileRead = CreateFileW(szOverlayFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if(hFileRead != INVALID_HANDLE_VALUE)
        {
            FileSize = GetFileSize(hFile, NULL);
            OverlaySize = GetFileSize(hFileRead, NULL);
            SetFilePointer(hFile, FileSize, NULL, FILE_BEGIN);
            while(OverlaySize > 0)
            {
                RtlZeroMemory(ueReadBuffer, sizeof(ueReadBuffer));

                if(OverlaySize > 0x1000)
                {
                    if(ReadFile(hFileRead, ueReadBuffer, 0x1000, &uedNumberOfBytesRead, NULL))
                    {
                        if(!WriteFile(hFile, ueReadBuffer, 0x1000, &uedNumberOfBytesRead, NULL))
                            return false;
                    }
                    else
                    {
                        return false;
                    }

                    OverlaySize = OverlaySize - 0x1000;
                }
                else
                {
                    if(ReadFile(hFileRead, ueReadBuffer, OverlaySize, &uedNumberOfBytesRead, NULL))
                    {
                        if(!WriteFile(hFile, ueReadBuffer, OverlaySize, &uedNumberOfBytesRead, NULL))
                            return false;
                    }
                    else
                    {
                        return false;
                    }

                    OverlaySize = 0;
                }
            }
            EngineCloseHandle(hFile);
            EngineCloseHandle(hFileRead);
            return true;
        }
        else
        {
            EngineCloseHandle(hFile);
            return false;
        }
    }
    return false;
}
__declspec(dllexport) bool TITCALL CopyOverlay(char* szInFileName, char* szOutFileName)
{

    wchar_t uniInFileName[MAX_PATH] = {};
    wchar_t uniOutFileName[MAX_PATH] = {};

    if(szInFileName != NULL && szOutFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szInFileName, lstrlenA(szInFileName) + 1, uniInFileName, sizeof(uniInFileName) / (sizeof(uniInFileName[0])));
        MultiByteToWideChar(CP_ACP, NULL, szOutFileName, lstrlenA(szOutFileName) + 1, uniOutFileName, sizeof(uniOutFileName) / (sizeof(uniOutFileName[0])));
        return(CopyOverlayW(uniInFileName, uniOutFileName));
    }
    else
    {
        return false;
    }
}
__declspec(dllexport) bool TITCALL CopyOverlayW(wchar_t* szInFileName, wchar_t* szOutFileName)
{

    wchar_t szTempName[MAX_PATH] = {};
    wchar_t szTempFolder[MAX_PATH] = {};

    if(GetTempPathW(MAX_PATH, szTempFolder) < MAX_PATH)
    {
        if(GetTempFileNameW(szTempFolder, L"OverlayTemp", GetTickCount() + 101, szTempName))
        {
            if(ExtractOverlayW(szInFileName, szTempName))
            {
                AddOverlayW(szOutFileName, szTempName);
                DeleteFileW(szTempName);
                return true;
            }
        }
    }
    return false;
}
__declspec(dllexport) bool TITCALL RemoveOverlay(char* szFileName)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        return(RemoveOverlayW(uniFileName));
    }
    else
    {
        return false;
    }
}
__declspec(dllexport) bool TITCALL RemoveOverlayW(wchar_t* szFileName)
{

    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    DWORD OverlayStart = 0;
    DWORD OverlaySize = 0;

    if(FindOverlayW(szFileName, &OverlayStart, &OverlaySize))
    {
        if(MapFileExW(szFileName, UE_ACCESS_ALL, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
        {
            FileSize = FileSize - OverlaySize;
            UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            return true;
        }
    }
    return false;
}

__declspec(dllexport) void TITCALL SetSharedOverlay(char* szFileName)
{
    szSharedOverlay = szFileName;
}
__declspec(dllexport) void TITCALL SetSharedOverlayW(wchar_t* szFileName)
{
    szSharedOverlayW = szFileName;
}
__declspec(dllexport) char* TITCALL GetSharedOverlay()
{
    return(szSharedOverlay);
}
__declspec(dllexport) wchar_t* TITCALL GetSharedOverlayW()
{
    return(szSharedOverlayW);
}
