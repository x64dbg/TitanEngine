#include "stdafx.h"
#include "definitions.h"
#include "Global.Mapping.h"
#include "Global.Handle.h"

// Global.Mapping.functions:
bool MapFileEx(const char* szFileName, DWORD ReadOrWrite, LPHANDLE FileHandle, LPDWORD FileSize, LPHANDLE FileMap, LPVOID FileMapVA, DWORD SizeModifier)
{
    DWORD FileAccess = 0;
    DWORD FileMapType = 0;
    DWORD FileMapViewType = 0;

    if(ReadOrWrite == UE_ACCESS_READ)
    {
        FileAccess = GENERIC_READ;
        FileMapType = PAGE_READONLY;
        FileMapViewType = FILE_MAP_READ;
    }
    else if(ReadOrWrite == UE_ACCESS_WRITE)
    {
        FileAccess = GENERIC_WRITE;
        FileMapType = PAGE_READWRITE;
        FileMapViewType = FILE_MAP_WRITE;
    }
    else if(ReadOrWrite == UE_ACCESS_ALL)
    {
        FileAccess = GENERIC_READ + GENERIC_WRITE + GENERIC_EXECUTE;
        FileMapType = PAGE_EXECUTE_READWRITE;
        FileMapViewType = FILE_MAP_WRITE;
    }
    else
    {
        FileAccess = GENERIC_READ + GENERIC_WRITE + GENERIC_EXECUTE;
        FileMapType = PAGE_EXECUTE_READWRITE;
        FileMapViewType = FILE_MAP_ALL_ACCESS;
    }

    HANDLE hFile = CreateFileA(szFileName, FileAccess, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile != INVALID_HANDLE_VALUE)
    {
        *FileHandle = hFile;
        DWORD mfFileSize = GetFileSize(hFile, NULL);
        mfFileSize = mfFileSize + SizeModifier;
        *FileSize = mfFileSize;
        HANDLE mfFileMap = CreateFileMappingA(hFile, NULL, FileMapType, NULL, mfFileSize, NULL);
        if(mfFileMap != NULL)
        {
            *FileMap = mfFileMap;
            LPVOID mfFileMapVA = MapViewOfFile(mfFileMap, FileMapViewType, NULL, NULL, NULL);
            if(mfFileMapVA != NULL)
            {
                RtlMoveMemory(FileMapVA, &mfFileMapVA, sizeof ULONG_PTR);
                return true;
            }
        }
        RtlZeroMemory(FileMapVA, sizeof ULONG_PTR);
        *FileHandle = NULL;
        *FileSize = NULL;
        EngineCloseHandle(hFile);
    }
    else
    {
        RtlZeroMemory(FileMapVA, sizeof ULONG_PTR);
    }
    return false;
}

bool MapFileExW(const wchar_t* szFileName, DWORD ReadOrWrite, LPHANDLE FileHandle, LPDWORD FileSize, LPHANDLE FileMap, LPVOID FileMapVA, DWORD SizeModifier)
{
    DWORD FileAccess = 0;
    DWORD FileMapType = 0;
    DWORD FileMapViewType = 0;

    if(ReadOrWrite == UE_ACCESS_READ)
    {
        FileAccess = GENERIC_READ;
        FileMapType = PAGE_READONLY;
        FileMapViewType = FILE_MAP_READ;
    }
    else if(ReadOrWrite == UE_ACCESS_WRITE)
    {
        FileAccess = GENERIC_WRITE;
        FileMapType = PAGE_READWRITE;
        FileMapViewType = FILE_MAP_WRITE;
    }
    else if(ReadOrWrite == UE_ACCESS_ALL)
    {
        FileAccess = GENERIC_READ + GENERIC_WRITE + GENERIC_EXECUTE;
        FileMapType = PAGE_EXECUTE_READWRITE;
        FileMapViewType = FILE_MAP_WRITE;
    }
    else
    {
        FileAccess = GENERIC_READ + GENERIC_WRITE + GENERIC_EXECUTE;
        FileMapType = PAGE_EXECUTE_READWRITE;
        FileMapViewType = FILE_MAP_ALL_ACCESS;
    }

    HANDLE hFile = CreateFileW(szFileName, FileAccess, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile != INVALID_HANDLE_VALUE)
    {
        *FileHandle = hFile;
        DWORD mfFileSize = GetFileSize(hFile, NULL);
        mfFileSize = mfFileSize + SizeModifier;
        *FileSize = mfFileSize;
        HANDLE mfFileMap = CreateFileMappingA(hFile, NULL, FileMapType, NULL, mfFileSize, NULL);
        if(mfFileMap != NULL)
        {
            *FileMap = mfFileMap;
            LPVOID mfFileMapVA = MapViewOfFile(mfFileMap, FileMapViewType, NULL, NULL, NULL);
            if(mfFileMapVA != NULL)
            {
                RtlMoveMemory(FileMapVA, &mfFileMapVA, sizeof ULONG_PTR);
                return true;
            }
        }
        RtlZeroMemory(FileMapVA, sizeof ULONG_PTR);
        *FileHandle = NULL;
        *FileSize = NULL;
        EngineCloseHandle(hFile);
    }
    else
    {
        RtlZeroMemory(FileMapVA, sizeof ULONG_PTR);
    }
    return false;
}

void UnMapFileEx(HANDLE FileHandle, DWORD FileSize, HANDLE FileMap, ULONG_PTR FileMapVA)
{
    if(UnmapViewOfFile((void*)FileMapVA))
    {
        EngineCloseHandle(FileMap);
        SetFilePointer(FileHandle, FileSize, NULL, FILE_BEGIN);
        SetEndOfFile(FileHandle);
        EngineCloseHandle(FileHandle);
    }
}
