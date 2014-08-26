#include "stdafx.h"
#include "definitions.h"
#include "Global.Garbage.h"
#include "Global.Handle.h"
#include "Global.Engine.h"


wchar_t engineSzEngineGarbageFolder[MAX_PATH] = L"";

// Global.Garbage.functions:
bool CreateGarbageItem(void* outGargabeItem, int MaxGargabeStringSize)
{
    wchar_t szGarbageItem[512];
    wchar_t szGargabeItemBuff[128];

    RtlZeroMemory(&szGarbageItem, sizeof szGarbageItem);
    RtlZeroMemory(&szGargabeItemBuff, sizeof szGargabeItemBuff);
    srand((unsigned int)time(NULL));
    wsprintfW(szGargabeItemBuff, L"Junk-%08x\\", (rand() % 128 + 1) * (rand() % 128 + 1) + (rand() % 1024 + 1));
    lstrcpyW(szGarbageItem, engineSzEngineGarbageFolder);
    lstrcatW(szGarbageItem, szGargabeItemBuff);
    EngineCreatePathForFileW(szGarbageItem);

    if(lstrlenW(szGarbageItem) * 2 >= MaxGargabeStringSize)
    {
        RtlMoveMemory(outGargabeItem, &szGarbageItem, MaxGargabeStringSize);
        return false;
    }
    else
    {
        RtlMoveMemory(outGargabeItem, &szGarbageItem, lstrlenW(szGarbageItem) * 2);
        return true;
    }
}

bool RemoveGarbageItem(wchar_t* szGarbageItem, bool RemoveFolder)
{

    wchar_t szFindSearchString[MAX_PATH];
    wchar_t szFoundFile[MAX_PATH];
    WIN32_FIND_DATAW FindData;
    bool QueryNextFile = true;
    HANDLE CurrentFile;

    if(szGarbageItem != NULL)
    {
        lstrcpyW(szFindSearchString, szGarbageItem);
        if(szFindSearchString[0] != NULL)
        {
            lstrcatW(szFindSearchString, L"\\*.*");
            CurrentFile = FindFirstFileW(szFindSearchString, &FindData);
            while(QueryNextFile == true && CurrentFile != INVALID_HANDLE_VALUE)
            {
                RtlZeroMemory(&szFoundFile, sizeof szFoundFile);
                lstrcpyW(szFoundFile, szGarbageItem);
                lstrcatW(szFoundFile, FindData.cFileName);
                if(FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                {
                    if(FindData.cFileName[0] != 0x2E)
                    {
                        lstrcatW(szFoundFile, L"\\");
                        RemoveGarbageItem(szFoundFile, true);
                    }
                }
                else
                {
                    if(!DeleteFileW(szFoundFile))
                    {
                        if(HandlerCloseAllLockHandlesW(szFoundFile, false, true))
                        {
                            DeleteFileW(szFoundFile);
                        }
                    }
                }
                if(!FindNextFileW(CurrentFile, &FindData))
                {
                    QueryNextFile = false;
                }
            }
            FindClose(CurrentFile);
            if(RemoveFolder)
            {
                if(lstrlenW(engineSzEngineGarbageFolder) < lstrlenW(szGarbageItem))
                {
                    if(!RemoveDirectoryW(szGarbageItem))
                    {
                        if(HandlerCloseAllLockHandlesW(szGarbageItem, true, true))
                        {
                            RemoveDirectoryW(szGarbageItem);
                        }
                    }
                }
            }
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

bool FillGarbageItem(wchar_t* szGarbageItem, wchar_t* szFileName, void* outGargabeItem, int MaxGargabeStringSize)
{
    if(!szGarbageItem || !szFileName || !outGargabeItem)
        return false;
    wchar_t szCopyFileName[512];
    wchar_t szGargabeItemBuff[128];

    lstrcpyW(szCopyFileName, szGarbageItem);
    if(szFileName != NULL)
    {
        lstrcatW(szCopyFileName, EngineExtractFileNameW(szFileName));
    }
    else
    {
        srand((unsigned int)time(NULL));
        wsprintfW(szGargabeItemBuff, L"Junk-Data-%08x.bin", (rand() % 128 + 1) * (rand() % 128 + 1) + (rand() % 1024 + 1));
        lstrcatW(szCopyFileName, szGargabeItemBuff);
    }
    if(lstrlenW(szCopyFileName) >= MaxGargabeStringSize)
    {
        RtlMoveMemory(outGargabeItem, &szCopyFileName, MaxGargabeStringSize);
        if(szFileName != NULL)
        {
            CopyFileW(szFileName, szCopyFileName, false);
        }
    }
    else
    {
        RtlMoveMemory(outGargabeItem, &szCopyFileName, lstrlenW(szCopyFileName) * 2);
        if(szFileName != NULL)
        {
            CopyFileW(szFileName, szCopyFileName, false);
        }
    }
    return true;
}

void EmptyGarbage()
{
    RemoveGarbageItem(engineSzEngineGarbageFolder, false);
}
