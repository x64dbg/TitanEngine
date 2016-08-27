#include "stdafx.h"
#include "definitions.h"
#include "Global.Mapping.h"
#include "Global.Engine.h"
#include "Global.Handle.h"

// TitanEngine.Resourcer.functions:
__declspec(dllexport) ULONG_PTR TITCALL ResourcerLoadFileForResourceUse(char* szFileName)
{
    return((ULONG_PTR)EngineSimulateNtLoader(szFileName));
}

__declspec(dllexport) ULONG_PTR TITCALL ResourcerLoadFileForResourceUseW(wchar_t* szFileName)
{
    return((ULONG_PTR)EngineSimulateNtLoaderW(szFileName));
}

__declspec(dllexport) bool TITCALL ResourcerFreeLoadedFile(LPVOID LoadedFileBase)
{
    if(VirtualFree(LoadedFileBase, NULL, MEM_RELEASE))
    {
        return true;
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL ResourcerExtractResourceFromFileEx(HMODULE hFile, char* szResourceType, char* szResourceName, char* szExtractedFileName)
{

    HRSRC hResource;
    HGLOBAL hResourceGlobal;
    DWORD ResourceSize;
    LPVOID ResourceData;
    DWORD NumberOfBytesWritten;
    HANDLE hOutFile;

    hResource = FindResourceA(hFile, (LPCSTR)szResourceName, (LPCSTR)szResourceType);
    if(hResource != NULL)
    {
        hResourceGlobal = LoadResource(hFile, hResource);
        if(hResourceGlobal != NULL)
        {
            ResourceSize = SizeofResource(hFile, hResource);
            ResourceData = LockResource(hResourceGlobal);
            EngineCreatePathForFile(szExtractedFileName);
            hOutFile = CreateFileA(szExtractedFileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if(hOutFile != INVALID_HANDLE_VALUE)
            {
                WriteFile(hOutFile, ResourceData, ResourceSize, &NumberOfBytesWritten, NULL);
                EngineCloseHandle(hOutFile);
            }
            else
            {
                return false;
            }
        }
        return true;
    }
    return false;
}

__declspec(dllexport) bool TITCALL ResourcerExtractResourceFromFile(char* szFileName, char* szResourceType, char* szResourceName, char* szExtractedFileName)
{
    HMODULE hFile = NULL;
    bool bReturn;

    hFile = LoadLibraryA(szFileName);
    if(hFile != NULL)
    {
        bReturn = ResourcerExtractResourceFromFileEx(hFile, szResourceType, szResourceName, szExtractedFileName);
        FreeLibrary(hFile);
        if(bReturn)
        {
            return true;
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL ResourcerExtractResourceFromFileW(wchar_t* szFileName, char* szResourceType, char* szResourceName, char* szExtractedFileName)
{
    HMODULE hFile = NULL;
    bool bReturn;

    hFile = LoadLibraryW(szFileName);
    if(hFile != NULL)
    {
        bReturn = ResourcerExtractResourceFromFileEx(hFile, szResourceType, szResourceName, szExtractedFileName);
        FreeLibrary(hFile);
        if(bReturn)
        {
            return true;
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL ResourcerFindResource(char* szFileName, char* szResourceType, DWORD ResourceType, char* szResourceName, DWORD ResourceName, DWORD ResourceLanguage, PULONG_PTR pResourceData, LPDWORD pResourceSize)
{

    wchar_t uniFileName[MAX_PATH] = {};
    wchar_t* PtrResourceType = NULL;
    wchar_t uniResourceType[MAX_PATH] = {};
    wchar_t* PtrResourceName = NULL;
    wchar_t uniResourceName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        if(szResourceName != NULL)
        {
            MultiByteToWideChar(CP_ACP, NULL, szResourceName, lstrlenA(szResourceName) + 1, uniResourceName, sizeof(uniResourceName) / (sizeof(uniResourceName[0])));
        }
        else
        {
            PtrResourceType = &uniResourceType[0];
        }
        if(szResourceType != NULL)
        {
            MultiByteToWideChar(CP_ACP, NULL, szResourceType, lstrlenA(szResourceType) + 1, uniResourceType, sizeof(uniResourceType) / (sizeof(uniResourceType[0])));
        }
        else
        {
            PtrResourceName = &uniResourceName[0];
        }
        return(ResourcerFindResourceW(uniFileName, PtrResourceType, ResourceType, PtrResourceName, ResourceName, ResourceLanguage, pResourceData, pResourceSize));
    }
    else
    {
        return false;
    }
}

__declspec(dllexport) bool TITCALL ResourcerFindResourceW(wchar_t* szFileName, wchar_t* szResourceType, DWORD ResourceType, wchar_t* szResourceName, DWORD ResourceName, DWORD ResourceLanguage, PULONG_PTR pResourceData, LPDWORD pResourceSize)
{

    bool ReturnValue;
    ULONG_PTR FileMapVA;
    HANDLE FileHandle;
    HANDLE FileMap;
    DWORD FileSize;

    if(MapFileExW(szFileName, UE_ACCESS_ALL, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        ReturnValue = ResourcerFindResourceEx(FileMapVA, FileSize, szResourceType, ResourceType, szResourceName, ResourceName, ResourceLanguage, pResourceData, pResourceSize);
        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
        if(ReturnValue)
        {
            return true;
        }
    }
    else
    {
        return false;
    }
    return false;
}

__declspec(dllexport) bool TITCALL ResourcerFindResourceEx(ULONG_PTR FileMapVA, DWORD FileSize, wchar_t* szResourceType, DWORD ResourceType, wchar_t* szResourceName, DWORD ResourceName, DWORD ResourceLanguage, PULONG_PTR pResourceData, LPDWORD pResourceSize)
{

    int i, j, n;
    wchar_t* uniResourceName;
    wchar_t* uniResourceType;
    PIMAGE_RESOURCE_DIRECTORY PEResource;
    PIMAGE_RESOURCE_DIRECTORY PEResourcePtr;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY PEResourceDir;
    PIMAGE_RESOURCE_DIRECTORY PESubResourcePtr1;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY PEResourceDir1;
    PIMAGE_RESOURCE_DIRECTORY PESubResourcePtr2;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY PEResourceDir2;
    PIMAGE_RESOURCE_DATA_ENTRY PEResourceItem;

    __try
    {
        if(FileMapVA != NULL && FileSize != NULL)
        {
            PEResource = (PIMAGE_RESOURCE_DIRECTORY)(ConvertVAtoFileOffsetEx(FileMapVA, FileSize, (ULONG_PTR)GetPE32DataFromMappedFile(FileMapVA, NULL, UE_IMAGEBASE), (ULONG_PTR)GetPE32DataFromMappedFile(FileMapVA, NULL, UE_RESOURCETABLEADDRESS), true, true));
            if(PEResource != NULL)
            {
                PEResourceDir = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((ULONG_PTR)PEResource + sizeof IMAGE_RESOURCE_DIRECTORY);
                i = PEResource->NumberOfIdEntries + PEResource->NumberOfNamedEntries;
                PEResourcePtr = PEResource;
                while(i > NULL)
                {
                    PESubResourcePtr1 = (PIMAGE_RESOURCE_DIRECTORY)((ULONG_PTR)PEResourcePtr + (PEResourceDir->OffsetToData ^ IMAGE_RESOURCE_DATA_IS_DIRECTORY));
                    PEResourceDir1 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((ULONG_PTR)PESubResourcePtr1 + sizeof IMAGE_RESOURCE_DIRECTORY);
                    j = PESubResourcePtr1->NumberOfIdEntries + PESubResourcePtr1->NumberOfNamedEntries;
                    uniResourceType = (wchar_t*)((ULONG_PTR)PEResourcePtr + PEResourceDir->NameOffset);
                    if(((bool)PEResourceDir->NameIsString == true && EngineCompareResourceString(uniResourceType, szResourceType) == true) || ((bool)PEResourceDir->NameIsString == false && PEResourceDir->Id == ResourceType))
                    {
                        while(j > NULL)
                        {
                            PESubResourcePtr2 = (PIMAGE_RESOURCE_DIRECTORY)((ULONG_PTR)PEResourcePtr + (PEResourceDir1->OffsetToData ^ IMAGE_RESOURCE_DATA_IS_DIRECTORY));
                            PEResourceDir2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((ULONG_PTR)PESubResourcePtr2 + sizeof IMAGE_RESOURCE_DIRECTORY);
                            n = PESubResourcePtr2->NumberOfIdEntries + PESubResourcePtr2->NumberOfNamedEntries;
                            uniResourceName = (wchar_t*)((ULONG_PTR)PEResourcePtr + PEResourceDir1->NameOffset);
                            if(((bool)PEResourceDir1->NameIsString == true && EngineCompareResourceString(uniResourceName, szResourceName) == true) || ((bool)PEResourceDir1->NameIsString == false && PEResourceDir1->Id == ResourceName))
                            {
                                while(n > NULL)
                                {
                                    PEResourceItem = (PIMAGE_RESOURCE_DATA_ENTRY)((ULONG_PTR)PEResourcePtr + PEResourceDir2->OffsetToData);
                                    if(ResourceLanguage == UE_RESOURCE_LANGUAGE_ANY || ResourceLanguage == PEResourceDir2->Id)
                                    {
                                        *pResourceData = PEResourceItem->OffsetToData;
                                        *pResourceSize = PEResourceItem->Size;
                                        return true;
                                    }
                                    PEResourceDir2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((ULONG_PTR)PEResourceDir2 + sizeof IMAGE_RESOURCE_DIRECTORY_ENTRY);
                                    n--;
                                }
                            }
                            else
                            {
                                PEResourceDir2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((ULONG_PTR)PEResourceDir2 + sizeof IMAGE_RESOURCE_DIRECTORY_ENTRY * n);
                            }
                            PEResourceDir1 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((ULONG_PTR)PEResourceDir1 + sizeof IMAGE_RESOURCE_DIRECTORY_ENTRY);
                            j--;
                        }
                    }
                    else
                    {
                        PEResourceDir1 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((ULONG_PTR)PEResourceDir1 + sizeof IMAGE_RESOURCE_DIRECTORY_ENTRY * j);
                    }
                    PEResourceDir = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((ULONG_PTR)PEResourceDir + sizeof IMAGE_RESOURCE_DIRECTORY_ENTRY);
                    i--;
                }
            }
        }
        else
        {
            return false;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {

    }
    return false;
}

__declspec(dllexport) void TITCALL ResourcerEnumerateResource(char* szFileName, void* CallBack)
{

    wchar_t uniFileName[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        ResourcerEnumerateResourceW(uniFileName, CallBack);
    }
}

__declspec(dllexport) void TITCALL ResourcerEnumerateResourceW(wchar_t* szFileName, void* CallBack)
{

    ULONG_PTR FileMapVA;
    HANDLE FileHandle;
    HANDLE FileMap;
    DWORD FileSize;

    if(MapFileExW(szFileName, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
    {
        ResourcerEnumerateResourceEx(FileMapVA, FileSize, CallBack);
        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
    }
}

__declspec(dllexport) void TITCALL ResourcerEnumerateResourceEx(ULONG_PTR FileMapVA, DWORD FileSize, void* CallBack)
{

    int i, j, n;
    wchar_t* pUniResourceName;
    wchar_t* pUniResourceType;
    PIMAGE_RESOURCE_DIRECTORY PEResource;
    PIMAGE_RESOURCE_DIRECTORY PEResourcePtr;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY PEResourceDir;
    PIMAGE_RESOURCE_DIRECTORY PESubResourcePtr1;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY PEResourceDir1;
    PIMAGE_RESOURCE_DIRECTORY PESubResourcePtr2;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY PEResourceDir2;
    PIMAGE_RESOURCE_DATA_ENTRY PEResourceItem;
    typedef bool(TITCALL * fResourceEnumerator)(wchar_t* szResourceType, DWORD ResourceType, wchar_t* szResourceName, DWORD ResourceName, DWORD ResourceLanguage, DWORD ResourceData, DWORD ResourceSize);
    fResourceEnumerator myResourceEnumerator = (fResourceEnumerator)CallBack;

    __try
    {
        if(CallBack != NULL)
        {
            if(FileMapVA != NULL && FileSize != NULL)
            {
                PEResource = (PIMAGE_RESOURCE_DIRECTORY)(ConvertVAtoFileOffsetEx(FileMapVA, FileSize, (ULONG_PTR)GetPE32DataFromMappedFile(FileMapVA, NULL, UE_IMAGEBASE), (ULONG_PTR)GetPE32DataFromMappedFile(FileMapVA, NULL, UE_RESOURCETABLEADDRESS), true, true));
                if(PEResource != NULL)
                {
                    PEResourceDir = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((ULONG_PTR)PEResource + sizeof IMAGE_RESOURCE_DIRECTORY);
                    i = PEResource->NumberOfIdEntries + PEResource->NumberOfNamedEntries;
                    PEResourcePtr = PEResource;
                    while(i > NULL)
                    {
                        PESubResourcePtr1 = (PIMAGE_RESOURCE_DIRECTORY)((ULONG_PTR)PEResourcePtr + (PEResourceDir->OffsetToData ^ IMAGE_RESOURCE_DATA_IS_DIRECTORY));
                        PEResourceDir1 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((ULONG_PTR)PESubResourcePtr1 + sizeof IMAGE_RESOURCE_DIRECTORY);
                        j = PESubResourcePtr1->NumberOfIdEntries + PESubResourcePtr1->NumberOfNamedEntries;
                        while(j > NULL)
                        {
                            PESubResourcePtr2 = (PIMAGE_RESOURCE_DIRECTORY)((ULONG_PTR)PEResourcePtr + (PEResourceDir1->OffsetToData ^ IMAGE_RESOURCE_DATA_IS_DIRECTORY));
                            PEResourceDir2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((ULONG_PTR)PESubResourcePtr2 + sizeof IMAGE_RESOURCE_DIRECTORY);
                            n = PESubResourcePtr2->NumberOfIdEntries + PESubResourcePtr2->NumberOfNamedEntries;
                            while(n > NULL)
                            {
                                wchar_t uniResourceName[MAX_PATH] = {};
                                wchar_t uniResourceType[MAX_PATH] = {};
                                PEResourceItem = (PIMAGE_RESOURCE_DATA_ENTRY)((ULONG_PTR)PEResourcePtr + PEResourceDir2->OffsetToData);
                                if(PEResourceDir->NameIsString)
                                {
                                    WORD resourceTypeLen = *(WORD*)((ULONG_PTR)PEResourcePtr + PEResourceDir->NameOffset);
                                    wcsncpy(uniResourceType, (wchar_t*)((ULONG_PTR)PEResourcePtr + PEResourceDir->NameOffset) + 1, resourceTypeLen);
                                    pUniResourceType = uniResourceType;
                                }
                                else
                                {
                                    pUniResourceType = NULL;
                                }
                                if(PEResourceDir1->NameIsString)
                                {
                                    WORD resourceNameLen = *(WORD*)((ULONG_PTR)PEResourcePtr + PEResourceDir1->NameOffset);
                                    wcsncpy(uniResourceName, (wchar_t*)((ULONG_PTR)PEResourcePtr + PEResourceDir1->NameOffset) + 1, resourceNameLen);
                                    pUniResourceName = uniResourceName;
                                }
                                else
                                {
                                    pUniResourceName = NULL;
                                }
                                if(!myResourceEnumerator(pUniResourceType, PEResourceDir->Id, pUniResourceName, PEResourceDir1->Id, PEResourceDir2->Id, PEResourceItem->OffsetToData, PEResourceItem->Size))
                                {
                                    return;
                                }
                                PEResourceDir2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((ULONG_PTR)PEResourceDir2 + sizeof IMAGE_RESOURCE_DIRECTORY_ENTRY);
                                n--;
                            }
                            PEResourceDir1 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((ULONG_PTR)PEResourceDir1 + sizeof IMAGE_RESOURCE_DIRECTORY_ENTRY);
                            j--;
                        }
                        PEResourceDir = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((ULONG_PTR)PEResourceDir + sizeof IMAGE_RESOURCE_DIRECTORY_ENTRY);
                        i--;
                    }
                }
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {

    }
}
