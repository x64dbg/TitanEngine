#include "stdafx.h"
#include "definitions.h"
#include "Global.Handle.h"
#include "Global.Engine.h"

bool NtQuerySysHandleInfo(DynBuf & buf)
{
    ULONG RequiredSize = NULL;

    buf.Allocate(sizeof(SYSTEM_HANDLE_INFORMATION));

    NtQuerySystemInformation(SystemHandleInformation, buf.GetPtr(), (ULONG)buf.Size(), &RequiredSize);

    buf.Allocate(RequiredSize + sizeof(SYSTEM_HANDLE_INFORMATION));

    return (NtQuerySystemInformation(SystemHandleInformation, buf.GetPtr(), (ULONG)buf.Size(), &RequiredSize) >= 0);
}


// TitanEngine.Handler.functions:
__declspec(dllexport) long TITCALL HandlerGetActiveHandleCount(DWORD ProcessId)
{
    int HandleCount = 0;

    DynBuf hinfo;
    if(!NtQuerySysHandleInfo(hinfo))
        return 0;

    LPVOID QuerySystemBuffer = hinfo.GetPtr();

    PSYSTEM_HANDLE_INFORMATION HandleInfo = (PSYSTEM_HANDLE_INFORMATION)QuerySystemBuffer;
    PSYSTEM_HANDLE_TABLE_ENTRY_INFO pHandle = HandleInfo->Handles;

    for(ULONG i = 0; i < HandleInfo->NumberOfHandles; i++)
    {
        if((DWORD)pHandle->UniqueProcessId == ProcessId)
        {
            HandleCount++;
        }

        pHandle++;
    }

    return HandleCount;
}
__declspec(dllexport) bool TITCALL HandlerIsHandleOpen(DWORD ProcessId, HANDLE hHandle)
{
    bool HandleActive = false;

    DynBuf hinfo;
    if(!NtQuerySysHandleInfo(hinfo))
        return false;

    LPVOID QuerySystemBuffer = hinfo.GetPtr();

    PSYSTEM_HANDLE_INFORMATION HandleInfo = (PSYSTEM_HANDLE_INFORMATION)QuerySystemBuffer;
    PSYSTEM_HANDLE_TABLE_ENTRY_INFO pHandle = HandleInfo->Handles;


    for(ULONG i = 0; i < HandleInfo->NumberOfHandles; i++)
    {
        if((DWORD)pHandle->UniqueProcessId == ProcessId && (HANDLE)pHandle->HandleValue == hHandle)
        {
            HandleActive = true;
            break;
        }

        pHandle++;
    }

    return HandleActive;
}
__declspec(dllexport) void* TITCALL HandlerGetHandleNameW(HANDLE hProcess, DWORD ProcessId, HANDLE hHandle, bool TranslateName)
{
    bool NameFound = false;
    HANDLE myHandle = NULL;
    ULONG RequiredSize = NULL;
    char ObjectNameInfo[0x1000] = {0};
    POBJECT_NAME_INFORMATION pObjectNameInfo = (POBJECT_NAME_INFORMATION)ObjectNameInfo;
    LPVOID HandleFullName = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);

    DynBuf hinfo;
    if(!NtQuerySysHandleInfo(hinfo))
    {
        VirtualFree(HandleFullName, NULL, MEM_RELEASE);
        return 0;
    }
    LPVOID QuerySystemBuffer = hinfo.GetPtr();

    PSYSTEM_HANDLE_INFORMATION HandleInfo = (PSYSTEM_HANDLE_INFORMATION)QuerySystemBuffer;
    PSYSTEM_HANDLE_TABLE_ENTRY_INFO pHandle = HandleInfo->Handles;

    for(ULONG i = 0; i < HandleInfo->NumberOfHandles; i++)
    {
        if((DWORD)pHandle->UniqueProcessId == ProcessId && (HANDLE)pHandle->HandleValue == hHandle)
        {
            if(pHandle->GrantedAccess != 0x0012019F) //Filter, because this GrantedAccess type can cause deadlocks!
            {
                if(DuplicateHandle(hProcess, hHandle, GetCurrentProcess(), &myHandle, NULL, FALSE, DUPLICATE_SAME_ACCESS))
                {
                    NtQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, sizeof(ObjectNameInfo), &RequiredSize);
                    ZeroMemory(HandleFullName, 0x1000);
                    if(pObjectNameInfo->Name.Length != NULL)
                    {
                        wcscpy((wchar_t*)HandleFullName, pObjectNameInfo->Name.Buffer);
                        NameFound = true;
                        if(TranslateName)
                        {
                            LPVOID tmpHandleFullName = TranslateNativeNameW((wchar_t*)HandleFullName);
                            if(tmpHandleFullName != NULL)
                            {
                                VirtualFree(HandleFullName, NULL, MEM_RELEASE);
                                HandleFullName = tmpHandleFullName;
                            }
                        }
                    }
                    EngineCloseHandle(myHandle);
                    break;
                }
            }
        }

        pHandle++;
    }

    if(!NameFound)
    {
        VirtualFree(HandleFullName, NULL, MEM_RELEASE);
        return(NULL);
    }
    else
    {
        return(HandleFullName);
    }
}
__declspec(dllexport) void* TITCALL HandlerGetHandleName(HANDLE hProcess, DWORD ProcessId, HANDLE hHandle, bool TranslateName)
{
    wchar_t* name = (wchar_t*)HandlerGetHandleNameW(hProcess, ProcessId, hHandle, TranslateName);

    if(name)
    {
        LPVOID HandleFullName = VirtualAlloc(NULL, wcslen(name) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        WideCharToMultiByte(CP_ACP, NULL, name, -1, (LPSTR)HandleFullName, (int)wcslen(name) + 1, NULL, NULL);
        VirtualFree(name, NULL, MEM_RELEASE);

        return HandleFullName;
    }

    return 0;
}
__declspec(dllexport) long TITCALL HandlerEnumerateOpenHandles(DWORD ProcessId, LPVOID HandleBuffer, DWORD MaxHandleCount)
{

    HANDLE myHandle = NULL;
    ULONG RequiredSize = NULL;
    ULONG TotalHandleCount = NULL;
    unsigned int HandleCount = NULL;
    PNTDLL_QUERY_HANDLE_INFO HandleInfo;

    DynBuf hinfo;
    if(!NtQuerySysHandleInfo(hinfo))
        return 0;
    LPVOID QuerySystemBuffer = hinfo.GetPtr();

    RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
    QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
    HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
    while(TotalHandleCount > NULL)
    {
        if(HandleInfo->ProcessId == ProcessId && HandleCount < MaxHandleCount)
        {
            myHandle = (HANDLE)HandleInfo->hHandle;
            RtlMoveMemory(HandleBuffer, &myHandle, sizeof HANDLE);
            HandleBuffer = (LPVOID)((ULONG_PTR)HandleBuffer + sizeof HANDLE);
            HandleCount++;
        }
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
        TotalHandleCount--;
    }
    return(HandleCount);
}
__declspec(dllexport) ULONG_PTR TITCALL HandlerGetHandleDetails(HANDLE hProcess, DWORD ProcessId, HANDLE hHandle, DWORD InformationReturn)
{

    HANDLE myHandle = NULL;
    ULONG RequiredSize = NULL;
    ULONG TotalHandleCount = NULL;
    PNTDLL_QUERY_HANDLE_INFO HandleInfo;
    OBJECT_BASIC_INFORMATION ObjectBasicInfo;
    char HandleFullData[0x1000] = {0};
    LPVOID HandleNameData = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    POBJECT_TYPE_INFORMATION pObjectTypeInfo = (POBJECT_TYPE_INFORMATION)HandleFullData;
    bool DontFreeStringMemory = false;
    ULONG_PTR ReturnData = NULL;


    DynBuf hinfo;
    if(!NtQuerySysHandleInfo(hinfo))
        return 0;
    LPVOID QuerySystemBuffer = hinfo.GetPtr();

    RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
    QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
    HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
    while(TotalHandleCount > NULL)
    {
        if(HandleInfo->ProcessId == ProcessId && (HANDLE)HandleInfo->hHandle == hHandle)
        {
            if(DuplicateHandle(hProcess, hHandle, GetCurrentProcess(), &myHandle, NULL, false, DUPLICATE_SAME_ACCESS))
            {
                RtlZeroMemory(&ObjectBasicInfo, sizeof OBJECT_BASIC_INFORMATION);
                NtQueryObject(myHandle, ObjectBasicInformation, &ObjectBasicInfo, sizeof OBJECT_BASIC_INFORMATION, &RequiredSize);
                if(InformationReturn == UE_OPTION_HANDLER_RETURN_HANDLECOUNT)
                {
                    ReturnData = (ULONG_PTR)ObjectBasicInfo.HandleCount;
                }
                else if(InformationReturn == UE_OPTION_HANDLER_RETURN_ACCESS)
                {
                    ReturnData = (ULONG_PTR)HandleInfo->GrantedAccess;
                }
                else if(InformationReturn == UE_OPTION_HANDLER_RETURN_FLAGS)
                {
                    ReturnData = (ULONG_PTR)HandleInfo->Flags;
                }
                else if(InformationReturn == UE_OPTION_HANDLER_RETURN_TYPENAME)
                {
                    //if(!(HandleInfo->GrantedAccess & SYNCHRONIZE) || ((HandleInfo->GrantedAccess & SYNCHRONIZE) && ((WORD)HandleInfo->GrantedAccess != 0x19F9))){// && (WORD)HandleInfo->GrantedAccess != 0x89))){
                    if(HandleInfo->GrantedAccess != 0x0012019F)
                    {
                        RtlZeroMemory(HandleFullData, sizeof(HandleFullData));
                        NtQueryObject(myHandle, ObjectTypeInformation, HandleFullData, 8, &RequiredSize);
                        NtQueryObject(myHandle, ObjectTypeInformation, HandleFullData, RequiredSize, &RequiredSize);
                        RtlZeroMemory(HandleNameData, 0x1000);
                        if(pObjectTypeInfo->TypeName.Length != NULL)
                        {
                            WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectTypeInfo->TypeName.Buffer, -1, (LPSTR)HandleNameData, 0x1000, NULL, NULL);
                            ReturnData = (ULONG_PTR)HandleNameData;
                            DontFreeStringMemory = true;
                        }
                    }
                }
                else if(InformationReturn == UE_OPTION_HANDLER_RETURN_TYPENAME_UNICODE)
                {
                    //if(!(HandleInfo->GrantedAccess & SYNCHRONIZE) || ((HandleInfo->GrantedAccess & SYNCHRONIZE) && ((WORD)HandleInfo->GrantedAccess != 0x19F9))){// && (WORD)HandleInfo->GrantedAccess != 0x89))){
                    if(HandleInfo->GrantedAccess != 0x0012019F)
                    {
                        RtlZeroMemory(HandleFullData, sizeof(HandleFullData));
                        NtQueryObject(myHandle, ObjectTypeInformation, HandleFullData, 8, &RequiredSize);
                        NtQueryObject(myHandle, ObjectTypeInformation, HandleFullData, RequiredSize, &RequiredSize);
                        RtlZeroMemory(HandleNameData, 0x1000);
                        if(pObjectTypeInfo->TypeName.Length != NULL)
                        {
                            //WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectTypeInfo->TypeName.Buffer, -1, (LPSTR)HandleNameData, 0x1000, NULL, NULL);
                            lstrcpyW((wchar_t*)HandleNameData, (wchar_t*)pObjectTypeInfo->TypeName.Buffer);
                            ReturnData = (ULONG_PTR)HandleNameData;
                            DontFreeStringMemory = true;
                        }
                    }
                }
                EngineCloseHandle(myHandle);
                break;
            }
        }
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
        TotalHandleCount--;
    }
    if(!DontFreeStringMemory)
    {
        VirtualFree(HandleNameData, NULL, MEM_RELEASE);
    }
    return(ReturnData);
}
__declspec(dllexport) bool TITCALL HandlerCloseRemoteHandle(HANDLE hProcess, HANDLE hHandle)
{

    HANDLE myHandle;

    if(hProcess != NULL)
    {
        DuplicateHandle(hProcess, hHandle, GetCurrentProcess(), &myHandle, NULL, false, DUPLICATE_CLOSE_SOURCE);
        EngineCloseHandle(myHandle);
    }
    return false;
}
__declspec(dllexport) long TITCALL HandlerEnumerateLockHandles(char* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated, LPVOID HandleDataBuffer, DWORD MaxHandleCount)
{

    wchar_t uniFileOrFolderName[MAX_PATH] = {};

    if(szFileOrFolderName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileOrFolderName, lstrlenA(szFileOrFolderName) + 1, uniFileOrFolderName, sizeof(uniFileOrFolderName) / (sizeof(uniFileOrFolderName[0])));
        return(HandlerEnumerateLockHandlesW(uniFileOrFolderName, NameIsFolder, NameIsTranslated, HandleDataBuffer, MaxHandleCount));
    }
    else
    {
        return(NULL);
    }
}
__declspec(dllexport) long TITCALL HandlerEnumerateLockHandlesW(wchar_t* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated, LPVOID HandleDataBuffer, DWORD MaxHandleCount)
{

    int FoundHandles = NULL;
    HANDLE hProcess = NULL;
    HANDLE myHandle = NULL;
    HANDLE CopyHandle = NULL;
    ULONG RequiredSize = NULL;
    ULONG TotalHandleCount = NULL;
    DWORD LastProcessId = NULL;

    PNTDLL_QUERY_HANDLE_INFO HandleInfo;
    OBJECT_BASIC_INFORMATION ObjectBasicInfo;
    char ObjectNameInfo[0x2000] = {0};
    POBJECT_NAME_INFORMATION pObjectNameInfo = (POBJECT_NAME_INFORMATION)ObjectNameInfo;
    char HandleFullNameB[0x1000] = {0};
    LPVOID HandleFullName = HandleFullNameB;
    int LenFileOrFolderName = lstrlenW(szFileOrFolderName);
    LPVOID tmpHandleFullName = NULL;

    DynBuf hinfo;
    if(!NtQuerySysHandleInfo(hinfo))
        return 0;
    LPVOID QuerySystemBuffer = hinfo.GetPtr();


    RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
    QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
    HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
    while(TotalHandleCount > NULL)
    {
        if(LastProcessId != HandleInfo->ProcessId)
        {
            if(hProcess != NULL)
            {
                EngineCloseHandle(hProcess);
            }
            hProcess = EngineOpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, false, HandleInfo->ProcessId);
            LastProcessId = HandleInfo->ProcessId;
        }
        if(hProcess != NULL)
        {
            //if(!(HandleInfo->GrantedAccess & SYNCHRONIZE) || ((HandleInfo->GrantedAccess & SYNCHRONIZE) && ((WORD)HandleInfo->GrantedAccess != 0x19F9))){// && (WORD)HandleInfo->GrantedAccess != 0x89))){
            if(HandleInfo->GrantedAccess != 0x0012019F)
            {
                if(DuplicateHandle(hProcess, (HANDLE)HandleInfo->hHandle, GetCurrentProcess(), &myHandle, NULL, false, DUPLICATE_SAME_ACCESS))
                {
                    RtlZeroMemory(&ObjectBasicInfo, sizeof OBJECT_BASIC_INFORMATION);
                    NtQueryObject(myHandle, ObjectBasicInformation, &ObjectBasicInfo, sizeof OBJECT_BASIC_INFORMATION, &RequiredSize);
                    NtQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, 8, &RequiredSize);
                    NtQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, RequiredSize, &RequiredSize);
                    RtlZeroMemory(HandleFullName, 0x1000);
                    if(pObjectNameInfo->Name.Length != NULL)
                    {
                        //WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectNameInfo->Name.Buffer, -1, (LPSTR)HandleFullName, 0x1000, NULL, NULL);
                        lstrcpyW((wchar_t*)HandleFullName, (wchar_t*)pObjectNameInfo->Name.Buffer);
                        if(NameIsTranslated)
                        {
                            tmpHandleFullName = TranslateNativeNameW((wchar_t*)HandleFullName);
                            if(tmpHandleFullName != NULL)
                            {
                                HandleFullName = tmpHandleFullName;
                            }
                        }
                        if(NameIsFolder)
                        {
                            if(lstrlenW((LPCWSTR)HandleFullName) > LenFileOrFolderName)
                            {
                                RtlZeroMemory((LPVOID)((ULONG_PTR)HandleFullName + LenFileOrFolderName * 2), 2);
                            }
                        }
                        if(lstrcmpiW((LPCWSTR)HandleFullName, szFileOrFolderName) == NULL && MaxHandleCount > NULL)
                        {
                            RtlMoveMemory(HandleDataBuffer, &HandleInfo->ProcessId, sizeof ULONG);
                            HandleDataBuffer = (LPVOID)((ULONG_PTR)HandleDataBuffer + sizeof ULONG);
                            CopyHandle = (HANDLE)HandleInfo->hHandle;
                            RtlMoveMemory(HandleDataBuffer, &CopyHandle, sizeof HANDLE);
                            HandleDataBuffer = (LPVOID)((ULONG_PTR)HandleDataBuffer + sizeof HANDLE);
                            FoundHandles++;
                            MaxHandleCount--;
                        }
                    }
                    EngineCloseHandle(myHandle);
                }
            }
        }
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
        TotalHandleCount--;
    }

    return(FoundHandles);
}
__declspec(dllexport) bool TITCALL HandlerCloseAllLockHandles(char* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated)
{

    wchar_t uniFileOrFolderName[MAX_PATH] = {};

    if(szFileOrFolderName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileOrFolderName, lstrlenA(szFileOrFolderName) + 1, uniFileOrFolderName, sizeof(uniFileOrFolderName) / (sizeof(uniFileOrFolderName[0])));
        return(HandlerCloseAllLockHandlesW(uniFileOrFolderName, NameIsFolder, NameIsTranslated));
    }
    else
    {
        return false;
    }
}
__declspec(dllexport) bool TITCALL HandlerCloseAllLockHandlesW(wchar_t* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated)
{

    bool AllHandled = true;
    HANDLE hProcess = NULL;
    HANDLE myHandle = NULL;
    HANDLE CopyHandle = NULL;
    ULONG RequiredSize = NULL;
    ULONG TotalHandleCount = NULL;
    DWORD LastProcessId = NULL;
    PNTDLL_QUERY_HANDLE_INFO HandleInfo;
    OBJECT_BASIC_INFORMATION ObjectBasicInfo;
    char ObjectNameInfo[0x2000] = {0};
    POBJECT_NAME_INFORMATION pObjectNameInfo = (POBJECT_NAME_INFORMATION)ObjectNameInfo;
    char HandleFullNameB[0x1000] = {0};
    LPVOID HandleFullName = HandleFullNameB;
    int LenFileOrFolderName = lstrlenW(szFileOrFolderName);
    LPVOID tmpHandleFullName = NULL;


    DynBuf hinfo;
    if(!NtQuerySysHandleInfo(hinfo))
        return 0;
    LPVOID QuerySystemBuffer = hinfo.GetPtr();


    RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
    QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
    HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
    while(TotalHandleCount > NULL)
    {
        if(LastProcessId != HandleInfo->ProcessId)
        {
            if(hProcess != NULL)
            {
                EngineCloseHandle(hProcess);
            }
            hProcess = EngineOpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, false, HandleInfo->ProcessId);
            LastProcessId = HandleInfo->ProcessId;
        }
        if(hProcess != NULL)
        {
            //if(!(HandleInfo->GrantedAccess & SYNCHRONIZE) || ((HandleInfo->GrantedAccess & SYNCHRONIZE) && ((WORD)HandleInfo->GrantedAccess != 0x19F9))){// && (WORD)HandleInfo->GrantedAccess != 0x89))){
            if(HandleInfo->GrantedAccess != 0x0012019F)
            {
                if(DuplicateHandle(hProcess, (HANDLE)HandleInfo->hHandle, GetCurrentProcess(), &myHandle, NULL, false, DUPLICATE_SAME_ACCESS))
                {
                    RtlZeroMemory(&ObjectBasicInfo, sizeof OBJECT_BASIC_INFORMATION);
                    NtQueryObject(myHandle, ObjectBasicInformation, &ObjectBasicInfo, sizeof OBJECT_BASIC_INFORMATION, &RequiredSize);
                    NtQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, 8, &RequiredSize);
                    NtQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, RequiredSize, &RequiredSize);
                    RtlZeroMemory(HandleFullName, 0x1000);
                    if(pObjectNameInfo->Name.Length != NULL)
                    {
                        //WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectNameInfo->Name.Buffer, -1, (LPSTR)HandleFullName, 0x1000, NULL, NULL);
                        lstrcpyW((wchar_t*)HandleFullName, (wchar_t*)pObjectNameInfo->Name.Buffer);
                        if(NameIsTranslated)
                        {
                            tmpHandleFullName = TranslateNativeNameW((wchar_t*)HandleFullName);
                            if(tmpHandleFullName != NULL)
                            {
                                HandleFullName = tmpHandleFullName;
                            }
                        }
                        if(NameIsFolder)
                        {
                            if(lstrlenW((LPCWSTR)HandleFullName) > LenFileOrFolderName)
                            {
                                RtlZeroMemory((LPVOID)((ULONG_PTR)HandleFullName + LenFileOrFolderName * 2), 2);
                            }
                        }
                        if(lstrcmpiW((LPCWSTR)HandleFullName, szFileOrFolderName) == NULL)
                        {
                            if(!HandlerCloseRemoteHandle(hProcess, (HANDLE)HandleInfo->hHandle))
                            {
                                AllHandled = false;
                            }
                        }
                    }
                    EngineCloseHandle(myHandle);
                }
            }
        }
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
        TotalHandleCount--;
    }

    return AllHandled;
}
__declspec(dllexport) bool TITCALL HandlerIsFileLocked(char* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated)
{

    wchar_t uniFileOrFolderName[MAX_PATH] = {};

    if(szFileOrFolderName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileOrFolderName, lstrlenA(szFileOrFolderName) + 1, uniFileOrFolderName, sizeof(uniFileOrFolderName) / (sizeof(uniFileOrFolderName[0])));
        return(HandlerIsFileLockedW(uniFileOrFolderName, NameIsFolder, NameIsTranslated));
    }
    else
    {
        return false;
    }
}
__declspec(dllexport) bool TITCALL HandlerIsFileLockedW(wchar_t* szFileOrFolderName, bool NameIsFolder, bool NameIsTranslated)
{

    HANDLE hProcess = NULL;
    HANDLE myHandle = NULL;
    HANDLE CopyHandle = NULL;
    ULONG RequiredSize = NULL;
    ULONG TotalHandleCount = NULL;
    DWORD LastProcessId = NULL;

    PNTDLL_QUERY_HANDLE_INFO HandleInfo;
    OBJECT_BASIC_INFORMATION ObjectBasicInfo;
    char ObjectNameInfo[0x2000] = {0};
    POBJECT_NAME_INFORMATION pObjectNameInfo = (POBJECT_NAME_INFORMATION)ObjectNameInfo;
    char HandleFullNameB[0x1000] = {0};
    LPVOID HandleFullName = HandleFullNameB;
    int LenFileOrFolderName = lstrlenW(szFileOrFolderName);
    LPVOID tmpHandleFullName = NULL;

    DynBuf hinfo;
    if(!NtQuerySysHandleInfo(hinfo))
        return 0;
    LPVOID QuerySystemBuffer = hinfo.GetPtr();


    RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
    QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
    HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
    while(TotalHandleCount > NULL)
    {
        if(LastProcessId != HandleInfo->ProcessId)
        {
            if(hProcess != NULL)
            {
                EngineCloseHandle(hProcess);
            }
            hProcess = EngineOpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, false, HandleInfo->ProcessId);
            LastProcessId = HandleInfo->ProcessId;
        }
        if(hProcess != NULL)
        {
            //if(!(HandleInfo->GrantedAccess & SYNCHRONIZE) || ((HandleInfo->GrantedAccess & SYNCHRONIZE) && ((WORD)HandleInfo->GrantedAccess != 0x19F9))){// && (WORD)HandleInfo->GrantedAccess != 0x89))){
            if(HandleInfo->GrantedAccess != 0x0012019F)
            {
                if(DuplicateHandle(hProcess, (HANDLE)HandleInfo->hHandle, GetCurrentProcess(), &myHandle, NULL, false, DUPLICATE_SAME_ACCESS))
                {
                    RtlZeroMemory(&ObjectBasicInfo, sizeof OBJECT_BASIC_INFORMATION);
                    NtQueryObject(myHandle, ObjectBasicInformation, &ObjectBasicInfo, sizeof OBJECT_BASIC_INFORMATION, &RequiredSize);
                    NtQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, 8, &RequiredSize);
                    NtQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, RequiredSize, &RequiredSize);
                    RtlZeroMemory(HandleFullName, 0x1000);
                    if(pObjectNameInfo->Name.Length != NULL)
                    {
                        //WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectNameInfo->Name.Buffer, -1, (LPSTR)HandleFullName, 0x1000, NULL, NULL);
                        lstrcpyW((wchar_t*)HandleFullName, (wchar_t*)pObjectNameInfo->Name.Buffer);
                        if(NameIsTranslated)
                        {
                            tmpHandleFullName = TranslateNativeNameW((wchar_t*)HandleFullName);
                            if(tmpHandleFullName != NULL)
                            {
                                HandleFullName = tmpHandleFullName;
                            }
                        }
                        if(NameIsFolder)
                        {
                            if(lstrlenW((LPCWSTR)HandleFullName) > LenFileOrFolderName)
                            {
                                RtlZeroMemory((LPVOID)((ULONG_PTR)HandleFullName + LenFileOrFolderName * 2), 2);
                            }
                        }
                        if(lstrcmpiW((LPCWSTR)HandleFullName, szFileOrFolderName) == NULL)
                        {
                            EngineCloseHandle(myHandle);
                            return true;
                        }
                    }
                    EngineCloseHandle(myHandle);
                }
            }
        }
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
        TotalHandleCount--;
    }
    return false;

}
// TitanEngine.Handler[Mutex].functions:
__declspec(dllexport) long TITCALL HandlerEnumerateOpenMutexes(HANDLE hProcess, DWORD ProcessId, LPVOID HandleBuffer, DWORD MaxHandleCount)
{

    HANDLE myHandle = NULL;
    HANDLE copyHandle = NULL;
    ULONG RequiredSize = NULL;
    ULONG TotalHandleCount = NULL;
    unsigned int HandleCount = NULL;

    PNTDLL_QUERY_HANDLE_INFO HandleInfo;
    char HandleFullData[0x1000] = {0};
    char HandleNameDataB[0x1000] = {0};
    LPVOID HandleNameData = HandleNameDataB;
    POBJECT_TYPE_INFORMATION pObjectTypeInfo = (POBJECT_TYPE_INFORMATION)HandleFullData;

    DynBuf hinfo;
    if(!NtQuerySysHandleInfo(hinfo))
        return 0;
    LPVOID QuerySystemBuffer = hinfo.GetPtr();

    RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
    QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
    HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
    while(TotalHandleCount > NULL)
    {
        if(HandleInfo->ProcessId == ProcessId && HandleCount < MaxHandleCount)
        {
            //if(!(HandleInfo->GrantedAccess & SYNCHRONIZE) || ((HandleInfo->GrantedAccess & SYNCHRONIZE) && ((WORD)HandleInfo->GrantedAccess != 0x19F9))){// && (WORD)HandleInfo->GrantedAccess != 0x89))){
            if(HandleInfo->GrantedAccess != 0x0012019F)
            {
                if(DuplicateHandle(hProcess, (HANDLE)HandleInfo->hHandle, GetCurrentProcess(), &myHandle, NULL, false, DUPLICATE_SAME_ACCESS))
                {
                    RtlZeroMemory(HandleFullData, sizeof(HandleFullData));
                    NtQueryObject(myHandle, ObjectTypeInformation, HandleFullData, 8, &RequiredSize);
                    NtQueryObject(myHandle, ObjectTypeInformation, HandleFullData, RequiredSize, &RequiredSize);
                    RtlZeroMemory(HandleNameData, 0x1000);
                    if(pObjectTypeInfo->TypeName.Length != NULL)
                    {
                        WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectTypeInfo->TypeName.Buffer, -1, (LPSTR)HandleNameData, 0x1000, NULL, NULL);
                        if(lstrcmpiA((LPCSTR)HandleNameData, "Mutant") == NULL)
                        {
                            copyHandle = (HANDLE)HandleInfo->hHandle;
                            RtlMoveMemory(HandleBuffer, &copyHandle, sizeof HANDLE);
                            HandleBuffer = (LPVOID)((ULONG_PTR)HandleBuffer + sizeof HANDLE);
                            HandleCount++;
                        }
                    }
                    EngineCloseHandle(myHandle);
                }
            }
        }
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
        TotalHandleCount--;
    }
    return(HandleCount);

}
__declspec(dllexport) ULONG_PTR TITCALL HandlerGetOpenMutexHandle(HANDLE hProcess, DWORD ProcessId, char* szMutexString)
{

    wchar_t uniMutexString[MAX_PATH] = {};

    if(szMutexString != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szMutexString, lstrlenA(szMutexString) + 1, uniMutexString, sizeof(uniMutexString) / (sizeof(uniMutexString[0])));
        return((ULONG_PTR)HandlerGetOpenMutexHandleW(hProcess, ProcessId, uniMutexString));
    }
    else
    {
        return(NULL);
    }
}
__declspec(dllexport) ULONG_PTR TITCALL HandlerGetOpenMutexHandleW(HANDLE hProcess, DWORD ProcessId, wchar_t* szMutexString)
{
    if(!szMutexString || lstrlenW(szMutexString) >= 512)
        return 0;
    int i;
    HANDLE myHandle;
    char HandleBuffer[0x1000] = {0};
    LPVOID cHandleBuffer = HandleBuffer;
    int OpenHandleCount = HandlerEnumerateOpenMutexes(hProcess, ProcessId, HandleBuffer, 0x1000 / sizeof HANDLE);
    wchar_t RealMutexName[512] = L"\\BaseNamedObjects\\";
    wchar_t* HandleName;

    if(OpenHandleCount > NULL)
    {
        lstrcatW(RealMutexName, szMutexString);
        for(i = 0; i < OpenHandleCount; i++)
        {
            RtlMoveMemory(&myHandle, cHandleBuffer, sizeof HANDLE);
            HandleName = (wchar_t*)HandlerGetHandleNameW(hProcess, ProcessId, myHandle, true);
            if(HandleName != NULL)
            {
                if(lstrcmpiW(HandleName, RealMutexName) == NULL)
                {
                    return((ULONG_PTR)myHandle);
                }
            }
            cHandleBuffer = (LPVOID)((ULONG_PTR)cHandleBuffer + sizeof HANDLE);
        }
    }
    return(NULL);
}
__declspec(dllexport) long TITCALL HandlerGetProcessIdWhichCreatedMutex(char* szMutexString)
{
    wchar_t uniMutexString[MAX_PATH] = {0};

    if(szMutexString != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szMutexString, -1, uniMutexString, _countof(uniMutexString));
        return(HandlerGetProcessIdWhichCreatedMutexW(uniMutexString));
    }
    else
    {
        return(NULL);
    }
}
__declspec(dllexport) long TITCALL HandlerGetProcessIdWhichCreatedMutexW(wchar_t* szMutexString)
{
    if(!szMutexString || wcslen(szMutexString) >= 450)
        return 0;
    HANDLE hProcess = NULL;
    DWORD ReturnData = NULL;
    HANDLE myHandle = NULL;
    ULONG RequiredSize = NULL;
    DWORD LastProcessId = NULL;
    ULONG TotalHandleCount = NULL;
    PNTDLL_QUERY_HANDLE_INFO HandleInfo;
    char HandleFullData[0x1000] = {0};
    char HandleNameData[0x1000] = {0};
    POBJECT_TYPE_INFORMATION pObjectTypeInfo = (POBJECT_TYPE_INFORMATION)HandleFullData;
    char ObjectNameInfo[0x2000] = {0};
    POBJECT_NAME_INFORMATION pObjectNameInfo = (POBJECT_NAME_INFORMATION)ObjectNameInfo;
    wchar_t RealMutexName[512] = L"\\BaseNamedObjects\\";


    lstrcatW(RealMutexName, szMutexString);

    DynBuf hinfo;
    if(!NtQuerySysHandleInfo(hinfo))
        return 0;
    LPVOID QuerySystemBuffer = hinfo.GetPtr();

    RtlMoveMemory(&TotalHandleCount, QuerySystemBuffer, sizeof ULONG);
    QuerySystemBuffer = (LPVOID)((ULONG_PTR)QuerySystemBuffer + 4);
    HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)QuerySystemBuffer;
    while(TotalHandleCount > NULL)
    {
        if(LastProcessId != HandleInfo->ProcessId)
        {
            if(hProcess != NULL)
            {
                EngineCloseHandle(hProcess);
            }
            hProcess = EngineOpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, FALSE, HandleInfo->ProcessId);
            LastProcessId = HandleInfo->ProcessId;
        }
        if(hProcess != NULL)
        {
            //if(!(HandleInfo->GrantedAccess & SYNCHRONIZE) || ((HandleInfo->GrantedAccess & SYNCHRONIZE) && ((WORD)HandleInfo->GrantedAccess != 0x19F9))){// && (WORD)HandleInfo->GrantedAccess != 0x89))){
            if(HandleInfo->GrantedAccess != 0x0012019F)
            {
                if(DuplicateHandle(hProcess, (HANDLE)HandleInfo->hHandle, GetCurrentProcess(), &myHandle, NULL, false, DUPLICATE_SAME_ACCESS))
                {
                    RtlZeroMemory(HandleFullData, sizeof(HandleFullData));
                    NtQueryObject(myHandle, ObjectTypeInformation, HandleFullData, 8, &RequiredSize);
                    NtQueryObject(myHandle, ObjectTypeInformation, HandleFullData, RequiredSize, &RequiredSize);
                    RtlZeroMemory(HandleNameData, sizeof(HandleNameData));
                    if(pObjectTypeInfo->TypeName.Length != NULL)
                    {
                        //WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectTypeInfo->TypeName.Buffer, -1, (LPSTR)HandleNameData, 0x1000, NULL, NULL);
                        lstrcpyW((wchar_t*)HandleNameData, (wchar_t*)pObjectNameInfo->Name.Buffer);
                        if(lstrcmpiW((LPCWSTR)HandleNameData, L"Mutant") == NULL)
                        {
                            NtQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, 8, &RequiredSize);
                            NtQueryObject(myHandle, ObjectNameInformation, ObjectNameInfo, RequiredSize, &RequiredSize);
                            RtlZeroMemory(HandleNameData, sizeof(HandleNameData));
                            if(pObjectNameInfo->Name.Length != NULL)
                            {
                                //WideCharToMultiByte(CP_ACP, NULL, (LPCWSTR)pObjectNameInfo->Name.Buffer, -1, (LPSTR)HandleNameData, 0x1000, NULL, NULL);
                                lstrcpyW((wchar_t*)HandleNameData, (wchar_t*)pObjectNameInfo->Name.Buffer);
                                if(lstrcmpiW((LPCWSTR)HandleNameData, RealMutexName) == NULL)
                                {
                                    ReturnData = HandleInfo->ProcessId;
                                    break;
                                }
                            }
                        }
                    }
                    EngineCloseHandle(myHandle);
                }
            }
        }
        HandleInfo = (PNTDLL_QUERY_HANDLE_INFO)((ULONG_PTR)HandleInfo + sizeof NTDLL_QUERY_HANDLE_INFO);
        TotalHandleCount--;
    }
    return(ReturnData);

}
