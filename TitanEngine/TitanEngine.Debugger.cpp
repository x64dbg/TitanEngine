#include "stdafx.h"
#include "definitions.h"
#include "Global.Debugger.h"
#include "Global.Engine.h"
#include "Global.Handle.h"
#include "Global.Threader.h"

static wchar_t szBackupDebuggedFileName[512];

// TitanEngine.Debugger.functions:
__declspec(dllexport) void* TITCALL InitDebug(char* szFileName, char* szCommandLine, char* szCurrentFolder)
{
    wchar_t* PtrUniFileName = NULL;
    wchar_t uniFileName[MAX_PATH] = {};
    wchar_t* PtrUniCommandLine = NULL;
    wchar_t uniCommandLine[MAX_PATH] = {};
    wchar_t* PtrUniCurrentFolder = NULL;
    wchar_t uniCurrentFolder[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        MultiByteToWideChar(CP_ACP, NULL, szCommandLine, lstrlenA(szCommandLine) + 1, uniCommandLine, sizeof(uniCommandLine) / (sizeof(uniCommandLine[0])));
        MultiByteToWideChar(CP_ACP, NULL, szCurrentFolder, lstrlenA(szCurrentFolder) + 1, uniCurrentFolder, sizeof(uniCurrentFolder) / (sizeof(uniCurrentFolder[0])));
        if(szFileName != NULL)
        {
            PtrUniFileName = &uniFileName[0];
        }
        if(szCommandLine != NULL)
        {
            PtrUniCommandLine = &uniCommandLine[0];
        }
        if(szCurrentFolder != NULL)
        {
            PtrUniCurrentFolder = &uniCurrentFolder[0];
        }
        return(InitDebugW(PtrUniFileName, PtrUniCommandLine, PtrUniCurrentFolder));
    }
    else
    {
        return NULL;
    }
}
__declspec(dllexport) void* TITCALL InitDebugW(wchar_t* szFileName, wchar_t* szCommandLine, wchar_t* szCurrentFolder)
{
    int DebugConsoleFlag = NULL;

    if(DebugDebuggingDLL)
    {
        DebugConsoleFlag = CREATE_NO_WINDOW | CREATE_SUSPENDED;
    }
    else if(engineRemoveConsoleForDebugee)
    {
        DebugConsoleFlag = CREATE_NO_WINDOW;
    }

    if(engineEnableDebugPrivilege)
    {
        EngineSetDebugPrivilege(GetCurrentProcess(), true);
        DebugRemoveDebugPrivilege = true;
    }
    wchar_t* szFileNameCreateProcess;
    wchar_t* szCommandLineCreateProcess;
    std::wstring createWithCmdLine;
    if(szCommandLine == NULL || !lstrlenW(szCommandLine))
    {
        szCommandLineCreateProcess = 0;
        szFileNameCreateProcess = szFileName;
    }
    else
    {
        createWithCmdLine.push_back('\"');
        createWithCmdLine.append(szFileName);
        createWithCmdLine.push_back('\"');
        createWithCmdLine.push_back(' ');
        createWithCmdLine.append(szCommandLine);
        szCommandLineCreateProcess = (wchar_t*)createWithCmdLine.c_str();
        szFileNameCreateProcess = 0;
    }
    if(CreateProcessW(szFileNameCreateProcess, szCommandLineCreateProcess, NULL, NULL, false, DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | DebugConsoleFlag | CREATE_NEW_CONSOLE, NULL, szCurrentFolder, &dbgStartupInfo, &dbgProcessInformation))
    {
        if(engineEnableDebugPrivilege)
            EngineSetDebugPrivilege(GetCurrentProcess(), false);
        DebugAttachedToProcess = false;
        DebugAttachedProcessCallBack = NULL;
        return &dbgProcessInformation;
    }
    else
    {
        DWORD lastError = GetLastError();
        if(engineEnableDebugPrivilege)
        {
            EngineSetDebugPrivilege(GetCurrentProcess(), false);
            DebugRemoveDebugPrivilege = false;
        }
        memset(&dbgProcessInformation, 0, sizeof(PROCESS_INFORMATION));
        SetLastError(lastError);
        return 0;
    }
}

__declspec(dllexport) void* TITCALL InitNativeDebug(char* szFileName, char* szCommandLine, char* szCurrentFolder)
{
    wchar_t* PtrUniFileName = NULL;
    wchar_t uniFileName[MAX_PATH] = {};
    wchar_t* PtrUniCommandLine = NULL;
    wchar_t uniCommandLine[MAX_PATH] = {};
    wchar_t* PtrUniCurrentFolder = NULL;
    wchar_t uniCurrentFolder[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        MultiByteToWideChar(CP_ACP, NULL, szCommandLine, lstrlenA(szCommandLine) + 1, uniCommandLine, sizeof(uniCommandLine) / (sizeof(uniCommandLine[0])));
        MultiByteToWideChar(CP_ACP, NULL, szCurrentFolder, lstrlenA(szCurrentFolder) + 1, uniCurrentFolder, sizeof(uniCurrentFolder) / (sizeof(uniCurrentFolder[0])));
        if(szFileName != NULL)
        {
            PtrUniFileName = &uniFileName[0];
        }
        if(szCommandLine != NULL)
        {
            PtrUniCommandLine = &uniCommandLine[0];
        }
        if(szCurrentFolder != NULL)
        {
            PtrUniCurrentFolder = &uniCurrentFolder[0];
        }
        return(InitNativeDebugW(PtrUniFileName, PtrUniCommandLine, PtrUniCurrentFolder));
    }
    else
    {
        return NULL;
    }
}

__declspec(dllexport) void* TITCALL InitNativeDebugW(wchar_t* szFileName, wchar_t* szCommandLine, wchar_t* szCurrentFolder)
{
    typedef
    NTSTATUS
    (NTAPI *
     t_RtlCreateProcessParametersEx)(
         _Out_ PRTL_USER_PROCESS_PARAMETERS * pProcessParameters,
         _In_ PUNICODE_STRING ImagePathName,
         _In_opt_ PUNICODE_STRING DllPath,
         _In_opt_ PUNICODE_STRING CurrentDirectory,
         _In_opt_ PUNICODE_STRING CommandLine,
         _In_opt_ PVOID Environment,
         _In_opt_ PUNICODE_STRING WindowTitle,
         _In_opt_ PUNICODE_STRING DesktopInfo,
         _In_opt_ PUNICODE_STRING ShellInfo,
         _In_opt_ PUNICODE_STRING RuntimeData,
         _In_ ULONG Flags
     );

    typedef
    NTSTATUS
    (NTAPI *
     t_NtCreateUserProcess)(
         _Out_ PHANDLE ProcessHandle,
         _Out_ PHANDLE ThreadHandle,
         _In_ ACCESS_MASK ProcessDesiredAccess,
         _In_ ACCESS_MASK ThreadDesiredAccess,
         _In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
         _In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes,
         _In_ ULONG ProcessFlags,
         _In_ ULONG ThreadFlags,
         _In_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
         _Inout_ PPS_CREATE_INFO CreateInfo,
         _In_ PPS_ATTRIBUTE_LIST AttributeList
     );

    HMODULE Ntdll = GetModuleHandleW(L"ntdll.dll");
    t_RtlCreateProcessParametersEx fnRtlCreateProcessParametersEx =
        (t_RtlCreateProcessParametersEx)GetProcAddress(Ntdll, "RtlCreateProcessParametersEx");
    t_NtCreateUserProcess fnNtCreateUserProcess =
        (t_NtCreateUserProcess)GetProcAddress(Ntdll, "NtCreateUserProcess");

    // NtCreateUserProcess requires Vista or higher
    if(fnRtlCreateProcessParametersEx == NULL || fnNtCreateUserProcess == NULL)
    {
        RtlSetLastWin32Error(ERROR_NOT_SUPPORTED);
        return NULL;
    }

    RtlZeroMemory(&dbgProcessInformation, sizeof(PROCESS_INFORMATION));
    HANDLE ProcessHandle = NULL, ThreadHandle = NULL;
    UNICODE_STRING CommandLine = { 0 };
    PUNICODE_STRING PtrCurrentDirectory = NULL;

    // Convert the application path to its NT equivalent
    UNICODE_STRING ImagePath, NtImagePath;
    RtlInitUnicodeString(&ImagePath, szFileName);
    if(!RtlDosPathNameToNtPathName_U(ImagePath.Buffer,
                                     &NtImagePath,
                                     NULL,
                                     NULL))
    {
        RtlSetLastWin32Error(ERROR_PATH_NOT_FOUND);
        return NULL;
    }

    // Enable SE_DEBUG if needed
    const LONG SE_DEBUG_PRIVILEGE = 20L;
    BOOLEAN SeDebugWasEnabled = FALSE;
    NTSTATUS Status = STATUS_SUCCESS;
    if(engineEnableDebugPrivilege)
    {
        Status = RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE,
                                    TRUE,
                                    FALSE,
                                    &SeDebugWasEnabled);
        DebugRemoveDebugPrivilege = true;
    }
    if(!NT_SUCCESS(Status))
        goto finished;

    // Convert command line and directory to UNICODE_STRING if present
    SIZE_T ArgumentsLength = lstrlenW(szCommandLine);
    if(szCommandLine != NULL && ArgumentsLength > 0)
    {
        SIZE_T BufferSize = ImagePath.Length + ((ArgumentsLength + 4) * sizeof(wchar_t));
        CommandLine.Buffer = (PWSTR)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, BufferSize);
        CommandLine.MaximumLength = (USHORT)BufferSize;
        RtlAppendUnicodeToString(&CommandLine, L"\"");
        RtlAppendUnicodeStringToString(&CommandLine, &ImagePath);
        RtlAppendUnicodeToString(&CommandLine, L"\" ");
        RtlAppendUnicodeToString(&CommandLine, szCommandLine);
    }

    if(szCurrentFolder != NULL && lstrlenW(szCurrentFolder) > 0)
    {
        UNICODE_STRING WorkingDirectory;
        RtlInitUnicodeString(&WorkingDirectory, szCurrentFolder);
        PtrCurrentDirectory = &WorkingDirectory;
    }

    // Create the process parameter block
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
    PRTL_USER_PROCESS_PARAMETERS OwnParameters = NtCurrentPeb()->ProcessParameters;
    Status = fnRtlCreateProcessParametersEx(&ProcessParameters,
                                            &ImagePath,
                                            NULL,                        // Create a new DLL path
                                            PtrCurrentDirectory,
                                            &CommandLine,
                                            NULL,                        // If null, a new environment will be created
                                            &ImagePath,                  // Window title is the exe path - needed for console apps
                                            &OwnParameters->DesktopInfo, // Copy our desktop name
                                            NULL,
                                            NULL,
                                            RTL_USER_PROCESS_PARAMETERS_NORMALIZED);
    if(!NT_SUCCESS(Status))
        goto finished;

    // Clear the current directory because we're not inheriting handles
    ProcessParameters->CurrentDirectory.Handle = NULL;

    // Default to CREATE_NEW_CONSOLE behaviour
    ProcessParameters->ConsoleHandle = HANDLE_CREATE_NEW_CONSOLE;
    ProcessParameters->ShowWindowFlags = STARTF_USESHOWWINDOW | SW_SHOWDEFAULT;

    // Create a debug port object
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    HANDLE DebugPort = NULL;
    Status = NtCreateDebugObject(&DebugPort,
                                 DEBUG_ALL_ACCESS,
                                 &ObjectAttributes,
                                 DEBUG_KILL_ON_CLOSE);
    if(!NT_SUCCESS(Status))
    {
        RtlDestroyProcessParameters(ProcessParameters);
        goto finished;
    }

    // Store the debug port handle in our TEB. The kernel uses this field
    NtCurrentTeb()->DbgSsReserved[1] = DebugPort;

    // Initialize the PS_CREATE_INFO structure
    PS_CREATE_INFO CreateInfo;
    RtlZeroMemory(&CreateInfo, sizeof(CreateInfo));
    CreateInfo.Size = sizeof(CreateInfo);
    CreateInfo.State = PsCreateInitialState;
    CreateInfo.InitState.u1.s1.WriteOutputOnExit = TRUE;
    CreateInfo.InitState.u1.s1.DetectManifest = TRUE;
    CreateInfo.InitState.u1.s1.ProhibitedImageCharacteristics = 0; // Normally: IMAGE_FILE_DLL (disallow executing DLLs)
    CreateInfo.InitState.AdditionalFileAccess = FILE_READ_ATTRIBUTES | FILE_READ_DATA;

    // Initialize the PS_ATTRIBUTE_LIST that contains the process creation attributes
    const SIZE_T NumAttributes = 3;
    const SIZE_T AttributesSize = sizeof(SIZE_T) + NumAttributes * sizeof(PS_ATTRIBUTE);
    PPS_ATTRIBUTE_LIST AttributeList = reinterpret_cast<PPS_ATTRIBUTE_LIST>(
                                           RtlAllocateHeap(RtlProcessHeap(),
                                                   HEAP_ZERO_MEMORY, // Not optional
                                                   AttributesSize));
    AttributeList->TotalLength = AttributesSize;

    // In: NT style absolute image path. This is the only required attribute
    ULONG N = 0;
    AttributeList->Attributes[N].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    AttributeList->Attributes[N].Size = NtImagePath.Length;
    AttributeList->Attributes[N].Value = reinterpret_cast<ULONG_PTR>(NtImagePath.Buffer);

    // In: debug port
    N++;
    AttributeList->Attributes[N].Attribute = PS_ATTRIBUTE_DEBUG_PORT;
    AttributeList->Attributes[N].Size = sizeof(HANDLE);
    AttributeList->Attributes[N].Value = reinterpret_cast<ULONG_PTR>(DebugPort);

    // Out: client ID
    N++;
    CLIENT_ID Cid;
    PCLIENT_ID ClientId = &Cid;
    AttributeList->Attributes[N].Attribute = PS_ATTRIBUTE_CLIENT_ID;
    AttributeList->Attributes[N].Size = sizeof(CLIENT_ID);
    AttributeList->Attributes[N].Value = reinterpret_cast<ULONG_PTR>(ClientId);

    // Set process and thread flags
    ULONG NtProcessFlags = PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT; // Same as DEBUG_ONLY_THIS_PROCESS. DEBUG_PROCESS is implied by the debug port
    ULONG NtThreadFlags = THREAD_CREATE_FLAGS_CREATE_SUSPENDED; // Always set this, because we need to do some bookkeeping before resuming

    // Create the process
    Status = fnNtCreateUserProcess(&ProcessHandle,
                                   &ThreadHandle,
                                   MAXIMUM_ALLOWED,
                                   MAXIMUM_ALLOWED,
                                   NULL,
                                   NULL,
                                   NtProcessFlags,
                                   NtThreadFlags,
                                   ProcessParameters,
                                   &CreateInfo,
                                   AttributeList);

    RtlFreeHeap(RtlProcessHeap(), 0, AttributeList);
    RtlDestroyProcessParameters(ProcessParameters);

    if(!NT_SUCCESS(Status))
        goto finished;

    // Success. Convert what we got back to a PROCESS_INFORMATION structure
    dbgProcessInformation.hProcess = ProcessHandle;
    dbgProcessInformation.hThread = ThreadHandle;
    dbgProcessInformation.dwProcessId = HandleToULong(ClientId->UniqueProcess);
    dbgProcessInformation.dwThreadId = HandleToULong(ClientId->UniqueThread);

finished:
    RtlFreeHeap(RtlProcessHeap(), 0, NtImagePath.Buffer);

    if(CommandLine.Buffer != NULL)
        RtlFreeHeap(RtlProcessHeap(), 0, CommandLine.Buffer);

    if(ProcessHandle != NULL)
    {
        // Close the file and section handles we got back from the kernel
        NtClose(CreateInfo.SuccessState.FileHandle);
        NtClose(CreateInfo.SuccessState.SectionHandle);

        // If we failed, terminate the process
        if(!NT_SUCCESS(Status))
        {
            BOOLEAN CloseDebugPort = DebugPort != NULL &&
                                     ((NtThreadFlags & PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT) != 0);

            if(CloseDebugPort)
            {
                NtRemoveProcessDebug(ProcessHandle, DebugPort);
                NtClose(DebugPort);
                NtCurrentTeb()->DbgSsReserved[1] = NULL;
            }

            NtTerminateProcess(ProcessHandle, Status);
        }
        else
        {
            // Otherwise resume the process now
            NtResumeThread(ThreadHandle, NULL);
        }
    }

    // Release SE_DEBUG if we acquired it previously
    if(engineEnableDebugPrivilege && !SeDebugWasEnabled)
        RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE,
                           FALSE,
                           FALSE,
                           &SeDebugWasEnabled);

    if(!NT_SUCCESS(Status))
    {
        // Set error status
        ULONG Win32Error = RtlNtStatusToDosError(Status);
        RtlSetLastWin32Error(Win32Error);
        DebugRemoveDebugPrivilege = false;
        return NULL;
    }

    DebugAttachedToProcess = false;
    DebugAttachedProcessCallBack = NULL;

    return &dbgProcessInformation;
}

__declspec(dllexport) void* TITCALL InitDebugEx(char* szFileName, char* szCommandLine, char* szCurrentFolder, LPVOID EntryCallBack)
{
    DebugExeFileEntryPointCallBack = EntryCallBack;
    return(InitDebug(szFileName, szCommandLine, szCurrentFolder));
}

__declspec(dllexport) void* TITCALL InitDebugExW(wchar_t* szFileName, wchar_t* szCommandLine, wchar_t* szCurrentFolder, LPVOID EntryCallBack)
{
    DebugExeFileEntryPointCallBack = EntryCallBack;
    return(InitDebugW(szFileName, szCommandLine, szCurrentFolder));
}

__declspec(dllexport) void* TITCALL InitDLLDebug(char* szFileName, bool ReserveModuleBase, char* szCommandLine, char* szCurrentFolder, LPVOID EntryCallBack)
{

    wchar_t* PtrUniFileName = NULL;
    wchar_t uniFileName[MAX_PATH] = {};
    wchar_t* PtrUniCommandLine = NULL;
    wchar_t uniCommandLine[MAX_PATH] = {};
    wchar_t* PtrUniCurrentFolder = NULL;
    wchar_t uniCurrentFolder[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        MultiByteToWideChar(CP_ACP, NULL, szCommandLine, lstrlenA(szCommandLine) + 1, uniCommandLine, sizeof(uniCommandLine) / (sizeof(uniCommandLine[0])));
        MultiByteToWideChar(CP_ACP, NULL, szCurrentFolder, lstrlenA(szCurrentFolder) + 1, uniCurrentFolder, sizeof(uniCurrentFolder) / (sizeof(uniCurrentFolder[0])));
        if(szFileName != NULL)
        {
            PtrUniFileName = &uniFileName[0];
        }
        if(szCommandLine != NULL)
        {
            PtrUniCommandLine = &uniCommandLine[0];
        }
        if(szCurrentFolder != NULL)
        {
            PtrUniCurrentFolder = &uniCurrentFolder[0];
        }
        return(InitDLLDebugW(PtrUniFileName, ReserveModuleBase, PtrUniCommandLine, PtrUniCurrentFolder, EntryCallBack));
    }
    else
    {
        return NULL;
    }
}

static bool TryExtractDllLoader(bool failedBefore = false)
{
    wchar_t* szPath = wcsrchr(szDebuggerName, L'\\');
    if(szPath)
        szPath[1] = '\0';
    wchar_t DLLLoaderName[64] = L"";
#ifdef _WIN64
    wsprintfW(DLLLoaderName, L"DLLLoader64_%.4X.exe", GetTickCount() & 0xFFFF);
#else
    wsprintfW(DLLLoaderName, L"DLLLoader32_%.4X.exe", GetTickCount() & 0xFFFF);
#endif //_WIN64
    lstrcatW(szDebuggerName, DLLLoaderName);
#ifdef _WIN64
    if(EngineExtractResource("LOADERX64", szDebuggerName))
#else
    if(EngineExtractResource("LOADERX86", szDebuggerName))
#endif //_WIN64
        return true;
    return !failedBefore &&
           GetModuleFileNameW(engineHandle, szDebuggerName, _countof(szDebuggerName)) &&
           TryExtractDllLoader(true);
}

__declspec(dllexport) void* TITCALL InitDLLDebugW(wchar_t* szFileName, bool ReserveModuleBase, wchar_t* szCommandLine, wchar_t* szCurrentFolder, LPVOID EntryCallBack)
{
    memset(szDebuggerName, 0, sizeof(szDebuggerName));
    if(lstrlenW(szFileName) < sizeof(szDebuggerName))
    {
        memset(szBackupDebuggedFileName, 0, sizeof(szBackupDebuggedFileName));
        lstrcpyW(szBackupDebuggedFileName, szFileName);
        szFileName = &szBackupDebuggedFileName[0];
    }
    lstrcpyW(szDebuggerName, szFileName);
    if(TryExtractDllLoader())
    {
        DebugDebuggingDLL = true;
        int i = lstrlenW(szFileName);
        while(szFileName[i] != '\\' && i)
            i--;
        DebugDebuggingDLLBase = NULL;
        DebugDebuggingMainModuleBase = NULL;
        DebugDebuggingDLLFullFileName = szFileName;
        DebugDebuggingDLLFileName = &szFileName[i + 1];
        DebugModuleImageBase = (ULONG_PTR)GetPE32DataW(szFileName, NULL, UE_IMAGEBASE);
        DebugModuleEntryPoint = (ULONG_PTR)GetPE32DataW(szFileName, NULL, UE_OEP);
        DebugModuleEntryPointCallBack = EntryCallBack;
        DebugReserveModuleBase = 0;
        if(ReserveModuleBase)
            DebugReserveModuleBase = DebugModuleImageBase;
        PPROCESS_INFORMATION ReturnValue = (PPROCESS_INFORMATION)InitDebugW(szDebuggerName, szCommandLine, szCurrentFolder);
        wchar_t szName[256] = L"";
        swprintf(szName, 256, L"Local\\szLibraryName%X", (unsigned int)ReturnValue->dwProcessId);
        DebugDLLFileMapping = CreateFileMappingW(INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 512 * sizeof(wchar_t), szName);
        if(DebugDLLFileMapping)
        {
            wchar_t* szLibraryPathMapping = (wchar_t*)MapViewOfFile(DebugDLLFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 512 * sizeof(wchar_t));
            if(szLibraryPathMapping)
            {
                wcscpy(szLibraryPathMapping, DebugDebuggingDLLFullFileName);
                UnmapViewOfFile(szLibraryPathMapping);
            }
        }
        ResumeThread(ReturnValue->hThread);
        return ReturnValue;
    }
    return 0;
}

__declspec(dllexport) bool TITCALL StopDebug()
{
    if(dbgProcessInformation.hProcess != NULL)
    {
        TerminateThread(dbgProcessInformation.hThread, NULL);
        TerminateProcess(dbgProcessInformation.hProcess, NULL);
        Sleep(10); //allow thread switching
        return true;
    }
    return false;
}

__declspec(dllexport) bool TITCALL AttachDebugger(DWORD ProcessId, bool KillOnExit, LPVOID DebugInfo, LPVOID CallBack)
{
    typedef void(WINAPI * fDebugSetProcessKillOnExit)(bool KillExitingDebugee);
    fDebugSetProcessKillOnExit myDebugSetProcessKillOnExit;
    LPVOID funcDebugSetProcessKillOnExit = NULL;

    if(ProcessId != NULL && dbgProcessInformation.hProcess == NULL)
    {
        if(engineEnableDebugPrivilege)
        {
            EngineSetDebugPrivilege(GetCurrentProcess(), true);
            DebugRemoveDebugPrivilege = true;
        }
        if(DebugActiveProcess(ProcessId))
        {
            if(engineEnableDebugPrivilege)
                EngineSetDebugPrivilege(GetCurrentProcess(), false);
            if(KillOnExit)
            {
                funcDebugSetProcessKillOnExit = GetProcAddress(GetModuleHandleA("kernel32.dll"), "DebugSetProcessKillOnExit");
                if(funcDebugSetProcessKillOnExit != NULL)
                {
                    myDebugSetProcessKillOnExit = (fDebugSetProcessKillOnExit)(funcDebugSetProcessKillOnExit);
                    myDebugSetProcessKillOnExit(KillOnExit);
                }
            }
            DebugDebuggingDLL = false;
            DebugAttachedToProcess = true;
            DebugAttachedProcessCallBack = (ULONG_PTR)CallBack;
            engineAttachedProcessDebugInfo = DebugInfo;
            dbgProcessInformation.dwProcessId = ProcessId;
            DebugLoop();
            DebugAttachedToProcess = false;
            DebugAttachedProcessCallBack = NULL;
            return true;
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL DetachDebugger(DWORD ProcessId)
{
    typedef bool(WINAPI * fDebugActiveProcessStop)(DWORD dwProcessId);
    fDebugActiveProcessStop myDebugActiveProcessStop;
    LPVOID funcDebugActiveProcessStop = NULL;
    bool FuncReturn = false;

    RemoveAllBreakPoints(UE_OPTION_REMOVEALL);

    if(ProcessId != NULL)
    {
        funcDebugActiveProcessStop = GetProcAddress(GetModuleHandleA("kernel32.dll"), "DebugActiveProcessStop");
        if(funcDebugActiveProcessStop != NULL)
        {
            myDebugActiveProcessStop = (fDebugActiveProcessStop)(funcDebugActiveProcessStop);
            FuncReturn = myDebugActiveProcessStop(ProcessId);
            engineProcessIsNowDetached = true;
            Sleep(250);
        }
        DebugAttachedToProcess = false;
        if(FuncReturn)
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

__declspec(dllexport) bool TITCALL DetachDebuggerEx(DWORD ProcessId)
{
    ThreaderPauseProcess();
    int threadcount = (int)hListThread.size();
    for(int i = 0; i < threadcount; i++)
    {
        HANDLE hActiveThread = EngineOpenThread(THREAD_GETSETSUSPEND, false, hListThread.at(i).dwThreadId);
        CONTEXT myDBGContext;
        myDBGContext.ContextFlags = CONTEXT_CONTROL;
        GetThreadContext(hActiveThread, &myDBGContext);
        myDBGContext.EFlags &= ~UE_TRAP_FLAG;
        myDBGContext.EFlags &= ~UE_RESUME_FLAG;
        SetThreadContext(hActiveThread, &myDBGContext);
        EngineCloseHandle(hActiveThread);
    }
    ContinueDebugEvent(DBGEvent.dwProcessId, DBGEvent.dwThreadId, DBG_CONTINUE);
    ThreaderResumeProcess();
    return DetachDebugger(ProcessId);
}

__declspec(dllexport) void TITCALL AutoDebugEx(char* szFileName, bool ReserveModuleBase, char* szCommandLine, char* szCurrentFolder, DWORD TimeOut, LPVOID EntryCallBack)
{

    wchar_t* PtrUniFileName = NULL;
    wchar_t uniFileName[MAX_PATH] = {};
    wchar_t* PtrUniCommandLine = NULL;
    wchar_t uniCommandLine[MAX_PATH] = {};
    wchar_t* PtrUniCurrentFolder = NULL;
    wchar_t uniCurrentFolder[MAX_PATH] = {};

    if(szFileName != NULL)
    {
        MultiByteToWideChar(CP_ACP, NULL, szFileName, lstrlenA(szFileName) + 1, uniFileName, sizeof(uniFileName) / (sizeof(uniFileName[0])));
        MultiByteToWideChar(CP_ACP, NULL, szCommandLine, lstrlenA(szCommandLine) + 1, uniCommandLine, sizeof(uniCommandLine) / (sizeof(uniCommandLine[0])));
        MultiByteToWideChar(CP_ACP, NULL, szCurrentFolder, lstrlenA(szCurrentFolder) + 1, uniCurrentFolder, sizeof(uniCurrentFolder) / (sizeof(uniCurrentFolder[0])));
        if(szFileName != NULL)
        {
            PtrUniFileName = &uniFileName[0];
        }
        if(szCommandLine != NULL)
        {
            PtrUniCommandLine = &uniCommandLine[0];
        }
        if(szCurrentFolder != NULL)
        {
            PtrUniCurrentFolder = &uniCurrentFolder[0];
        }
        return(AutoDebugExW(PtrUniFileName, ReserveModuleBase, PtrUniCommandLine, PtrUniCurrentFolder, TimeOut, EntryCallBack));
    }
}

__declspec(dllexport) void TITCALL AutoDebugExW(wchar_t* szFileName, bool ReserveModuleBase, wchar_t* szCommandLine, wchar_t* szCurrentFolder, DWORD TimeOut, LPVOID EntryCallBack)
{
    DebugReserveModuleBase = 0;
    DWORD ThreadId;
    DWORD ExitCode = 0;
    HANDLE hSecondThread;
    bool FileIsDll = false;
#if !defined(_WIN64)
    PE32Struct PEStructure;
#else
    PE64Struct PEStructure;
#endif

    if(TimeOut == NULL)
    {
        TimeOut = INFINITE;
    }

    if(szFileName != NULL)
    {
        RtlZeroMemory(&expertDebug, sizeof ExpertDebug);
        expertDebug.ExpertModeActive = true;
        expertDebug.szFileName = szFileName;
        expertDebug.szCommandLine = szCommandLine;
        expertDebug.szCurrentFolder = szCurrentFolder;
        expertDebug.ReserveModuleBase = ReserveModuleBase;
        expertDebug.EntryCallBack = EntryCallBack;
        GetPE32DataExW(szFileName, (LPVOID)&PEStructure);
        if(PEStructure.Characteristics & 0x2000)
        {
            FileIsDll = true;
        }
        SetDebugLoopTimeOut(TimeOut);
        hSecondThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)DebugLoopInSecondThread, (LPVOID)FileIsDll, NULL, &ThreadId);
        WaitForSingleObject(hSecondThread, INFINITE);
        if(GetExitCodeThread(hSecondThread, &ExitCode))
        {
            if(ExitCode == -1)
            {
                ForceClose();
            }
        }
        RtlZeroMemory(&expertDebug, sizeof ExpertDebug);
        SetDebugLoopTimeOut(INFINITE);
    }
}
