#include "stdafx.h"
#include "definitions.h"
#include "Global.Debugger.h"
#include "Global.Handle.h"
#include "Global.Engine.h"
#include "Global.Engine.Extension.h"
#include "Global.Breakpoints.h"
#include "Global.Threader.h"
#include "Global.Librarian.h"
#include "Global.TLS.h"
#include <psapi.h>

#define UE_MODULEx86 0x2000;
#define UE_MODULEx64 0x2000;

static DWORD engineWaitForDebugEventTimeOut = INFINITE;

__declspec(dllexport) void TITCALL DebugLoop()
{
    int j = NULL;
    int k = NULL;
    bool FirstBPX = true;
    bool ResetBPX = false;
    bool BreakDBG = false;
    bool ResetHwBPX = false;
    bool ResetMemBPX = false;
    bool CompareResult = false;
    bool SecondChance = false;
    ULONG_PTR CmpValue1 = NULL;
    ULONG_PTR CmpValue2 = NULL;
    bool hListProcessFirst = true;
    bool hListThreadFirst = true;
    bool hListLibraryFirst = true;
    PPROCESS_ITEM_DATA hListProcessPtr = NULL;
    PTHREAD_ITEM_DATA hListThreadPtr = NULL;
    PLIBRARY_ITEM_DATAW hListLibraryPtr = NULL;
    PLIBRARY_ITEM_DATAW hLoadedLibData = NULL;
    PLIBRARY_BREAK_DATA ptrLibrarianData = NULL;
    typedef void(TITCALL *fCustomBreakPoint)(void);
    typedef void(TITCALL *fCustomHandler)(void* SpecialDBG);
    typedef void(TITCALL *fFindOEPHandler)(LPPROCESS_INFORMATION fProcessInfo, LPVOID fCallBack);
    fCustomHandler myCustomHandler;
    fCustomBreakPoint myCustomBreakPoint;
    ULONG_PTR MemoryBpxCallBack = 0;
    SIZE_T ResetBPXSize = 0;
    ULONG_PTR ResetBPXAddressTo =  0;
    ULONG_PTR ResetMemBPXAddress = 0;
    SIZE_T ResetMemBPXSize = 0;
    //int MaximumBreakPoints = 0;
    ULONG_PTR NumberOfBytesReadWritten = 0;
    MEMORY_BASIC_INFORMATION MemInfo;
    HANDLE hActiveThread;
    CONTEXT myDBGContext;
    DWORD OldProtect;
    DWORD NewProtect;
    DWORD DebugRegisterXId = NULL;
    HARDWARE_DATA DebugRegisterX;
    wchar_t DLLDebugFileName[512];
    char szAnsiLibraryName[MAX_PATH];
    ULONG_PTR DLLPatchAddress;
    HANDLE hFileMapping;
    LPVOID hFileMappingView;
    LPVOID DBGEntryPoint;
    bool MemoryBpxFound = false;
    wchar_t* szTranslatedNativeName;

    DBGFileHandle = NULL;
    DBGCode = DBG_CONTINUE;
    engineFakeDLLHandle = NULL;
    DebugRegister[0].DrxEnabled = false;
    DebugRegister[1].DrxEnabled = false;
    DebugRegister[2].DrxEnabled = false;
    DebugRegister[3].DrxEnabled = false;
    engineProcessIsNowDetached = false;
    engineResumeProcessIfNoThreadIsActive = false;
    RtlZeroMemory(&DBGEvent, sizeof DEBUG_EVENT);
    RtlZeroMemory(&TerminateDBGEvent, sizeof DEBUG_EVENT);
    RtlZeroMemory(&DLLDebugFileName, 512);
    ExtensionManagerPluginResetCallBack();
    engineFileIsBeingDebugged = true;
    if(engineExecutePluginCallBack)
    {
        ExtensionManagerPluginDebugCallBack(&DBGEvent, UE_PLUGIN_CALL_REASON_PREDEBUG);
    }

    while(!BreakDBG) //actual debug loop
    {
        WaitForDebugEvent(&DBGEvent, engineWaitForDebugEventTimeOut);
        if(engineExecutePluginCallBack)
        {
            ExtensionManagerPluginDebugCallBack(&DBGEvent, UE_PLUGIN_CALL_REASON_EXCEPTION);
        }

        //Debug event
        switch(DBGEvent.dwDebugEventCode)
        {
        case CREATE_PROCESS_DEBUG_EVENT:
        {
            if(DBGFileHandle == NULL) //we didn't set the handle yet
            {
                DBGEntryPoint = DBGEvent.u.CreateProcessInfo.lpStartAddress;
                DBGFileHandle = DBGEvent.u.CreateProcessInfo.hFile;
                EngineCloseHandle(DBGFileHandle); //handle is never used inside the code
                DebugDebuggingMainModuleBase = (unsigned long long) DBGEvent.u.CreateProcessInfo.lpBaseOfImage;
                if(DebugAttachedToProcess) //we attached, set information
                {
                    dbgProcessInformation.hProcess = DBGEvent.u.CreateProcessInfo.hProcess;
                    dbgProcessInformation.hThread = DBGEvent.u.CreateProcessInfo.hThread;
                    dbgProcessInformation.dwThreadId = NULL;
                    if(engineAttachedProcessDebugInfo != NULL)
                    {
                        RtlMoveMemory(engineAttachedProcessDebugInfo, &dbgProcessInformation, sizeof PROCESS_INFORMATION);
                    }
                }
                if(DebugDebuggingDLL) //the DLL loader just started, set DLL names
                {
#if defined(_WIN64)
                    DLLPatchAddress = (ULONG_PTR)DBGEvent.u.CreateProcessInfo.lpBaseOfImage;
                    DLLPatchAddress = (ULONG_PTR)DLLPatchAddress + UE_MODULEx64;
#else
                    DLLPatchAddress = (ULONG_PTR)DBGEvent.u.CreateProcessInfo.lpBaseOfImage;
                    DLLPatchAddress = (ULONG_PTR)DLLPatchAddress + UE_MODULEx86;
#endif
                    if(!WriteProcessMemory(DBGEvent.u.CreateProcessInfo.hProcess, (LPVOID)DLLPatchAddress, DebugDebuggingDLLFullFileName, lstrlenW(DebugDebuggingDLLFullFileName) * 2, &NumberOfBytesReadWritten))
                    {
                        StopDebug();
                        return;
                    }
                    if(DebugReserveModuleBase) //reserve original image base
                    {
                        VirtualAllocEx(dbgProcessInformation.hProcess, (void*)DebugReserveModuleBase, 0x1000, MEM_RESERVE, PAGE_READWRITE); //return value nt used, yea just ignore. return value doesnt matter and there is no possible fix when failed :D this is only used to make sure DLL loads on another image base
                    }
                }
                if(hListProcess == NULL)
                {
                    hListProcess = VirtualAlloc(NULL, MAX_DEBUG_DATA * sizeof PROCESS_ITEM_DATA, MEM_COMMIT, PAGE_READWRITE);
                }
                else
                {
                    if(hListProcessFirst == true)
                    {
                        RtlZeroMemory(hListProcess, MAX_DEBUG_DATA * sizeof PROCESS_ITEM_DATA);
                    }
                }
                if(hListThread == NULL)
                {
                    hListThread = VirtualAlloc(NULL, MAX_DEBUG_DATA * sizeof THREAD_ITEM_DATA, MEM_COMMIT, PAGE_READWRITE);
                }
                else
                {
                    if(hListThreadFirst == true)
                    {
                        RtlZeroMemory(hListThread, MAX_DEBUG_DATA * sizeof THREAD_ITEM_DATA);
                    }
                }
                hListProcessPtr = (PPROCESS_ITEM_DATA)hListProcess;
                hListProcessPtr->hFile = DBGEvent.u.CreateProcessInfo.hFile;
                hListProcessPtr->hProcess = DBGEvent.u.CreateProcessInfo.hProcess;
                hListProcessPtr->hThread = DBGEvent.u.CreateProcessInfo.hThread;
                hListProcessPtr->dwProcessId = DBGEvent.dwProcessId;
                hListProcessPtr->dwThreadId = DBGEvent.dwThreadId;
                hListProcessPtr->BaseOfImage = (void*)DBGEvent.u.CreateProcessInfo.lpBaseOfImage;
                hListProcessPtr->ThreadStartAddress = (void*)DBGEvent.u.CreateProcessInfo.lpStartAddress;
                hListProcessPtr->ThreadLocalBase = (void*)DBGEvent.u.CreateProcessInfo.lpThreadLocalBase;

                hListThreadPtr = (PTHREAD_ITEM_DATA)hListThread;
                hListThreadPtr->dwThreadId = DBGEvent.dwThreadId;
                hListThreadPtr->hThread = DBGEvent.u.CreateProcessInfo.hThread;
                hListThreadPtr->ThreadStartAddress = (void*)DBGEvent.u.CreateProcessInfo.lpStartAddress;
                hListThreadPtr->ThreadLocalBase = (void*)DBGEvent.u.CreateProcessInfo.lpThreadLocalBase;
                hListThreadFirst = false;
            }
            else //we have a valid handle already (which means a child process started)
            {
                hListProcessPtr = (PPROCESS_ITEM_DATA)hListProcess;
                while(hListProcessPtr->hProcess != NULL)
                {
                    hListProcessPtr = (PPROCESS_ITEM_DATA)((ULONG_PTR)hListProcessPtr + sizeof PROCESS_ITEM_DATA);
                }
                if(hListProcessPtr->hProcess == NULL)
                {
                    hListProcessPtr->hFile = DBGEvent.u.CreateProcessInfo.hFile;
                    hListProcessPtr->hProcess = DBGEvent.u.CreateProcessInfo.hProcess;
                    hListProcessPtr->hThread = DBGEvent.u.CreateProcessInfo.hThread;
                    hListProcessPtr->dwProcessId = DBGEvent.dwProcessId;
                    hListProcessPtr->dwThreadId = DBGEvent.dwThreadId;
                    hListProcessPtr->BaseOfImage = (void*)DBGEvent.u.CreateProcessInfo.lpBaseOfImage;
                    hListProcessPtr->ThreadStartAddress = (void*)DBGEvent.u.CreateProcessInfo.lpStartAddress;
                    hListProcessPtr->ThreadLocalBase = (void*)DBGEvent.u.CreateProcessInfo.lpThreadLocalBase;
                    hListProcessFirst = false;
                }
            }

            //process created callback
            if(DBGCustomHandler->chCreateProcess != NULL)
            {
                myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chCreateProcess);
                __try
                {
                    myCustomHandler(&DBGEvent.u.CreateProcessInfo);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    DBGCustomHandler->chCreateProcess = NULL;
                }
            }
        }
        break;

        case EXIT_PROCESS_DEBUG_EVENT:
        {
            ProcessExitCode = DBGEvent.u.ExitProcess.dwExitCode;
            DBGCode = DBG_CONTINUE;
            if(DBGEvent.dwProcessId == dbgProcessInformation.dwProcessId) //main process closed
                BreakDBG = true;

            //exit process handler
            if(DBGCustomHandler->chExitProcess != NULL)
            {
                myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chExitProcess);
                __try
                {
                    myCustomHandler(&DBGEvent.u.ExitProcess);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    DBGCustomHandler->chExitProcess = NULL;
                }
            }
        }
        break;

        case CREATE_THREAD_DEBUG_EVENT:
        {
            //maintain thread list
            if(hListThread == NULL)
            {
                hListThread = VirtualAlloc(NULL, MAX_DEBUG_DATA * sizeof THREAD_ITEM_DATA, MEM_COMMIT, PAGE_READWRITE);
            }
            hListThreadPtr = (PTHREAD_ITEM_DATA)hListThread;
            __try
            {
                while(hListThreadPtr->hThread != NULL)
                {
                    hListThreadPtr = (PTHREAD_ITEM_DATA)((ULONG_PTR)hListThreadPtr + sizeof THREAD_ITEM_DATA);
                }
                hListThreadPtr->dwThreadId = DBGEvent.dwThreadId;
                hListThreadPtr->hThread = DBGEvent.u.CreateThread.hThread;
                hListThreadPtr->ThreadStartAddress = (void*)DBGEvent.u.CreateThread.lpStartAddress;
                hListThreadPtr->ThreadLocalBase = (void*)DBGEvent.u.CreateThread.lpThreadLocalBase;
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {

            }

            //custom handler
            if(DBGCustomHandler->chCreateThread != NULL)
            {
                myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chCreateThread);
                __try
                {
                    myCustomHandler(&DBGEvent.u.CreateThread);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    DBGCustomHandler->chCreateThread = NULL;
                }
            }
        }
        break;

        case EXIT_THREAD_DEBUG_EVENT:
        {
            //custom handler
            if(DBGCustomHandler->chExitThread != NULL)
            {
                myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chExitThread);
                __try
                {
                    myCustomHandler(&DBGEvent.u.ExitThread);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    DBGCustomHandler->chExitThread = NULL;
                }
            }
            if(engineExitThreadOneShootCallBack != NULL)
            {
                myCustomHandler = (fCustomHandler)(engineExitThreadOneShootCallBack);
                __try
                {
                    myCustomHandler(&DBGEvent.u.ExitThread);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {

                }
                engineExitThreadOneShootCallBack = NULL;
            }

            //maintain thread list
            hListThreadPtr = (PTHREAD_ITEM_DATA)hListThread;
            while(hListThreadPtr->hThread != NULL && hListThreadPtr->dwThreadId != DBGEvent.dwThreadId)
            {
                hListThreadPtr = (PTHREAD_ITEM_DATA)((ULONG_PTR)hListThreadPtr + sizeof THREAD_ITEM_DATA);
            }
            if(hListThreadPtr->dwThreadId == DBGEvent.dwThreadId)
            {
                hListThreadPtr->hThread = (HANDLE)-1;
                hListThreadPtr->dwThreadId = NULL;
                hListThreadPtr->ThreadLocalBase = NULL;
                hListThreadPtr->ThreadStartAddress = NULL;
            }
        }
        break;

        case LOAD_DLL_DEBUG_EVENT:
        {
            //maintain library list
            if(hListLibrary == NULL)
            {
                hListLibrary = VirtualAlloc(NULL, MAX_DEBUG_DATA * sizeof LIBRARY_ITEM_DATAW, MEM_COMMIT, PAGE_READWRITE);
            }
            else
            {
                if(hListLibraryFirst == true)
                {
                    RtlZeroMemory(hListLibrary, MAX_DEBUG_DATA * sizeof LIBRARY_ITEM_DATAW);
                }
            }
            hListLibraryFirst = false;
            hListLibraryPtr = (PLIBRARY_ITEM_DATAW)hListLibrary;
            while(hListLibraryPtr->hFile != NULL)
            {
                hListLibraryPtr = (PLIBRARY_ITEM_DATAW)((ULONG_PTR)hListLibraryPtr + sizeof LIBRARY_ITEM_DATAW);
            }
            hListLibraryPtr->hFile = DBGEvent.u.LoadDll.hFile;
            hListLibraryPtr->BaseOfDll = DBGEvent.u.LoadDll.lpBaseOfDll;
            hFileMapping = CreateFileMappingA(DBGEvent.u.LoadDll.hFile, NULL, PAGE_READONLY, NULL, GetFileSize(DBGEvent.u.LoadDll.hFile, NULL), NULL);
            if(hFileMapping != NULL)
            {
                hFileMappingView = MapViewOfFile(hFileMapping, FILE_MAP_READ, NULL, NULL, NULL);
                if(hFileMappingView != NULL)
                {
                    hListLibraryPtr->hFileMapping = hFileMapping;
                    hListLibraryPtr->hFileMappingView = hFileMappingView;
                    if(GetMappedFileNameW(GetCurrentProcess(), hFileMappingView, DLLDebugFileName, sizeof(DLLDebugFileName)/sizeof(DLLDebugFileName[0])) > NULL)
                    {
                        int i = lstrlenW(DLLDebugFileName);
                        while(DLLDebugFileName[i] != 0x5C && i >= NULL)
                        {
                            i--;
                        }
                        if(DebugDebuggingDLL)
                        {
                            if(lstrcmpiW(&DLLDebugFileName[i+1], DebugDebuggingDLLFileName) == NULL)
                            {
                                SetBPX(DebugModuleEntryPoint + (ULONG_PTR)DBGEvent.u.LoadDll.lpBaseOfDll, UE_SINGLESHOOT, DebugModuleEntryPointCallBack);
                                DebugDebuggingDLLBase = (ULONG_PTR)DBGEvent.u.LoadDll.lpBaseOfDll;
                            }
                            /*else if(lstrcmpiW(&DLLDebugFileName[i+1], DebugDebuggingDLLReserveFileName) == NULL)
                            {
                                if((ULONG_PTR)DBGEvent.u.LoadDll.lpBaseOfDll != DebugModuleImageBase)
                                {
                                    VirtualAllocEx(dbgProcessInformation.hProcess, (void*)DebugModuleImageBase, 0x1000, MEM_RESERVE, PAGE_READWRITE);
                                }
                            }*/
                        }
                        if(engineFakeDLLHandle == NULL)
                        {
                            if(lstrcmpiW(&DLLDebugFileName[i+1], L"kernel32.dll") == NULL)
                            {
                                engineFakeDLLHandle = (ULONG_PTR)DBGEvent.u.LoadDll.lpBaseOfDll;
                            }
                        }
                        lstrcpyW(hListLibraryPtr->szLibraryName, &DLLDebugFileName[i+1]);
                        szTranslatedNativeName = (wchar_t*)TranslateNativeNameW(DLLDebugFileName);
                        lstrcpyW(hListLibraryPtr->szLibraryPath, szTranslatedNativeName);
                        VirtualFree((void*)szTranslatedNativeName, NULL, MEM_RELEASE);
                        RtlZeroMemory(szAnsiLibraryName, sizeof szAnsiLibraryName);
                        WideCharToMultiByte(CP_ACP, NULL, hListLibraryPtr->szLibraryName, -1, szAnsiLibraryName, sizeof szAnsiLibraryName, NULL, NULL);
                        ptrLibrarianData = (PLIBRARY_BREAK_DATA)LibrarianData;
                        k = NULL;
                        if(ptrLibrarianData != NULL)
                        {
                            while(k < MAX_LIBRARY_BPX)
                            {
                                if(ptrLibrarianData->szLibraryName[0] != 0x00)
                                {
                                    if(lstrcmpiA(ptrLibrarianData->szLibraryName, szAnsiLibraryName) == NULL)
                                    {
                                        if(ptrLibrarianData->bpxType == UE_ON_LIB_LOAD || ptrLibrarianData->bpxType == UE_ON_LIB_ALL)
                                        {
                                            myCustomHandler = (fCustomHandler)(ptrLibrarianData->bpxCallBack);
                                            __try
                                            {
                                                myCustomHandler(&DBGEvent.u.LoadDll);
                                            }
                                            __except(EXCEPTION_EXECUTE_HANDLER)
                                            {
                                                LibrarianRemoveBreakPoint(ptrLibrarianData->szLibraryName, ptrLibrarianData->bpxType);
                                            }
                                            if(ptrLibrarianData->bpxSingleShoot)
                                            {
                                                LibrarianRemoveBreakPoint(ptrLibrarianData->szLibraryName, ptrLibrarianData->bpxType);
                                            }
                                        }
                                    }
                                }
                                ptrLibrarianData = (PLIBRARY_BREAK_DATA)((ULONG_PTR)ptrLibrarianData + sizeof LIBRARY_BREAK_DATA);
                                k++;
                            }
                        }
                    }
                }
            }
            //loadDLL callback
            if(DBGCustomHandler->chLoadDll != NULL)
            {
                myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chLoadDll);
                __try
                {
                    myCustomHandler(&DBGEvent.u.LoadDll);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    DBGCustomHandler->chLoadDll = NULL;
                }
            }
        }
        break;

        case UNLOAD_DLL_DEBUG_EVENT:
        {
            //unload DLL callback
            if(DBGCustomHandler->chUnloadDll != NULL)
            {
                myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chUnloadDll);
                __try
                {
                    myCustomHandler(&DBGEvent.u.UnloadDll);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    DBGCustomHandler->chUnloadDll = NULL;
                }
            }

            //maintain library list
            k = NULL;
            ptrLibrarianData = (PLIBRARY_BREAK_DATA)LibrarianData;
            hLoadedLibData = (PLIBRARY_ITEM_DATAW)LibrarianGetLibraryInfoEx(DBGEvent.u.UnloadDll.lpBaseOfDll);
            if(hLoadedLibData != NULL)
            {
                RtlZeroMemory(szAnsiLibraryName, sizeof szAnsiLibraryName);
                WideCharToMultiByte(CP_ACP, NULL, hLoadedLibData->szLibraryName, -1, szAnsiLibraryName, sizeof szAnsiLibraryName, NULL, NULL);
                if(ptrLibrarianData != NULL)
                {
                    while(k < MAX_LIBRARY_BPX)
                    {
                        if(ptrLibrarianData->szLibraryName[0] != 0x00)
                        {
                            if(lstrcmpiA(ptrLibrarianData->szLibraryName, szAnsiLibraryName) == NULL)
                            {
                                if(ptrLibrarianData->bpxType == UE_ON_LIB_UNLOAD || ptrLibrarianData->bpxType == UE_ON_LIB_ALL)
                                {
                                    myCustomHandler = (fCustomHandler)(ptrLibrarianData->bpxCallBack);
                                    __try
                                    {
                                        myCustomHandler(&DBGEvent.u.UnloadDll);
                                    }
                                    __except(EXCEPTION_EXECUTE_HANDLER)
                                    {
                                        LibrarianRemoveBreakPoint(ptrLibrarianData->szLibraryName, ptrLibrarianData->bpxType);
                                    }
                                    if(ptrLibrarianData->bpxSingleShoot)
                                    {
                                        LibrarianRemoveBreakPoint(ptrLibrarianData->szLibraryName, ptrLibrarianData->bpxType);
                                    }
                                }
                            }
                        }
                        ptrLibrarianData = (PLIBRARY_BREAK_DATA)((ULONG_PTR)ptrLibrarianData + sizeof LIBRARY_BREAK_DATA);
                        k++;
                    }
                }
            }
            hListLibraryPtr = (PLIBRARY_ITEM_DATAW)hListLibrary;
            if(hListLibraryPtr != NULL)
            {
                while(hListLibraryPtr->hFile != NULL)
                {
                    if(hListLibraryPtr->BaseOfDll == DBGEvent.u.UnloadDll.lpBaseOfDll)
                    {
                        if(hListLibraryPtr->hFile != (HANDLE)-1)
                        {
                            if(hListLibraryPtr->hFileMappingView != NULL)
                            {
                                UnmapViewOfFile(hListLibraryPtr->hFileMappingView);
                                EngineCloseHandle(hListLibraryPtr->hFileMapping);
                            }
                            EngineCloseHandle(hListLibraryPtr->hFile);
                            RtlZeroMemory(hListLibraryPtr, sizeof LIBRARY_ITEM_DATAW);
                            hListLibraryPtr->hFile = (HANDLE)-1;
                        }
                    }
                    hListLibraryPtr = (PLIBRARY_ITEM_DATAW)((ULONG_PTR)hListLibraryPtr + sizeof LIBRARY_ITEM_DATAW);
                }
            }
        }
        break;

        case OUTPUT_DEBUG_STRING_EVENT:
        {
            //debug string callback
            if(DBGCustomHandler->chOutputDebugString != NULL)
            {
                myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chOutputDebugString);
                __try
                {
                    myCustomHandler(&DBGEvent.u.DebugString);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    DBGCustomHandler->chOutputDebugString = NULL;
                }
            }
            //http://maximumcrack.wordpress.com/2009/06/22/outputdebugstring-awesomeness/ (the final advice is incorrect, but still helpful)
            DBGCode = DBG_EXCEPTION_NOT_HANDLED; //pass exception to debuggee
        }
        break;

        case EXCEPTION_DEBUG_EVENT:
        {
            DBGCode = DBG_EXCEPTION_NOT_HANDLED; //let the debuggee handle exceptions per default

            if(DBGCustomHandler->chEverythingElse != NULL)
            {
                myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chEverythingElse);
                __try
                {
                    myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    DBGCustomHandler->chEverythingElse = NULL;
                }
            }
            if(DBGEvent.u.Exception.dwFirstChance == FALSE) //second chance exception
            {
                //NOTE: unclear behavious of ->Pass<- all exceptions (not to debuggee, but to debugger)
                if(!enginePassAllExceptions)
                {
                    DBGCode = DBG_CONTINUE;
                }
                else
                {
                    DBGCode = DBG_EXCEPTION_NOT_HANDLED; //let debuggee handle the exception
                }
                RtlMoveMemory(&TerminateDBGEvent, &DBGEvent, sizeof DEBUG_EVENT);
            }

            //handle different exception codes
            switch(DBGEvent.u.Exception.ExceptionRecord.ExceptionCode)
            {
            case STATUS_BREAKPOINT:
            {
                bool bFoundBreakPoint=false;
                BreakPointDetail FoundBreakPoint;
                int bpcount=BreakPointBuffer.size();
                for(int i=0; i<bpcount; i++)
                {
                    if(BreakPointBuffer.at(i).BreakPointAddress == (ULONG_PTR)DBGEvent.u.Exception.ExceptionRecord.ExceptionAddress - (BreakPointBuffer.at(i).BreakPointSize - 1) &&
                            (BreakPointBuffer.at(i).BreakPointType == UE_BREAKPOINT || BreakPointBuffer.at(i).BreakPointType == UE_SINGLESHOOT) &&
                            BreakPointBuffer.at(i).BreakPointActive == UE_BPXACTIVE)
                    {
                        FoundBreakPoint=BreakPointBuffer.at(i);
                        bFoundBreakPoint=true;
                        break;
                    }
                }
                if(bFoundBreakPoint) //breakpoint found
                {
                    VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)FoundBreakPoint.BreakPointAddress, FoundBreakPoint.BreakPointSize, PAGE_EXECUTE_READWRITE, &OldProtect);
                    if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)FoundBreakPoint.BreakPointAddress, &FoundBreakPoint.OriginalByte[0], FoundBreakPoint.BreakPointSize, &NumberOfBytesReadWritten))
                    {
                        DBGCode = DBG_CONTINUE;
                        hActiveThread = OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT, false, DBGEvent.dwThreadId);
                        myDBGContext.ContextFlags = CONTEXT_CONTROL;
                        GetThreadContext(hActiveThread, &myDBGContext);
                        if(FoundBreakPoint.BreakPointType != UE_SINGLESHOOT)
                        {
                            if(!(myDBGContext.EFlags & 0x100))
                            {
                                myDBGContext.EFlags = myDBGContext.EFlags ^ 0x100;
                            }
                        }
                        if(!(myDBGContext.EFlags & 0x10000))
                        {
                            myDBGContext.EFlags = myDBGContext.EFlags ^ 0x10000;
                        }
#if defined(_WIN64)
                        myDBGContext.Rip = myDBGContext.Rip - FoundBreakPoint.BreakPointSize;
#else
                        myDBGContext.Eip = myDBGContext.Eip - FoundBreakPoint.BreakPointSize;
#endif
                        SetThreadContext(hActiveThread, &myDBGContext);
                        EngineCloseHandle(hActiveThread);
                        VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)FoundBreakPoint.BreakPointAddress, FoundBreakPoint.BreakPointSize, OldProtect, &OldProtect);
                        myCustomBreakPoint = (fCustomBreakPoint)((LPVOID)FoundBreakPoint.ExecuteCallBack);
                        //execute callback
                        __try
                        {
                            myCustomBreakPoint();
                        }
                        __except(EXCEPTION_EXECUTE_HANDLER)
                        {

                        }
                        if(FoundBreakPoint.BreakPointType != UE_SINGLESHOOT)
                        {
                            DisableBPX((ULONG_PTR)FoundBreakPoint.BreakPointAddress);
                            ResetBPXSize = FoundBreakPoint.BreakPointSize - 1;
                            ResetBPXAddressTo = (ULONG_PTR)FoundBreakPoint.BreakPointAddress;
                            ResetBPX = true;
                        }
                        else
                        {
                            DeleteBPX((ULONG_PTR)FoundBreakPoint.BreakPointAddress);
                            ResetBPXSize = FoundBreakPoint.BreakPointSize - 1;
                            ResetBPXAddressTo = NULL;
                            ResetBPX = false;
                        }
                    }
                    else
                        VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)FoundBreakPoint.BreakPointAddress, FoundBreakPoint.BreakPointSize, OldProtect, &OldProtect);
                }
                else //breakpoint not in list
                {
                    if(!FirstBPX) //program generated a breakpoint exception
                    {
                        DBGCode = DBG_EXCEPTION_NOT_HANDLED;
                        if(DBGCustomHandler->chBreakPoint != NULL)
                        {
                            myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chBreakPoint);
                            __try
                            {
                                myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                            }
                            __except(EXCEPTION_EXECUTE_HANDLER)
                            {
                                DBGCustomHandler->chBreakPoint = NULL;
                            }
                        }
                    }
                    else //system breakpoint
                    {
                        FirstBPX = false;
                        DBGCode = DBG_CONTINUE;
                        if(DebugAttachedToProcess)
                        {
                            myCustomBreakPoint = (fCustomBreakPoint)(DebugAttachedProcessCallBack);
                            __try
                            {
                                myCustomBreakPoint();
                            }
                            __except(EXCEPTION_EXECUTE_HANDLER)
                            {

                            }
                        }
                        if(engineAutoHideFromDebugger)
                        {
                            HideDebugger(dbgProcessInformation.hProcess, UE_HIDE_PEBONLY);
                        }
                        if(DebugExeFileEntryPointCallBack != NULL) //set entry breakpoint
                        {
                            SetBPX((ULONG_PTR)DBGEntryPoint, UE_SINGLESHOOT, DebugExeFileEntryPointCallBack);
                        }
                        if(engineTLSBreakOnCallBack) //set TLS callback breakpoints
                        {
                            int i = NULL;
                            while(tlsCallBackList[i] != NULL)
                            {
                                SetBPX((ULONG_PTR)tlsCallBackList[i], UE_SINGLESHOOT, (LPVOID)engineTLSBreakOnCallBackAddress);
                                tlsCallBackList[i] = NULL;
                                i++;
                            }
                            engineTLSBreakOnCallBackAddress = NULL;
                            engineTLSBreakOnCallBack = false;
                        }

                        //system breakpoint callback
                        if(DBGCustomHandler->chSystemBreakpoint != NULL)
                        {
                            myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chSystemBreakpoint);
                            __try
                            {
                                myCustomHandler(&DBGEvent);
                            }
                            __except(EXCEPTION_EXECUTE_HANDLER)
                            {
                                DBGCustomHandler->chSystemBreakpoint = NULL;
                            }
                        }
                    }
                }
            }
            break;

            case STATUS_SINGLE_STEP:
            {
                if(ResetBPX == true || ResetHwBPX == true || ResetMemBPX == true) //restore breakpoints (internal step)
                {
                    DBGCode = DBG_CONTINUE;
                    if(ResetBPX) //restore 'normal' breakpoint
                    {
                        if(ResetBPXAddressTo + ResetBPXSize != (ULONG_PTR)DBGEvent.u.Exception.ExceptionRecord.ExceptionAddress)
                        {
                            EnableBPX(ResetBPXAddressTo);
                            ResetBPXAddressTo = NULL;
                            ResetBPX = false;
                            if(engineStepActive)
                            {
                                if(engineStepCount == NULL)
                                {
                                    myCustomBreakPoint = (fCustomBreakPoint)(engineStepCallBack);
                                    __try
                                    {
                                        engineStepActive = false;
                                        engineStepCallBack = NULL;
                                        myCustomBreakPoint();
                                    }
                                    __except(EXCEPTION_EXECUTE_HANDLER)
                                    {

                                    }
                                }
                                else
                                {
                                    SingleStep(engineStepCount, engineStepCallBack);
                                }
                            }
                        }
                        else
                        {
                            hActiveThread = OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_QUERY_INFORMATION, false, DBGEvent.dwThreadId);
                            myDBGContext.ContextFlags = CONTEXT_CONTROL;
                            GetThreadContext(hActiveThread, &myDBGContext);
                            if(!(myDBGContext.EFlags & 0x100))
                            {
                                myDBGContext.EFlags = myDBGContext.EFlags ^ 0x100;
                            }
                            SetThreadContext(hActiveThread, &myDBGContext);
                            EngineCloseHandle(hActiveThread);
                        }
                    }
                    else if(ResetHwBPX) //restore hardware breakpoint
                    {
                        ResetHwBPX = false;
                        SetHardwareBreakPoint(DebugRegisterX.DrxBreakAddress, DebugRegisterXId, DebugRegisterX.DrxBreakPointType, DebugRegisterX.DrxBreakPointSize, (LPVOID)DebugRegisterX.DrxCallBack);
                        if(engineStepActive)
                        {
                            if(engineStepCount == NULL)
                            {
                                myCustomBreakPoint = (fCustomBreakPoint)(engineStepCallBack);
                                __try
                                {
                                    engineStepActive = false;
                                    engineStepCallBack = NULL;
                                    myCustomBreakPoint();
                                }
                                __except(EXCEPTION_EXECUTE_HANDLER)
                                {

                                }
                            }
                            else
                            {
                                SingleStep(engineStepCount, engineStepCallBack);
                            }
                        }
                    }
                    else if(ResetMemBPX) //restore memory breakpoint
                    {
                        ResetMemBPX = false;
                        VirtualQueryEx(dbgProcessInformation.hProcess, (LPCVOID)ResetMemBPXAddress, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
                        OldProtect = MemInfo.Protect;
                        NewProtect = OldProtect | PAGE_GUARD; //guard page protection
                        VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)ResetMemBPXAddress, ResetMemBPXSize, NewProtect, &OldProtect);
                        if(engineStepActive)
                        {
                            if(engineStepCount == NULL)
                            {
                                myCustomBreakPoint = (fCustomBreakPoint)(engineStepCallBack);
                                __try
                                {
                                    engineStepActive = false;
                                    engineStepCallBack = NULL;
                                    myCustomBreakPoint();
                                }
                                __except(EXCEPTION_EXECUTE_HANDLER)
                                {

                                }
                            }
                            else
                            {
                                SingleStep(engineStepCount, engineStepCallBack);
                            }
                        }
                    }
                }
                else //no resetting needed (debugger reached hardware breakpoint or the user stepped)
                {
                    if(engineStepActive)
                    {
                        DBGCode = DBG_CONTINUE;
                        if(engineStepCount == NULL)
                        {
                            myCustomBreakPoint = (fCustomBreakPoint)(engineStepCallBack);
                            __try
                            {
                                engineStepActive = false;
                                engineStepCallBack = NULL;
                                myCustomBreakPoint();
                            }
                            __except(EXCEPTION_EXECUTE_HANDLER)
                            {

                            }
                        }
                        else
                        {
                            SingleStep(engineStepCount, engineStepCallBack);
                        }
                    }
                    else //handle hardware breakpoints
                    {
                        hActiveThread = OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_QUERY_INFORMATION, false, DBGEvent.dwThreadId);
                        myDBGContext.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                        GetThreadContext(hActiveThread, &myDBGContext);
                        if((ULONG_PTR)DBGEvent.u.Exception.ExceptionRecord.ExceptionAddress == myDBGContext.Dr0 || (myDBGContext.Dr6 & 0x1))
                        {
                            if(DebugRegister[0].DrxEnabled)
                            {
                                DBGCode = DBG_CONTINUE;
                                if(!(myDBGContext.EFlags & 0x100))
                                {
                                    myDBGContext.EFlags = myDBGContext.EFlags ^ 0x100;
                                }
                                SetThreadContext(hActiveThread, &myDBGContext);
                                myCustomHandler = (fCustomHandler)(DebugRegister[0].DrxCallBack);
                                __try
                                {
                                    myCustomHandler((void*)myDBGContext.Dr0);
                                }
                                __except(EXCEPTION_EXECUTE_HANDLER)
                                {

                                }
                                RtlZeroMemory(&DebugRegisterX, sizeof HARDWARE_DATA);
                                RtlMoveMemory(&DebugRegisterX, &DebugRegister[0], sizeof HARDWARE_DATA);
                                DeleteHardwareBreakPoint(UE_DR0);
                                DebugRegisterXId = UE_DR0;
                                ResetHwBPX = true;
                            }
                            else
                            {
                                DBGCode = DBG_EXCEPTION_NOT_HANDLED;
                            }
                        }
                        else if((ULONG_PTR)DBGEvent.u.Exception.ExceptionRecord.ExceptionAddress == myDBGContext.Dr1 || (myDBGContext.Dr6 & 0x2))
                        {
                            if(DebugRegister[1].DrxEnabled)
                            {
                                DBGCode = DBG_CONTINUE;
                                if(!(myDBGContext.EFlags & 0x100))
                                {
                                    myDBGContext.EFlags = myDBGContext.EFlags ^ 0x100;
                                }
                                SetThreadContext(hActiveThread, &myDBGContext);
                                myCustomHandler = (fCustomHandler)(DebugRegister[1].DrxCallBack);
                                __try
                                {
                                    myCustomHandler((void*)myDBGContext.Dr1);
                                }
                                __except(EXCEPTION_EXECUTE_HANDLER)
                                {

                                }
                                RtlZeroMemory(&DebugRegisterX, sizeof HARDWARE_DATA);
                                RtlMoveMemory(&DebugRegisterX, &DebugRegister[1], sizeof HARDWARE_DATA);
                                DeleteHardwareBreakPoint(UE_DR1);
                                DebugRegisterXId = UE_DR1;
                                ResetHwBPX = true;
                            }
                            else
                            {
                                DBGCode = DBG_EXCEPTION_NOT_HANDLED;
                            }
                        }
                        else if((ULONG_PTR)DBGEvent.u.Exception.ExceptionRecord.ExceptionAddress == myDBGContext.Dr2 || (myDBGContext.Dr6 & 0x4))
                        {
                            if(DebugRegister[2].DrxEnabled)
                            {
                                DBGCode = DBG_CONTINUE;
                                if(!(myDBGContext.EFlags & 0x100))
                                {
                                    myDBGContext.EFlags = myDBGContext.EFlags ^ 0x100;
                                }
                                SetThreadContext(hActiveThread, &myDBGContext);
                                myCustomHandler = (fCustomHandler)(DebugRegister[2].DrxCallBack);
                                __try
                                {
                                    myCustomHandler((void*)myDBGContext.Dr2);
                                }
                                __except(EXCEPTION_EXECUTE_HANDLER)
                                {

                                }
                                RtlZeroMemory(&DebugRegisterX, sizeof HARDWARE_DATA);
                                RtlMoveMemory(&DebugRegisterX, &DebugRegister[2], sizeof HARDWARE_DATA);
                                DeleteHardwareBreakPoint(UE_DR2);
                                DebugRegisterXId = UE_DR2;
                                ResetHwBPX = true;
                            }
                            else
                            {
                                DBGCode = DBG_EXCEPTION_NOT_HANDLED;
                            }
                        }
                        else if((ULONG_PTR)DBGEvent.u.Exception.ExceptionRecord.ExceptionAddress == myDBGContext.Dr3 || (myDBGContext.Dr6 & 0x8))
                        {
                            if(DebugRegister[3].DrxEnabled)
                            {
                                DBGCode = DBG_CONTINUE;
                                if(!(myDBGContext.EFlags & 0x100))
                                {
                                    myDBGContext.EFlags = myDBGContext.EFlags ^ 0x100;
                                }
                                SetThreadContext(hActiveThread, &myDBGContext);
                                myCustomHandler = (fCustomHandler)(DebugRegister[3].DrxCallBack);
                                __try
                                {
                                    myCustomHandler((void*)myDBGContext.Dr3);
                                }
                                __except(EXCEPTION_EXECUTE_HANDLER)
                                {

                                }
                                RtlZeroMemory(&DebugRegisterX, sizeof HARDWARE_DATA);
                                RtlMoveMemory(&DebugRegisterX, &DebugRegister[3], sizeof HARDWARE_DATA);
                                DeleteHardwareBreakPoint(UE_DR3);
                                DebugRegisterXId = UE_DR3;
                                ResetHwBPX = true;
                            }
                            else
                            {
                                DBGCode = DBG_EXCEPTION_NOT_HANDLED;
                            }
                        }
                        else //debuggee generated exception
                        {
                            DBGCode = DBG_EXCEPTION_NOT_HANDLED;
                        }
                        EngineCloseHandle(hActiveThread);
                    }
                }
                if(DBGCode==DBG_EXCEPTION_NOT_HANDLED) //NOTE: only call the chSingleStep callback when the debuggee generated the exception
                {
                    if(DBGCustomHandler->chSingleStep != NULL)
                    {
                        myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chSingleStep);
                        __try
                        {
                            myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                        }
                        __except(EXCEPTION_EXECUTE_HANDLER)
                        {
                            DBGCustomHandler->chSingleStep = NULL;
                        }
                    }
                }
            }
            break;

            case STATUS_GUARD_PAGE_VIOLATION:
            {
                ULONG_PTR bpaddr;
                bool bFoundBreakPoint=false;
                BreakPointDetail FoundBreakPoint;
                int bpcount=BreakPointBuffer.size();
                for(int i=0; i<bpcount; i++)
                {
                    ULONG_PTR addr=BreakPointBuffer.at(i).BreakPointAddress;
                    bpaddr=(ULONG_PTR)DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[1]; //page accessed
                    if(bpaddr>=addr && bpaddr<(addr+BreakPointBuffer.at(i).BreakPointSize) &&
                            (BreakPointBuffer.at(i).BreakPointType == UE_MEMORY ||
                             BreakPointBuffer.at(i).BreakPointType == UE_MEMORY_READ ||
                             BreakPointBuffer.at(i).BreakPointType == UE_MEMORY_WRITE ||
                             BreakPointBuffer.at(i).BreakPointType == UE_MEMORY_EXECUTE) &&
                            BreakPointBuffer.at(i).BreakPointActive == UE_BPXACTIVE)
                    {
                        FoundBreakPoint=BreakPointBuffer.at(i);
                        bFoundBreakPoint=true;
                        break;
                    }
                }
                if(bFoundBreakPoint) //found memory breakpoint
                {
                    hActiveThread = OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT, false, DBGEvent.dwThreadId);
                    myDBGContext.ContextFlags = CONTEXT_CONTROL;
                    GetThreadContext(hActiveThread, &myDBGContext);
                    DBGCode = DBG_CONTINUE; //debugger handled the exception
                    MemoryBpxCallBack = FoundBreakPoint.ExecuteCallBack;
                    if(FoundBreakPoint.BreakPointType == UE_MEMORY) //READ|WRITE|EXECUTE
                    {
                        if(FoundBreakPoint.MemoryBpxRestoreOnHit != 1)
                        {
                            RemoveMemoryBPX(FoundBreakPoint.BreakPointAddress, FoundBreakPoint.BreakPointSize);
                        }
                        else
                        {
                            if(!(myDBGContext.EFlags & 0x100))
                            {
                                myDBGContext.EFlags = myDBGContext.EFlags ^ 0x100;
                            }
                            SetThreadContext(hActiveThread, &myDBGContext);
                            ResetMemBPXAddress = FoundBreakPoint.BreakPointAddress;
                            ResetMemBPXSize = FoundBreakPoint.BreakPointSize;
                            ResetMemBPX = true;
                        }
                        myCustomHandler = (fCustomHandler)(MemoryBpxCallBack);
                        __try
                        {
                            myCustomHandler((void*)bpaddr);
                        }
                        __except(EXCEPTION_EXECUTE_HANDLER)
                        {

                        }
                    }
                    else if(FoundBreakPoint.BreakPointType == UE_MEMORY_READ) //READ
                    {
                        if(FoundBreakPoint.MemoryBpxRestoreOnHit != 1) //do not restore the memory breakpoint
                        {
                            if(DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[0] == 0) //read operation
                                RemoveMemoryBPX(FoundBreakPoint.BreakPointAddress, FoundBreakPoint.BreakPointSize);
                        }
                        else //restore the memory breakpoint
                        {
                            if(!(myDBGContext.EFlags & 0x100))
                            {
                                myDBGContext.EFlags = myDBGContext.EFlags ^ 0x100;
                            }
                            SetThreadContext(hActiveThread, &myDBGContext);
                            ResetMemBPXAddress = FoundBreakPoint.BreakPointAddress;
                            ResetMemBPXSize = FoundBreakPoint.BreakPointSize;
                            ResetMemBPX = true;
                        }
                        if(DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[0] == 0) //read operation
                        {
                            myCustomHandler = (fCustomHandler)(MemoryBpxCallBack);
                            __try
                            {
                                myCustomHandler((void*)bpaddr);
                            }
                            __except(EXCEPTION_EXECUTE_HANDLER)
                            {

                            }
                        }
                        else //no read operation, restore breakpoint
                        {
                            if(!(myDBGContext.EFlags & 0x100))
                            {
                                myDBGContext.EFlags = myDBGContext.EFlags ^ 0x100;
                            }
                            SetThreadContext(hActiveThread, &myDBGContext);
                            ResetMemBPXAddress = FoundBreakPoint.BreakPointAddress;
                            ResetMemBPXSize = FoundBreakPoint.BreakPointSize;
                            ResetMemBPX = true;
                        }
                    }
                    else if(FoundBreakPoint.BreakPointType == UE_MEMORY_WRITE) //WRITE
                    {
                        if(FoundBreakPoint.MemoryBpxRestoreOnHit != 1) //remove breakpoint
                        {
                            if(DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[0] == 1) //write operation
                                RemoveMemoryBPX(FoundBreakPoint.BreakPointAddress, FoundBreakPoint.BreakPointSize);
                        }
                        else //restore breakpoint after trap flag
                        {
                            if(!(myDBGContext.EFlags & 0x100))
                            {
                                myDBGContext.EFlags = myDBGContext.EFlags ^ 0x100;
                            }
                            SetThreadContext(hActiveThread, &myDBGContext);
                            ResetMemBPXAddress = FoundBreakPoint.BreakPointAddress;
                            ResetMemBPXSize = FoundBreakPoint.BreakPointSize;
                            ResetMemBPX = true;
                        }
                        if(DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[0] == 1) //write operation
                        {
                            myCustomHandler = (fCustomHandler)(MemoryBpxCallBack);
                            __try
                            {
                                myCustomHandler((void*)bpaddr);
                            }
                            __except(EXCEPTION_EXECUTE_HANDLER)
                            {

                            }
                        }
                        else //no write operation, restore breakpoint
                        {
                            if(!(myDBGContext.EFlags & 0x100))
                            {
                                myDBGContext.EFlags = myDBGContext.EFlags ^ 0x100;
                            }
                            SetThreadContext(hActiveThread, &myDBGContext);
                            ResetMemBPXAddress = FoundBreakPoint.BreakPointAddress;
                            ResetMemBPXSize = FoundBreakPoint.BreakPointSize;
                            ResetMemBPX = true;
                        }
                    }
                    else if(FoundBreakPoint.BreakPointType == UE_MEMORY_EXECUTE) //EXECUTE
                    {
                        if(FoundBreakPoint.MemoryBpxRestoreOnHit != 1)
                        {
                            if(DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[0] == 8 && //data execution prevention (DEP) violation
                                    (ULONG_PTR)DBGEvent.u.Exception.ExceptionRecord.ExceptionAddress == DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[1]) //exception address == read address
                                RemoveMemoryBPX(FoundBreakPoint.BreakPointAddress, FoundBreakPoint.BreakPointSize);
                        }
                        else
                        {
                            if(!(myDBGContext.EFlags & 0x100))
                            {
                                myDBGContext.EFlags = myDBGContext.EFlags ^ 0x100;
                            }
                            SetThreadContext(hActiveThread, &myDBGContext);
                            ResetMemBPXAddress = FoundBreakPoint.BreakPointAddress;
                            ResetMemBPXSize = FoundBreakPoint.BreakPointSize;
                            ResetMemBPX = true;
                        }
                        if(DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[0] == 8 && //data execution prevention (DEP) violation
                                (ULONG_PTR)DBGEvent.u.Exception.ExceptionRecord.ExceptionAddress == DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[1]) //exception address == read address
                        {
                            myCustomHandler = (fCustomHandler)(MemoryBpxCallBack);
                            __try
                            {
                                myCustomHandler((void*)bpaddr);
                            }
                            __except(EXCEPTION_EXECUTE_HANDLER)
                            {

                            }
                        }
                        else //no execute operation, restore breakpoint
                        {
                            if(!(myDBGContext.EFlags & 0x100))
                            {
                                myDBGContext.EFlags = myDBGContext.EFlags ^ 0x100;
                            }
                            SetThreadContext(hActiveThread, &myDBGContext);
                            ResetMemBPXAddress = FoundBreakPoint.BreakPointAddress;
                            ResetMemBPXSize = FoundBreakPoint.BreakPointSize;
                            ResetMemBPX = true;
                        }
                    }
                    EngineCloseHandle(hActiveThread);
                }
                else //no memory breakpoint found
                {
                    DBGCode = DBG_EXCEPTION_NOT_HANDLED;
                }

                //debuggee generated GUARD_PAGE exception
                if(DBGCode==DBG_EXCEPTION_NOT_HANDLED)
                {
                    //TODO: restore memory breakpoint?
                    if(DBGCustomHandler->chPageGuard != NULL)
                    {
                        myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chPageGuard);
                        __try
                        {
                            myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                        }
                        __except(EXCEPTION_EXECUTE_HANDLER)
                        {
                            DBGCustomHandler->chPageGuard = NULL;
                        }
                    }
                }
            }
            break;

            case STATUS_ACCESS_VIOLATION:
            {
                if(DBGCustomHandler->chAccessViolation != NULL)
                {
                    myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chAccessViolation);
                    __try
                    {
                        myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        DBGCustomHandler->chAccessViolation = NULL;
                    }
                }
            }
            break;

            case STATUS_ILLEGAL_INSTRUCTION:
            {
                //UD2 breakpoint
                bool bFoundBreakPoint=false;
                BreakPointDetail FoundBreakPoint;
                int bpcount=BreakPointBuffer.size();
                for(int i=0; i<bpcount; i++)
                {
                    if(BreakPointBuffer.at(i).BreakPointAddress == (ULONG_PTR)DBGEvent.u.Exception.ExceptionRecord.ExceptionAddress &&
                        (BreakPointBuffer.at(i).BreakPointType == UE_BREAKPOINT || BreakPointBuffer.at(i).BreakPointType == UE_SINGLESHOOT) &&
                        BreakPointBuffer.at(i).BreakPointActive == UE_BPXACTIVE)
                    {
                        FoundBreakPoint=BreakPointBuffer.at(i);
                        bFoundBreakPoint=true;
                        break;
                    }
                }
                if(bFoundBreakPoint) //found ud2 breakpoint
                {
                    VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)FoundBreakPoint.BreakPointAddress, FoundBreakPoint.BreakPointSize, PAGE_EXECUTE_READWRITE, &OldProtect);
                    if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)FoundBreakPoint.BreakPointAddress, &FoundBreakPoint.OriginalByte[0], FoundBreakPoint.BreakPointSize, &NumberOfBytesReadWritten))
                    {
                        DBGCode = DBG_CONTINUE;
                        hActiveThread = OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_QUERY_INFORMATION, false, DBGEvent.dwThreadId);
                        myDBGContext.ContextFlags = CONTEXT_CONTROL;
                        GetThreadContext(hActiveThread, &myDBGContext);
                        if(FoundBreakPoint.BreakPointType != UE_SINGLESHOOT)
                        {
                            if(!(myDBGContext.EFlags & 0x100))
                            {
                                myDBGContext.EFlags = myDBGContext.EFlags ^ 0x100;
                            }
                        }
                        if(!(myDBGContext.EFlags & 0x10000))
                        {
                            myDBGContext.EFlags = myDBGContext.EFlags ^ 0x10000;
                        }
                        SetThreadContext(hActiveThread, &myDBGContext);
                        EngineCloseHandle(hActiveThread);
                        VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)FoundBreakPoint.BreakPointAddress, FoundBreakPoint.BreakPointSize, OldProtect, &OldProtect);
                        myCustomBreakPoint = (fCustomBreakPoint)((LPVOID)FoundBreakPoint.ExecuteCallBack);
                        //execute callback
                        __try
                        {
                            myCustomBreakPoint();
                        }
                        __except(EXCEPTION_EXECUTE_HANDLER)
                        {

                        }
                        if(FoundBreakPoint.BreakPointType != UE_SINGLESHOOT)
                        {
                            DisableBPX((ULONG_PTR)FoundBreakPoint.BreakPointAddress);
                            ResetBPXSize = FoundBreakPoint.BreakPointSize - 1;
                            ResetBPXAddressTo = (ULONG_PTR)FoundBreakPoint.BreakPointAddress;
                            ResetBPX = true;
                        }
                        else
                        {
                            DeleteBPX((ULONG_PTR)FoundBreakPoint.BreakPointAddress);
                            ResetBPXSize = FoundBreakPoint.BreakPointSize - 1;
                            ResetBPXAddressTo = NULL;
                            ResetBPX = false;
                        }
                    }
                    else
                        VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)FoundBreakPoint.BreakPointAddress, FoundBreakPoint.BreakPointSize, OldProtect, &OldProtect);
                }
                else
                    DBGCode=DBG_EXCEPTION_NOT_HANDLED;

                //application-generated exception
                if(DBGCode==DBG_EXCEPTION_NOT_HANDLED)
                {
                    if(DBGCustomHandler->chIllegalInstruction != NULL)
                    {
                        myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chIllegalInstruction);
                        __try
                        {
                            myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                        }
                        __except(EXCEPTION_EXECUTE_HANDLER)
                        {
                            DBGCustomHandler->chIllegalInstruction = NULL;
                        }
                    }
                }
            }
            break;

            case STATUS_NONCONTINUABLE_EXCEPTION:
            {
                if(DBGCustomHandler->chNonContinuableException != NULL)
                {
                    myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chNonContinuableException);
                    __try
                    {
                        myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        DBGCustomHandler->chNonContinuableException = NULL;
                    }
                }
            }
            break;

            case STATUS_ARRAY_BOUNDS_EXCEEDED:
            {
                if(DBGCustomHandler->chArrayBoundsException != NULL)
                {
                    myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chArrayBoundsException);
                    __try
                    {
                        myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        DBGCustomHandler->chArrayBoundsException = NULL;
                    }
                }
            }
            break;

            case STATUS_FLOAT_DENORMAL_OPERAND:
            {
                if(DBGCustomHandler->chFloatDenormalOperand != NULL)
                {
                    myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chFloatDenormalOperand);
                    __try
                    {
                        myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        DBGCustomHandler->chFloatDenormalOperand = NULL;
                    }
                }
            }
            break;

            case STATUS_FLOAT_DIVIDE_BY_ZERO:
            {
                if(DBGCustomHandler->chFloatDevideByZero != NULL)
                {
                    myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chFloatDevideByZero);
                    __try
                    {
                        myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        DBGCustomHandler->chFloatDevideByZero = NULL;
                    }
                }
            }
            break;

            case STATUS_INTEGER_DIVIDE_BY_ZERO:
            {
                if(DBGCustomHandler->chIntegerDevideByZero != NULL)
                {
                    myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chIntegerDevideByZero);
                    __try
                    {
                        myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        DBGCustomHandler->chIntegerDevideByZero = NULL;
                    }
                }
            }
            break;

            case STATUS_INTEGER_OVERFLOW:
            {
                if(DBGCustomHandler->chIntegerOverflow != NULL)
                {
                    myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chIntegerOverflow);
                    __try
                    {
                        myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        DBGCustomHandler->chIntegerOverflow = NULL;
                    }
                }
            }
            break;

            case STATUS_PRIVILEGED_INSTRUCTION:
            {
                if(DBGCustomHandler->chPrivilegedInstruction != NULL)
                {
                    myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chPrivilegedInstruction);
                    __try
                    {
                        myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        DBGCustomHandler->chPrivilegedInstruction = NULL;
                    }
                }
            }
            break;
            }

            //general unhandled exception callback
            if(DBGCode==DBG_EXCEPTION_NOT_HANDLED)
            {
                if(DBGCustomHandler->chUnhandledException != NULL)
                {
                    myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chUnhandledException);
                    __try
                    {
                        myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        DBGCustomHandler->chUnhandledException = NULL;
                    }
                }
            }

            //general after-exception callback (includes debugger exceptions)
            if(DBGCustomHandler->chAfterException != NULL)
            {
                myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chAfterException);
                __try
                {
                    myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    DBGCustomHandler->chAfterException = NULL;
                }
            }
        }
        break;

        case RIP_EVENT:
        {
            DBGCode = DBG_EXCEPTION_NOT_HANDLED; //fix an anti-debug trick
            //system breakpoint callback
            if(DBGCustomHandler->chRipEvent != NULL)
            {
                myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chRipEvent);
                __try
                {
                    myCustomHandler(&DBGEvent);
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {
                    DBGCustomHandler->chSystemBreakpoint = NULL;
                }
            }
        }
        break;
        }

        if(engineResumeProcessIfNoThreadIsActive)
        {
            if(!ThreaderIsAnyThreadActive())
            {
                ThreaderResumeProcess();
            }
        }
        if(!ContinueDebugEvent(DBGEvent.dwProcessId, DBGEvent.dwThreadId, DBGCode)) //continue debugging
        {
            break;
        }
    }

    if(!SecondChance) //debugger didn't close with a second chance exception (normal exit)
    {
        RtlMoveMemory(&TerminateDBGEvent, &DBGEvent, sizeof DEBUG_EVENT);
    }
    ForceClose();
    engineFileIsBeingDebugged = false;
    if(engineExecutePluginCallBack)
    {
        ExtensionManagerPluginDebugCallBack(&DBGEvent, UE_PLUGIN_CALL_REASON_POSTDEBUG);
    }
}

__declspec(dllexport) void TITCALL DebugLoopEx(DWORD TimeOut)
{
    SetDebugLoopTimeOut(TimeOut);
    DebugLoop();
    SetDebugLoopTimeOut(INFINITE);
}

__declspec(dllexport) void TITCALL SetDebugLoopTimeOut(DWORD TimeOut)
{

    if(TimeOut == NULL)
    {
        TimeOut = INFINITE;
    }
    engineWaitForDebugEventTimeOut = TimeOut;
}
