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

#define UE_MODULEx86 0x2000;
#define UE_MODULEx64 0x2000;

static void engineStep()
{
    EnterCriticalSection(&engineStepActiveCr);
    if (engineStepActive)
    {
        DBGCode = DBG_CONTINUE;
        if (engineStepCount == 0)
        {
            typedef void(TITCALL* fCustomBreakPoint)(void);
            auto cbStep = fCustomBreakPoint(engineStepCallBack);
            engineStepActive = false;
            engineStepCallBack = NULL;
            LeaveCriticalSection(&engineStepActiveCr);
            cbStep();
        }
        else
        {
            SingleStep(engineStepCount, engineStepCallBack);
            LeaveCriticalSection(&engineStepActiveCr);
        }
    }
    else
    {
        LeaveCriticalSection(&engineStepActiveCr);
    }
}

__declspec(dllexport) void TITCALL DebugLoop()
{
    bool FirstBPX = true;
    bool ResetBPX = false;
    bool PushfBPX = false;
    bool BreakDBG = false;
    bool ResetHwBPX = false;
    bool ResetMemBPX = false;
    bool SecondChance = false;
    bool hListProcessFirst = true;
    bool hListThreadFirst = true;
    bool hListLibraryFirst = true;
    bool MemoryBpxFound = false;
    PLIBRARY_ITEM_DATAW hLoadedLibData = NULL;
    PLIBRARY_BREAK_DATA ptrLibrarianData = NULL;
    typedef void(TITCALL * fCustomBreakPoint)(void);
    typedef void(TITCALL * fCustomHandler)(void* SpecialDBG);
    typedef void(TITCALL * fFindOEPHandler)(LPPROCESS_INFORMATION fProcessInfo, LPVOID fCallBack);
    fCustomHandler myCustomHandler;
    fCustomBreakPoint myCustomBreakPoint;
    ULONG_PTR MemoryBpxCallBack = 0;
    SIZE_T ResetBPXSize = 0;
    ULONG_PTR ResetBPXAddressTo =  0;
    ULONG_PTR ResetMemBPXAddress = 0;
    SIZE_T ResetMemBPXSize = 0;
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
    LPVOID DBGEntryPoint;

    wchar_t* szTranslatedNativeName;

    DWORD ThreadBeingProcessed = 0;
    std::vector<THREAD_ITEM_DATA> SuspendedThreads;
    bool IsDbgReplyLaterSupported = false;

    // Check if DBG_REPLY_LATER is supported based on Windows version (Windows 10, version 1507 or above)
    // https://www.gaijin.at/en/infos/windows-version-numbers
    const uint32_t NtBuildNumber = *(uint32_t*)(0x7FFE0000 + 0x260);
    if(NtBuildNumber != 0 && NtBuildNumber >= 10240)
    {
        IsDbgReplyLaterSupported = true;
    }

    DBGFileHandle = NULL;
    DBGCode = DBG_CONTINUE;
    engineFakeDLLHandle = NULL;
    DebugRegister[0].DrxEnabled = false;
    DebugRegister[1].DrxEnabled = false;
    DebugRegister[2].DrxEnabled = false;
    DebugRegister[3].DrxEnabled = false;
    engineProcessIsNowDetached = false;
    engineResumeProcessIfNoThreadIsActive = false;
    memset(&DBGEvent, 0, sizeof(DEBUG_EVENT));
    memset(&TerminateDBGEvent, 0, sizeof(DEBUG_EVENT));
    memset(&DLLDebugFileName, 0, sizeof(DLLDebugFileName));
    ExtensionManagerPluginResetCallBack();
    engineFileIsBeingDebugged = true;
    if(engineExecutePluginCallBack)
    {
        ExtensionManagerPluginDebugCallBack(&DBGEvent, UE_PLUGIN_CALL_REASON_PREDEBUG);
    }

    while(!BreakDBG) //actual debug loop
    {
        // Fix based on work by https://github.com/number201724
        if(!WaitForDebugEvent(&DBGEvent, 100))
        {
            if(engineProcessIsNowDetached)
            {
                DebugActiveProcessStop(dbgProcessInformation.dwProcessId);
                DebugAttachedToProcess = false;
                break;
            }
            if(WaitForSingleObject(dbgProcessInformation.hProcess, 0) == WAIT_OBJECT_0)
            {
                DBGEvent.dwDebugEventCode = EXIT_PROCESS_DEBUG_EVENT;
                DBGEvent.dwProcessId = dbgProcessInformation.dwProcessId;
                DBGEvent.dwThreadId = dbgProcessInformation.dwThreadId;
                if(!GetExitCodeProcess(dbgProcessInformation.hProcess, &DBGEvent.u.ExitProcess.dwExitCode))
                    DBGEvent.u.ExitProcess.dwExitCode = 0xFFFFFFFF;
            }
            else
            {
                // Regular timeout, wait again
                continue;
            }
        }

        if(IsDbgReplyLaterSupported)
        {
            if(DBGEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
            {
                // Check if there is a thread processing a single step
                if(ThreadBeingProcessed != 0 && DBGEvent.dwThreadId != ThreadBeingProcessed)
                {
                    // Reply to the dbg event later
                    DBGCode = DBG_REPLY_LATER;

                    goto continue_dbg_event;
                }
            }
            else if(DBGEvent.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT)
            {
                if(ThreadBeingProcessed != 0 && DBGEvent.dwThreadId == ThreadBeingProcessed)
                {
                    // Resume the other threads since the thread being processed is exiting
                    for(auto & Thread : SuspendedThreads)
                        ResumeThread(Thread.hThread);

                    SuspendedThreads.clear();
                    ThreadBeingProcessed = 0;
                }
            }
        }

        if(engineExecutePluginCallBack)
        {
            ExtensionManagerPluginDebugCallBack(&DBGEvent, UE_PLUGIN_CALL_REASON_EXCEPTION);
        }

        //Debug event custom handler
        if(DBGCustomHandler->chDebugEvent != NULL)
        {
            myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chDebugEvent);
            myCustomHandler(&DBGEvent);
        }

        //Debug event
        switch(DBGEvent.dwDebugEventCode)
        {
        case CREATE_PROCESS_DEBUG_EVENT:
        {
            // HACK: when hollowing the process the debug event still delivers the original image base
            if(engineDisableAslr && !DebugDebuggingDLL && DebugModuleImageBase != 0)
            {
                auto startAddress = ULONG_PTR(DBGEvent.u.CreateProcessInfo.lpStartAddress);
                if(startAddress)
                {
                    startAddress -= ULONG_PTR(DBGEvent.u.CreateProcessInfo.lpBaseOfImage);
                    startAddress += DebugModuleImageBase;
                    DBGEvent.u.CreateProcessInfo.lpStartAddress = LPTHREAD_START_ROUTINE(startAddress);
                }
                DBGEvent.u.CreateProcessInfo.lpBaseOfImage = LPVOID(DebugModuleImageBase);
            }

            bool attachBreakpoint = false;
            if(DBGFileHandle == NULL) //we didn't set the handle yet (initial process)
            {
                DBGEntryPoint = DBGEvent.u.CreateProcessInfo.lpStartAddress;
                DBGFileHandle = DBGEvent.u.CreateProcessInfo.hFile;
                DebugDebuggingMainModuleBase = (ULONG_PTR) DBGEvent.u.CreateProcessInfo.lpBaseOfImage;
                if(DebugAttachedToProcess)  //we attached, set information
                {
                    dbgProcessInformation.hProcess = DBGEvent.u.CreateProcessInfo.hProcess;
                    dbgProcessInformation.hThread = DBGEvent.u.CreateProcessInfo.hThread;
                    dbgProcessInformation.dwThreadId = NULL;
                    if(engineAttachedProcessDebugInfo != NULL)
                    {
                        RtlMoveMemory(engineAttachedProcessDebugInfo, &dbgProcessInformation, sizeof PROCESS_INFORMATION);
                    }
                    attachBreakpoint = true;
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
                    if(DebugReserveModuleBase) //reserve original image base
                    {
                        VirtualAllocEx(dbgProcessInformation.hProcess, (void*)DebugReserveModuleBase, 0x1000, MEM_RESERVE, PAGE_READWRITE); //return value nt used, yea just ignore. return value doesnt matter and there is no possible fix when failed :D this is only used to make sure DLL loads on another image base
                    }
                }
                if(hListProcessFirst) //clear process list
                    ClearProcessList();
                hListProcessFirst = false;

                if(hListThreadFirst) //clear thread list
                    ClearThreadList();
                hListThreadFirst = false;
                //update thread list
                THREAD_ITEM_DATA NewThreadData;
                memset(&NewThreadData, 0, sizeof(THREAD_ITEM_DATA));
                NewThreadData.dwThreadId = DBGEvent.dwThreadId;
                NewThreadData.hThread = DBGEvent.u.CreateProcessInfo.hThread;
                NewThreadData.ThreadStartAddress = (void*)DBGEvent.u.CreateProcessInfo.lpStartAddress;
                NewThreadData.ThreadLocalBase = (void*)DBGEvent.u.CreateProcessInfo.lpThreadLocalBase;
                hListThread.push_back(NewThreadData);
            }
            //update process list
            PROCESS_ITEM_DATA NewProcessItem;
            memset(&NewProcessItem, 0, sizeof(PROCESS_ITEM_DATA));
            NewProcessItem.hFile = DBGEvent.u.CreateProcessInfo.hFile;
            NewProcessItem.hProcess = DBGEvent.u.CreateProcessInfo.hProcess;
            NewProcessItem.hThread = DBGEvent.u.CreateProcessInfo.hThread;
            NewProcessItem.dwProcessId = DBGEvent.dwProcessId;
            NewProcessItem.dwThreadId = DBGEvent.dwThreadId;
            NewProcessItem.BaseOfImage = (void*)DBGEvent.u.CreateProcessInfo.lpBaseOfImage;
            NewProcessItem.ThreadStartAddress = (void*)DBGEvent.u.CreateProcessInfo.lpStartAddress;
            NewProcessItem.ThreadLocalBase = (void*)DBGEvent.u.CreateProcessInfo.lpThreadLocalBase;
            hListProcess.push_back(NewProcessItem);

            //process created callback
            if(DBGCustomHandler->chCreateProcess != NULL)
            {
                myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chCreateProcess);
                myCustomHandler(&DBGEvent.u.CreateProcessInfo);
            }

            if(DBGFileHandle)
                EngineCloseHandle(DBGFileHandle); //close file handle

            // Call the attach breakpoint
            if(attachBreakpoint)
            {
                myCustomBreakPoint = (fCustomBreakPoint)(DebugAttachedProcessCallBack);
                myCustomBreakPoint();
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
                myCustomHandler(&DBGEvent.u.ExitProcess);
            }
        }
        break;

        case CREATE_THREAD_DEBUG_EVENT:
        {
            //maintain thread list
            THREAD_ITEM_DATA NewThreadData;
            memset(&NewThreadData, 0, sizeof(THREAD_ITEM_DATA));
            NewThreadData.dwThreadId = DBGEvent.dwThreadId;
            NewThreadData.hThread = DBGEvent.u.CreateThread.hThread;
            NewThreadData.ThreadStartAddress = (void*)DBGEvent.u.CreateThread.lpStartAddress;
            NewThreadData.ThreadLocalBase = (void*)DBGEvent.u.CreateThread.lpThreadLocalBase;
            hListThread.push_back(NewThreadData);

            //Set hardware breakpoints to all threads
            HANDLE hThread = NewThreadData.hThread;
            if(DebugRegister[0].DrxEnabled)
                SetHardwareBreakPointEx(hThread, DebugRegister[0].DrxBreakAddress, UE_DR0, DebugRegister[0].DrxBreakPointType, DebugRegister[0].DrxBreakPointSize, (void*)DebugRegister[0].DrxCallBack, 0);
            if(DebugRegister[1].DrxEnabled)
                SetHardwareBreakPointEx(hThread, DebugRegister[1].DrxBreakAddress, UE_DR1, DebugRegister[1].DrxBreakPointType, DebugRegister[1].DrxBreakPointSize, (void*)DebugRegister[1].DrxCallBack, 0);
            if(DebugRegister[2].DrxEnabled)
                SetHardwareBreakPointEx(hThread, DebugRegister[2].DrxBreakAddress, UE_DR2, DebugRegister[2].DrxBreakPointType, DebugRegister[2].DrxBreakPointSize, (void*)DebugRegister[2].DrxCallBack, 0);
            if(DebugRegister[3].DrxEnabled)
                SetHardwareBreakPointEx(hThread, DebugRegister[3].DrxBreakAddress, UE_DR3, DebugRegister[3].DrxBreakPointType, DebugRegister[3].DrxBreakPointSize, (void*)DebugRegister[3].DrxCallBack, 0);
            if(ResetHwBPX)
            {
                SetHardwareBreakPoint(DebugRegisterX.DrxBreakAddress, DebugRegisterXId, DebugRegisterX.DrxBreakPointType, DebugRegisterX.DrxBreakPointSize, (void*)DebugRegisterX.DrxCallBack);
                ResetHwBPX = false;
            }

            //custom handler
            if(DBGCustomHandler->chCreateThread != NULL)
            {
                myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chCreateThread);
                myCustomHandler(&DBGEvent.u.CreateThread);
            }
        }
        break;

        case EXIT_THREAD_DEBUG_EVENT:
        {
            //custom handler
            if(DBGCustomHandler->chExitThread != NULL)
            {
                myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chExitThread);
                myCustomHandler(&DBGEvent.u.ExitThread);
            }
            if(engineExitThreadOneShootCallBack != NULL)
            {
                myCustomHandler = (fCustomHandler)(engineExitThreadOneShootCallBack);
                myCustomHandler(&DBGEvent.u.ExitThread);
                engineExitThreadOneShootCallBack = NULL;
            }

            //maintain thread list
            for(unsigned int i = 0; i < hListThread.size(); i++)
            {
                if(hListThread.at(i).dwThreadId == DBGEvent.dwThreadId) //found the thread to remove
                {
                    hListThread.erase(hListThread.begin() + i);
                    break;
                }
            }
        }
        break;

        case LOAD_DLL_DEBUG_EVENT:
        {
            //maintain library list
            if(hListLibraryFirst)
                ClearLibraryList();
            hListLibraryFirst = false;
            LIBRARY_ITEM_DATAW NewLibraryData;
            memset(&NewLibraryData, 0, sizeof(LIBRARY_ITEM_DATAW));
            NewLibraryData.BaseOfDll = DBGEvent.u.LoadDll.lpBaseOfDll;

            // Query remote DLL path
            if(GetMappedFileNameW(dbgProcessInformation.hProcess, DBGEvent.u.LoadDll.lpBaseOfDll, DLLDebugFileName, sizeof(DLLDebugFileName) / sizeof(wchar_t)))
            {
                int i = lstrlenW(DLLDebugFileName);
                while(DLLDebugFileName[i] != '\\' && i)
                    i--;
                if(DebugDebuggingDLL)
                {
                    if(lstrcmpiW(&DLLDebugFileName[i + 1], DebugDebuggingDLLFileName) == NULL)
                    {
                        CloseHandle(DebugDLLFileMapping); //close file mapping handle
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
                    if(_wcsicmp(&DLLDebugFileName[i + 1], L"kernel32.dll") == NULL)
                    {
                        engineFakeDLLHandle = (ULONG_PTR)DBGEvent.u.LoadDll.lpBaseOfDll;
                    }
                }
                lstrcpyW(NewLibraryData.szLibraryName, &DLLDebugFileName[i + 1]);
                szTranslatedNativeName = (wchar_t*)TranslateNativeNameW(DLLDebugFileName);
                if(szTranslatedNativeName != nullptr)
                {
                    lstrcpyW(NewLibraryData.szLibraryPath, szTranslatedNativeName);
                    VirtualFree((void*)szTranslatedNativeName, NULL, MEM_RELEASE);
                }
                RtlZeroMemory(szAnsiLibraryName, sizeof(szAnsiLibraryName));
                WideCharToMultiByte(CP_ACP, NULL, NewLibraryData.szLibraryName, -1, szAnsiLibraryName, sizeof szAnsiLibraryName, NULL, NULL);

                //library breakpoint
                for(int i = (int)LibrarianData.size() - 1; i >= 0; i--)
                {
                    ptrLibrarianData = &LibrarianData.at(i);
                    if(!_stricmp(ptrLibrarianData->szLibraryName, szAnsiLibraryName))
                    {
                        if(ptrLibrarianData->bpxType == UE_ON_LIB_LOAD || ptrLibrarianData->bpxType == UE_ON_LIB_ALL)
                        {
                            myCustomHandler = (fCustomHandler)(ptrLibrarianData->bpxCallBack);
                            myCustomHandler(&DBGEvent.u.LoadDll);
                            if(ptrLibrarianData->bpxSingleShoot)
                            {
                                LibrarianRemoveBreakPoint(ptrLibrarianData->szLibraryName, ptrLibrarianData->bpxType);
                            }
                        }
                    }
                }
            }

            //maintain library list
            hListLibrary.push_back(NewLibraryData);

            //loadDLL callback
            if(DBGCustomHandler->chLoadDll != NULL)
            {
                myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chLoadDll);
                myCustomHandler(&DBGEvent.u.LoadDll);
            }

            if(DBGEvent.u.LoadDll.hFile)
                EngineCloseHandle(DBGEvent.u.LoadDll.hFile); //close file handle
        }
        break;

        case UNLOAD_DLL_DEBUG_EVENT:
        {
            //unload DLL callback
            if(DBGCustomHandler->chUnloadDll != NULL)
            {
                myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chUnloadDll);
                myCustomHandler(&DBGEvent.u.UnloadDll);
            }

            //library breakpoint
            hLoadedLibData = (PLIBRARY_ITEM_DATAW)LibrarianGetLibraryInfoEx(DBGEvent.u.UnloadDll.lpBaseOfDll);
            if(hLoadedLibData)
            {
                RtlZeroMemory(szAnsiLibraryName, sizeof(szAnsiLibraryName));
                WideCharToMultiByte(CP_ACP, NULL, hLoadedLibData->szLibraryName, -1, szAnsiLibraryName, sizeof szAnsiLibraryName, NULL, NULL);

                for(int i = (int)LibrarianData.size() - 1; i >= 0; i--)
                {
                    ptrLibrarianData = &LibrarianData.at(i);
                    if(!_stricmp(ptrLibrarianData->szLibraryName, szAnsiLibraryName))
                    {
                        if(ptrLibrarianData->bpxType == UE_ON_LIB_UNLOAD || ptrLibrarianData->bpxType == UE_ON_LIB_ALL)
                        {
                            myCustomHandler = (fCustomHandler)(ptrLibrarianData->bpxCallBack);
                            myCustomHandler(&DBGEvent.u.UnloadDll);
                            if(ptrLibrarianData->bpxSingleShoot)
                            {
                                LibrarianRemoveBreakPoint(ptrLibrarianData->szLibraryName, ptrLibrarianData->bpxType);
                            }
                        }
                    }
                }
            }

            //maintain library list
            for(unsigned int i = 0; i < hListLibrary.size(); i++)
            {
                if(hListLibrary.at(i).BaseOfDll == DBGEvent.u.UnloadDll.lpBaseOfDll)
                {
                    if(hListLibrary.at(i).hFileMappingView != NULL)
                    {
                        UnmapViewOfFile(hListLibrary.at(i).hFileMappingView);
                        EngineCloseHandle(hListLibrary.at(i).hFileMapping);
                    }
                    hListLibrary.erase(hListLibrary.begin() + i);
                    break;
                }
            }
        }
        break;

        case OUTPUT_DEBUG_STRING_EVENT:
        {
            //http://maximumcrack.wordpress.com/2009/06/22/outputdebugstring-awesomeness/ (the final advice is incorrect, but still helpful)
            DBGCode = DBG_EXCEPTION_NOT_HANDLED; //pass exception to debuggee
            if(engineExecutePluginCallBack)
            {
                ExtensionManagerPluginDebugCallBack(&DBGEvent, UE_PLUGIN_CALL_REASON_UNHANDLEDEXCEPTION);
            }
            //debug string callback
            if(DBGCustomHandler->chOutputDebugString != NULL)
            {
                myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chOutputDebugString);
                myCustomHandler(&DBGEvent.u.DebugString);
            }
        }
        break;

        case EXCEPTION_DEBUG_EVENT:
        {
            DBGCode = DBG_EXCEPTION_NOT_HANDLED; //let the debuggee handle exceptions per default

            if(DBGCustomHandler->chEverythingElse != NULL)
            {
                myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chEverythingElse);
                myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
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
                bool bFoundBreakPoint = false;
                BreakPointDetail FoundBreakPoint;
                int bpcount = (int)BreakPointBuffer.size();
                for(int i = 0; i < bpcount; i++)
                {
                    if(BreakPointBuffer.at(i).BreakPointAddress == (ULONG_PTR)DBGEvent.u.Exception.ExceptionRecord.ExceptionAddress - (BreakPointBuffer.at(i).BreakPointSize - 1) &&
                            (BreakPointBuffer.at(i).BreakPointType == UE_BREAKPOINT || BreakPointBuffer.at(i).BreakPointType == UE_SINGLESHOOT) &&
                            BreakPointBuffer.at(i).BreakPointActive == UE_BPXACTIVE)
                    {
                        FoundBreakPoint = BreakPointBuffer.at(i);
                        bFoundBreakPoint = true;
                        break;
                    }
                }
                if(bFoundBreakPoint) //breakpoint found
                {
                    VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)FoundBreakPoint.BreakPointAddress, FoundBreakPoint.BreakPointSize, PAGE_EXECUTE_READWRITE, &OldProtect);
                    if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)FoundBreakPoint.BreakPointAddress, &FoundBreakPoint.OriginalByte[0], FoundBreakPoint.BreakPointSize, &NumberOfBytesReadWritten))
                    {
                        FlushInstructionCache(dbgProcessInformation.hProcess, NULL, 0);
                        DBGCode = DBG_CONTINUE;
                        hActiveThread = EngineOpenThread(THREAD_GETSETSUSPEND, false, DBGEvent.dwThreadId);
                        myDBGContext.ContextFlags = ContextControlFlags;
                        GetThreadContext(hActiveThread, &myDBGContext);
                        if(FoundBreakPoint.BreakPointType != UE_SINGLESHOOT)
                            myDBGContext.EFlags |= UE_TRAP_FLAG;
#if defined(_WIN64)
                        myDBGContext.Rip = myDBGContext.Rip - FoundBreakPoint.BreakPointSize;
#else
                        myDBGContext.Eip = myDBGContext.Eip - FoundBreakPoint.BreakPointSize;
#endif
                        SetThreadContext(hActiveThread, &myDBGContext);
                        EngineCloseHandle(hActiveThread);
                        VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)FoundBreakPoint.BreakPointAddress, FoundBreakPoint.BreakPointSize, OldProtect, &OldProtect);
                        ULONG_PTR ueCurrentPosition = FoundBreakPoint.BreakPointAddress;
                        unsigned char instr[16];
                        MemoryReadSafe(dbgProcessInformation.hProcess, (void*)ueCurrentPosition, instr, sizeof(instr), 0);
                        char* DisassembledString = (char*)StaticDisassembleEx(ueCurrentPosition, (LPVOID)instr);
                        if(strstr(DisassembledString, "PUSHF"))
                            PushfBPX = true;

                        if(FoundBreakPoint.BreakPointType == UE_SINGLESHOOT)
                        {
                            DeleteBPX((ULONG_PTR)FoundBreakPoint.BreakPointAddress);
                            ResetBPXSize = FoundBreakPoint.BreakPointSize - 1;
                            ResetBPXAddressTo = NULL;
                            ResetBPX = false;
                        }

                        //execute callback
                        myCustomBreakPoint = (fCustomBreakPoint)((LPVOID)FoundBreakPoint.ExecuteCallBack);
                        myCustomBreakPoint();

                        if(FoundBreakPoint.BreakPointType != UE_SINGLESHOOT)
                        {
                            DisableBPX((ULONG_PTR)FoundBreakPoint.BreakPointAddress);
                            ResetBPXSize = FoundBreakPoint.BreakPointSize - 1;
                            ResetBPXAddressTo = (ULONG_PTR)FoundBreakPoint.BreakPointAddress;
                            ResetBPX = true;
                        }
                    }
                    else
                        VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)FoundBreakPoint.BreakPointAddress, FoundBreakPoint.BreakPointSize, OldProtect, &OldProtect);
                }
                else //breakpoint not in list
                {
                    if(DebugAttachedToProcess || !FirstBPX) //program generated a breakpoint exception
                    {
                        DBGCode = DBG_EXCEPTION_NOT_HANDLED;
                        if(DBGCustomHandler->chBreakPoint != NULL)
                        {
                            myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chBreakPoint);
                            myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                        }
                    }
                    else //system breakpoint
                    {
                        FirstBPX = false;
                        DBGCode = DBG_CONTINUE;
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
                            for(unsigned int i = 0; i < tlsCallBackList.size(); i++)
                                SetBPX(tlsCallBackList.at(i), UE_SINGLESHOOT, (LPVOID)engineTLSBreakOnCallBackAddress);
                            ClearTlsCallBackList();
                            engineTLSBreakOnCallBackAddress = NULL;
                            engineTLSBreakOnCallBack = false;
                        }

                        //system breakpoint callback
                        if(DBGCustomHandler->chSystemBreakpoint != NULL)
                        {
                            myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chSystemBreakpoint);
                            myCustomHandler(&DBGEvent);
                        }
                    }
                }
            }
            break;

            case STATUS_SINGLE_STEP:
            {
                if(IsDbgReplyLaterSupported)
                {
                    // Resume the other threads since we are done processing the single step
                    for(auto & Thread : SuspendedThreads)
                        ResumeThread(Thread.hThread);

                    SuspendedThreads.clear();
                    ThreadBeingProcessed = 0;
                }

                if(ResetBPX == true || ResetHwBPX == true || ResetMemBPX == true) //restore breakpoints (internal step)
                {
                    DBGCode = DBG_CONTINUE;
                    if(PushfBPX) //remove trap flag from stack
                    {
                        PushfBPX = false;
                        void* csp = (void*)GetContextData(UE_CSP);
                        ULONG_PTR data = 0;
                        ReadProcessMemory(dbgProcessInformation.hProcess, csp, &data, sizeof(ULONG_PTR), 0);
                        data &= ~UE_TRAP_FLAG;
                        WriteProcessMemory(dbgProcessInformation.hProcess, csp, &data, sizeof(ULONG_PTR), 0);
                        FlushInstructionCache(dbgProcessInformation.hProcess, NULL, 0);
                    }
                    if(ResetBPX) //restore 'normal' breakpoint
                    {
                        if(ResetBPXAddressTo + ResetBPXSize != (ULONG_PTR)DBGEvent.u.Exception.ExceptionRecord.ExceptionAddress)
                        {
                            EnableBPX(ResetBPXAddressTo);
                            ResetBPXAddressTo = NULL;
                            ResetBPX = false;
                            engineStep();
                        }
                        else
                        {
                            hActiveThread = EngineOpenThread(THREAD_GETSETSUSPEND, false, DBGEvent.dwThreadId);
                            myDBGContext.ContextFlags = ContextControlFlags;
                            GetThreadContext(hActiveThread, &myDBGContext);
                            myDBGContext.EFlags |= UE_TRAP_FLAG;
                            SetThreadContext(hActiveThread, &myDBGContext);
                            EngineCloseHandle(hActiveThread);
                        }
                    }
                    if(ResetHwBPX) //restore hardware breakpoint
                    {
                        ResetHwBPX = false;
                        SetHardwareBreakPoint(DebugRegisterX.DrxBreakAddress, DebugRegisterXId, DebugRegisterX.DrxBreakPointType, DebugRegisterX.DrxBreakPointSize, (LPVOID)DebugRegisterX.DrxCallBack);
                        engineStep();
                    }
                    if(ResetMemBPX) //restore memory breakpoint
                    {
                        ResetMemBPX = false;

                        // Check if the alternative memory breakpoint method should be used
                        if(engineMembpAlt)
                        {
                            // Check if the breakpoint is still enabled/present and has not been removed
                            for(int i = 0; i < BreakPointBuffer.size(); i++)
                            {
                                if(BreakPointBuffer.at(i).BreakPointAddress == ResetMemBPXAddress &&
                                        (BreakPointBuffer.at(i).BreakPointType == UE_MEMORY ||
                                         BreakPointBuffer.at(i).BreakPointType == UE_MEMORY_READ ||
                                         BreakPointBuffer.at(i).BreakPointType == UE_MEMORY_WRITE ||
                                         BreakPointBuffer.at(i).BreakPointType == UE_MEMORY_EXECUTE) &&
                                        BreakPointBuffer.at(i).BreakPointActive == UE_BPXACTIVE)
                                {
                                    // Restore the breakpoint
                                    VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)ResetMemBPXAddress,
                                                     ResetMemBPXSize, PAGE_NOACCESS, &OldProtect);

                                    break;
                                }
                            }
                        }
                        else
                        {
                            VirtualQueryEx(dbgProcessInformation.hProcess, (LPCVOID)ResetMemBPXAddress, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION));
                            OldProtect = MemInfo.Protect;
                            NewProtect = OldProtect | PAGE_GUARD; //guard page protection
                            VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)ResetMemBPXAddress, ResetMemBPXSize, NewProtect, &OldProtect);
                        }

                        engineStep();
                    }
                }
                else //no resetting needed (debugger reached hardware breakpoint or the user stepped)
                {
                    //handle hardware breakpoints
                    hActiveThread = EngineOpenThread(THREAD_GETSETSUSPEND, false, DBGEvent.dwThreadId);
                    myDBGContext.ContextFlags = CONTEXT_DEBUG_REGISTERS | ContextControlFlags;
                    GetThreadContext(hActiveThread, &myDBGContext);
                    if((ULONG_PTR)DBGEvent.u.Exception.ExceptionRecord.ExceptionAddress == myDBGContext.Dr0 || (myDBGContext.Dr6 & 0x1))
                    {
                        if(DebugRegister[0].DrxEnabled)
                        {
                            DBGCode = DBG_CONTINUE;
                            myDBGContext.EFlags |= UE_TRAP_FLAG;
                            SetThreadContext(hActiveThread, &myDBGContext);
                            myCustomHandler = (fCustomHandler)(DebugRegister[0].DrxCallBack);
                            myCustomHandler((void*)myDBGContext.Dr0);
                            if(DebugRegister[0].DrxEnabled)
                            {
                                memcpy(&DebugRegisterX, &DebugRegister[0], sizeof(HARDWARE_DATA));
                                DebugRegisterXId = UE_DR0;
                                DeleteHardwareBreakPoint(UE_DR0);
                                ResetHwBPX = true;
                            }
                            else
                            {
                                GetThreadContext(hActiveThread, &myDBGContext);
                                myDBGContext.EFlags &= ~UE_TRAP_FLAG;
                                SetThreadContext(hActiveThread, &myDBGContext);
                            }
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
                            myDBGContext.EFlags |= UE_TRAP_FLAG;
                            SetThreadContext(hActiveThread, &myDBGContext);
                            myCustomHandler = (fCustomHandler)(DebugRegister[1].DrxCallBack);
                            myCustomHandler((void*)myDBGContext.Dr1);
                            if(DebugRegister[1].DrxEnabled)
                            {
                                memcpy(&DebugRegisterX, &DebugRegister[1], sizeof(HARDWARE_DATA));
                                DebugRegisterXId = UE_DR1;
                                DeleteHardwareBreakPoint(UE_DR1);
                                ResetHwBPX = true;
                            }
                            else
                            {
                                GetThreadContext(hActiveThread, &myDBGContext);
                                myDBGContext.EFlags &= ~UE_TRAP_FLAG;
                                SetThreadContext(hActiveThread, &myDBGContext);
                            }
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
                            myDBGContext.EFlags |= UE_TRAP_FLAG;
                            SetThreadContext(hActiveThread, &myDBGContext);
                            myCustomHandler = (fCustomHandler)(DebugRegister[2].DrxCallBack);
                            myCustomHandler((void*)myDBGContext.Dr2);
                            if(DebugRegister[2].DrxEnabled)
                            {
                                memcpy(&DebugRegisterX, &DebugRegister[2], sizeof(HARDWARE_DATA));
                                DebugRegisterXId = UE_DR2;
                                DeleteHardwareBreakPoint(UE_DR2);
                                ResetHwBPX = true;
                            }
                            else
                            {
                                GetThreadContext(hActiveThread, &myDBGContext);
                                myDBGContext.EFlags &= ~UE_TRAP_FLAG;
                                SetThreadContext(hActiveThread, &myDBGContext);
                            }
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
                            myDBGContext.EFlags |= UE_TRAP_FLAG;
                            SetThreadContext(hActiveThread, &myDBGContext);
                            myCustomHandler = (fCustomHandler)(DebugRegister[3].DrxCallBack);
                            myCustomHandler((void*)myDBGContext.Dr3);
                            if(DebugRegister[3].DrxEnabled)
                            {
                                memcpy(&DebugRegisterX, &DebugRegister[3], sizeof(HARDWARE_DATA));
                                DebugRegisterXId = UE_DR3;
                                DeleteHardwareBreakPoint(UE_DR3);
                                ResetHwBPX = true;
                            }
                            else
                            {
                                GetThreadContext(hActiveThread, &myDBGContext);
                                myDBGContext.EFlags &= ~UE_TRAP_FLAG;
                                SetThreadContext(hActiveThread, &myDBGContext);
                            }
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
                    if(ResetHwBPX) //a hardware breakpoint was reached
                    {
                        ULONG_PTR ueCurrentPosition = GetContextData(UE_CIP);
                        unsigned char instr[16];
                        MemoryReadSafe(dbgProcessInformation.hProcess, (void*)ueCurrentPosition, instr, sizeof(instr), 0);
                        char* DisassembledString = (char*)StaticDisassembleEx(ueCurrentPosition, (LPVOID)instr);
                        if(strstr(DisassembledString, "PUSHF"))
                            PushfBPX = true;
                    }
                    engineStep();
                }
                if(DBGCode == DBG_EXCEPTION_NOT_HANDLED) //NOTE: only call the chSingleStep callback when the debuggee generated the exception
                {
                    if(DBGCustomHandler->chSingleStep != NULL)
                    {
                        myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chSingleStep);
                        myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                    }
                }
            }
            break;

            case STATUS_GUARD_PAGE_VIOLATION:
            {
                ULONG_PTR bpaddr;
                bool bFoundBreakPoint = false;
                BreakPointDetail FoundBreakPoint;
                int bpcount = (int)BreakPointBuffer.size();
                for(int i = 0; i < bpcount; i++)
                {
                    ULONG_PTR addr = BreakPointBuffer.at(i).BreakPointAddress;
                    bpaddr = (ULONG_PTR)DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[1]; //page accessed
                    if(bpaddr >= addr && bpaddr < (addr + BreakPointBuffer.at(i).BreakPointSize) &&
                            (BreakPointBuffer.at(i).BreakPointType == UE_MEMORY ||
                             BreakPointBuffer.at(i).BreakPointType == UE_MEMORY_READ ||
                             BreakPointBuffer.at(i).BreakPointType == UE_MEMORY_WRITE ||
                             BreakPointBuffer.at(i).BreakPointType == UE_MEMORY_EXECUTE) &&
                            BreakPointBuffer.at(i).BreakPointActive == UE_BPXACTIVE)
                    {
                        FoundBreakPoint = BreakPointBuffer.at(i);
                        bFoundBreakPoint = true;
                        break;
                    }
                }
                if(bFoundBreakPoint) //found memory breakpoint
                {
                    hActiveThread = EngineOpenThread(THREAD_GETSETSUSPEND, false, DBGEvent.dwThreadId);
                    myDBGContext.ContextFlags = ContextControlFlags;
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
                            myDBGContext.EFlags |= UE_TRAP_FLAG;
                            SetThreadContext(hActiveThread, &myDBGContext);
                            ResetMemBPXAddress = FoundBreakPoint.BreakPointAddress;
                            ResetMemBPXSize = FoundBreakPoint.BreakPointSize;
                            ResetMemBPX = true;
                        }
                        myCustomHandler = (fCustomHandler)(MemoryBpxCallBack);
                        myCustomHandler((void*)bpaddr);
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
                            myDBGContext.EFlags |= UE_TRAP_FLAG;
                            SetThreadContext(hActiveThread, &myDBGContext);
                            ResetMemBPXAddress = FoundBreakPoint.BreakPointAddress;
                            ResetMemBPXSize = FoundBreakPoint.BreakPointSize;
                            ResetMemBPX = true;
                        }
                        if(DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[0] == 0) //read operation
                        {
                            myCustomHandler = (fCustomHandler)(MemoryBpxCallBack);
                            myCustomHandler((void*)bpaddr);
                        }
                        else //no read operation, restore breakpoint
                        {
                            myDBGContext.EFlags |= UE_TRAP_FLAG;
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
                            myDBGContext.EFlags |= UE_TRAP_FLAG;
                            SetThreadContext(hActiveThread, &myDBGContext);
                            ResetMemBPXAddress = FoundBreakPoint.BreakPointAddress;
                            ResetMemBPXSize = FoundBreakPoint.BreakPointSize;
                            ResetMemBPX = true;
                        }
                        if(DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[0] == 1) //write operation
                        {
                            myCustomHandler = (fCustomHandler)(MemoryBpxCallBack);
                            myCustomHandler((void*)bpaddr);
                        }
                        else //no write operation, restore breakpoint
                        {
                            myDBGContext.EFlags |= UE_TRAP_FLAG;
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
                            if((DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[0] == 8 || DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[0] == 0) && //data execution prevention (DEP) violation
                                    (ULONG_PTR)DBGEvent.u.Exception.ExceptionRecord.ExceptionAddress == DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[1]) //exception address == read address
                                RemoveMemoryBPX(FoundBreakPoint.BreakPointAddress, FoundBreakPoint.BreakPointSize);
                        }
                        else
                        {
                            myDBGContext.EFlags |= UE_TRAP_FLAG;
                            SetThreadContext(hActiveThread, &myDBGContext);
                            ResetMemBPXAddress = FoundBreakPoint.BreakPointAddress;
                            ResetMemBPXSize = FoundBreakPoint.BreakPointSize;
                            ResetMemBPX = true;
                        }
                        if((DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[0] == 8 || DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[0] == 0) && //data execution prevention (DEP) violation
                                (ULONG_PTR)DBGEvent.u.Exception.ExceptionRecord.ExceptionAddress == DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[1]) //exception address == read address
                        {
                            myCustomHandler = (fCustomHandler)(MemoryBpxCallBack);
                            myCustomHandler((void*)bpaddr);
                        }
                        else //no execute operation, restore breakpoint
                        {
                            myDBGContext.EFlags |= UE_TRAP_FLAG;
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
                if(ResetMemBPX) //memory breakpoint hit
                {
                    ULONG_PTR ueCurrentPosition = GetContextData(UE_CIP);
                    unsigned char instr[16];
                    MemoryReadSafe(dbgProcessInformation.hProcess, (void*)ueCurrentPosition, instr, sizeof(instr), 0);
                    char* DisassembledString = (char*)StaticDisassembleEx(ueCurrentPosition, (LPVOID)instr);
                    if(strstr(DisassembledString, "PUSHF"))
                        PushfBPX = true;
                }

                //debuggee generated GUARD_PAGE exception
                if(DBGCode == DBG_EXCEPTION_NOT_HANDLED)
                {
                    //TODO: restore memory breakpoint?
                    if(DBGCustomHandler->chPageGuard != NULL)
                    {
                        myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chPageGuard);
                        myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                    }
                }
            }
            break;

            case STATUS_ACCESS_VIOLATION:
            {
                ULONG_PTR bpaddr;
                bool bFoundBreakPoint = false;
                bool bCallCustomHandler = false;
                BreakPointDetail FoundBreakPoint;
                int bpcount = (int)BreakPointBuffer.size();

                for(int i = 0; i < bpcount; i++)
                {
                    ULONG_PTR addr = BreakPointBuffer.at(i).BreakPointAddress;
                    bpaddr = (ULONG_PTR)DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[1]; //page accessed
                    if(bpaddr >= addr && bpaddr < (addr + BreakPointBuffer.at(i).BreakPointSize) &&
                            (BreakPointBuffer.at(i).BreakPointType == UE_MEMORY ||
                             BreakPointBuffer.at(i).BreakPointType == UE_MEMORY_READ ||
                             BreakPointBuffer.at(i).BreakPointType == UE_MEMORY_WRITE ||
                             BreakPointBuffer.at(i).BreakPointType == UE_MEMORY_EXECUTE) &&
                            BreakPointBuffer.at(i).BreakPointActive == UE_BPXACTIVE)
                    {
                        FoundBreakPoint = BreakPointBuffer.at(i);
                        bFoundBreakPoint = true;
                        break;
                    }
                }

                // Most of the logic has been copied from the STATUS_GUARD_PAGE_VIOLATION handler

                if(bFoundBreakPoint && engineMembpAlt) //found memory breakpoint
                {
                    hActiveThread = EngineOpenThread(THREAD_GETSETSUSPEND, false, DBGEvent.dwThreadId);
                    myDBGContext.ContextFlags = ContextControlFlags;
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
                            myDBGContext.EFlags |= UE_TRAP_FLAG;
                            SetThreadContext(hActiveThread, &myDBGContext);
                            ResetMemBPXAddress = FoundBreakPoint.BreakPointAddress;
                            ResetMemBPXSize = FoundBreakPoint.BreakPointSize;
                            ResetMemBPX = true;
                        }

                        bCallCustomHandler = true;
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
                            myDBGContext.EFlags |= UE_TRAP_FLAG;
                            SetThreadContext(hActiveThread, &myDBGContext);
                            ResetMemBPXAddress = FoundBreakPoint.BreakPointAddress;
                            ResetMemBPXSize = FoundBreakPoint.BreakPointSize;
                            ResetMemBPX = true;
                        }
                        if(DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[0] == 0) //read operation
                        {
                            bCallCustomHandler = true;
                        }
                        else //no read operation, restore breakpoint
                        {
                            myDBGContext.EFlags |= UE_TRAP_FLAG;
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
                            myDBGContext.EFlags |= UE_TRAP_FLAG;
                            SetThreadContext(hActiveThread, &myDBGContext);
                            ResetMemBPXAddress = FoundBreakPoint.BreakPointAddress;
                            ResetMemBPXSize = FoundBreakPoint.BreakPointSize;
                            ResetMemBPX = true;
                        }
                        if(DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[0] == 1) //write operation
                        {
                            bCallCustomHandler = true;
                        }
                        else //no write operation, restore breakpoint
                        {
                            myDBGContext.EFlags |= UE_TRAP_FLAG;
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
                            if((DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[0] == 8 || DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[0] == 0) && //data execution prevention (DEP) violation
                                    (ULONG_PTR)DBGEvent.u.Exception.ExceptionRecord.ExceptionAddress == DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[1]) //exception address == read address
                                RemoveMemoryBPX(FoundBreakPoint.BreakPointAddress, FoundBreakPoint.BreakPointSize);
                        }
                        else
                        {
                            myDBGContext.EFlags |= UE_TRAP_FLAG;
                            SetThreadContext(hActiveThread, &myDBGContext);
                            ResetMemBPXAddress = FoundBreakPoint.BreakPointAddress;
                            ResetMemBPXSize = FoundBreakPoint.BreakPointSize;
                            ResetMemBPX = true;
                        }
                        if((DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[0] == 8 || DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[0] == 0) && //data execution prevention (DEP) violation
                                (ULONG_PTR)DBGEvent.u.Exception.ExceptionRecord.ExceptionAddress == DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[1]) //exception address == read address
                        {
                            bCallCustomHandler = true;
                        }
                        else //no execute operation, restore breakpoint
                        {
                            myDBGContext.EFlags |= UE_TRAP_FLAG;
                            SetThreadContext(hActiveThread, &myDBGContext);
                            ResetMemBPXAddress = FoundBreakPoint.BreakPointAddress;
                            ResetMemBPXSize = FoundBreakPoint.BreakPointSize;
                            ResetMemBPX = true;
                        }
                    }

                    // If the breakpoint has to be restored...
                    if(ResetMemBPX)
                    {
                        // ...temporarily revert the PAGE_NOACCESS permission
                        VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)ResetMemBPXAddress,
                                         ResetMemBPXSize, FoundBreakPoint.OldProtect, &OldProtect);
                    }

                    // Call the custom memory breakpoint handler
                    if(bCallCustomHandler)
                    {
                        myCustomHandler = (fCustomHandler)(MemoryBpxCallBack);
                        myCustomHandler((void*)bpaddr);
                    }

                    EngineCloseHandle(hActiveThread);
                }
                else //no memory breakpoint found
                {
                    DBGCode = DBG_EXCEPTION_NOT_HANDLED;
                }
                if(ResetMemBPX) //memory breakpoint hit
                {
                    ULONG_PTR ueCurrentPosition = GetContextData(UE_CIP);
                    unsigned char instr[16];
                    MemoryReadSafe(dbgProcessInformation.hProcess, (void*)ueCurrentPosition, instr, sizeof(instr), 0);
                    char* DisassembledString = (char*)StaticDisassembleEx(ueCurrentPosition, (LPVOID)instr);
                    if(strstr(DisassembledString, "PUSHF"))
                        PushfBPX = true;
                }

                // Debuggee generated access violation exception
                if(DBGCode == DBG_EXCEPTION_NOT_HANDLED)
                {
                    if(DBGCustomHandler->chAccessViolation != NULL)
                    {
                        myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chAccessViolation);
                        myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                    }
                }
            }
            break;

            case STATUS_ILLEGAL_INSTRUCTION:
            {
                //UD2 breakpoint
                bool bFoundBreakPoint = false;
                BreakPointDetail FoundBreakPoint;
                int bpcount = (int)BreakPointBuffer.size();
                for(int i = 0; i < bpcount; i++)
                {
                    if(BreakPointBuffer.at(i).BreakPointAddress == (ULONG_PTR)DBGEvent.u.Exception.ExceptionRecord.ExceptionAddress &&
                            (BreakPointBuffer.at(i).BreakPointType == UE_BREAKPOINT || BreakPointBuffer.at(i).BreakPointType == UE_SINGLESHOOT) &&
                            BreakPointBuffer.at(i).BreakPointActive == UE_BPXACTIVE)
                    {
                        FoundBreakPoint = BreakPointBuffer.at(i);
                        bFoundBreakPoint = true;
                        break;
                    }
                }
                if(bFoundBreakPoint) //found ud2 breakpoint
                {
                    VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)FoundBreakPoint.BreakPointAddress, FoundBreakPoint.BreakPointSize, PAGE_EXECUTE_READWRITE, &OldProtect);
                    if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)FoundBreakPoint.BreakPointAddress, &FoundBreakPoint.OriginalByte[0], FoundBreakPoint.BreakPointSize, &NumberOfBytesReadWritten))
                    {
                        FlushInstructionCache(dbgProcessInformation.hProcess, NULL, 0);
                        DBGCode = DBG_CONTINUE;
                        hActiveThread = EngineOpenThread(THREAD_GETSETSUSPEND, false, DBGEvent.dwThreadId);
                        myDBGContext.ContextFlags = ContextControlFlags;
                        GetThreadContext(hActiveThread, &myDBGContext);
                        if(FoundBreakPoint.BreakPointType != UE_SINGLESHOOT)
                            myDBGContext.EFlags |= UE_TRAP_FLAG;
                        SetThreadContext(hActiveThread, &myDBGContext);
                        EngineCloseHandle(hActiveThread);
                        VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)FoundBreakPoint.BreakPointAddress, FoundBreakPoint.BreakPointSize, OldProtect, &OldProtect);

                        if(FoundBreakPoint.BreakPointType == UE_SINGLESHOOT)
                        {
                            DeleteBPX((ULONG_PTR)FoundBreakPoint.BreakPointAddress);
                            ResetBPXSize = FoundBreakPoint.BreakPointSize - 1;
                            ResetBPXAddressTo = NULL;
                            ResetBPX = false;
                        }

                        //execute callback
                        myCustomBreakPoint = (fCustomBreakPoint)((LPVOID)FoundBreakPoint.ExecuteCallBack);
                        myCustomBreakPoint();

                        if(FoundBreakPoint.BreakPointType != UE_SINGLESHOOT)
                        {
                            DisableBPX((ULONG_PTR)FoundBreakPoint.BreakPointAddress);
                            ResetBPXSize = FoundBreakPoint.BreakPointSize - 1;
                            ResetBPXAddressTo = (ULONG_PTR)FoundBreakPoint.BreakPointAddress;
                            ResetBPX = true;
                        }
                    }
                    else
                        VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)FoundBreakPoint.BreakPointAddress, FoundBreakPoint.BreakPointSize, OldProtect, &OldProtect);
                }
                else
                    DBGCode = DBG_EXCEPTION_NOT_HANDLED;

                //application-generated exception
                if(DBGCode == DBG_EXCEPTION_NOT_HANDLED)
                {
                    if(DBGCustomHandler->chIllegalInstruction != NULL)
                    {
                        myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chIllegalInstruction);
                        myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                    }
                }
            }
            break;

            case STATUS_NONCONTINUABLE_EXCEPTION:
            {
                if(DBGCustomHandler->chNonContinuableException != NULL)
                {
                    myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chNonContinuableException);
                    myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                }
            }
            break;

            case STATUS_ARRAY_BOUNDS_EXCEEDED:
            {
                if(DBGCustomHandler->chArrayBoundsException != NULL)
                {
                    myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chArrayBoundsException);
                    myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                }
            }
            break;

            case STATUS_FLOAT_DENORMAL_OPERAND:
            {
                if(DBGCustomHandler->chFloatDenormalOperand != NULL)
                {
                    myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chFloatDenormalOperand);
                    myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                }
            }
            break;

            case STATUS_FLOAT_DIVIDE_BY_ZERO:
            {
                if(DBGCustomHandler->chFloatDevideByZero != NULL)
                {
                    myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chFloatDevideByZero);
                    myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                }
            }
            break;

            case STATUS_INTEGER_DIVIDE_BY_ZERO:
            {
                if(DBGCustomHandler->chIntegerDevideByZero != NULL)
                {
                    myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chIntegerDevideByZero);
                    myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                }
            }
            break;

            case STATUS_INTEGER_OVERFLOW:
            {
                if(DBGCustomHandler->chIntegerOverflow != NULL)
                {
                    myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chIntegerOverflow);
                    myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                }
            }
            break;

            case STATUS_PRIVILEGED_INSTRUCTION:
            {
                if(DBGCustomHandler->chPrivilegedInstruction != NULL)
                {
                    myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chPrivilegedInstruction);
                    myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                }
            }
            break;
            }

            //general unhandled exception callback
            if(DBGCode == DBG_EXCEPTION_NOT_HANDLED)
            {
                if(engineExecutePluginCallBack)
                {
                    ExtensionManagerPluginDebugCallBack(&DBGEvent, UE_PLUGIN_CALL_REASON_UNHANDLEDEXCEPTION);
                }
                if(DBGCustomHandler->chUnhandledException != NULL)
                {
                    myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chUnhandledException);
                    myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                }
            }

            //general after-exception callback (includes debugger exceptions)
            if(DBGCustomHandler->chAfterException != NULL)
            {
                myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chAfterException);
                myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
            }
        }
        break;

        case RIP_EVENT:
        {
            DBGCode = DBG_EXCEPTION_NOT_HANDLED; //fix an anti-debug trick
            if(engineExecutePluginCallBack)
            {
                ExtensionManagerPluginDebugCallBack(&DBGEvent, UE_PLUGIN_CALL_REASON_UNHANDLEDEXCEPTION);
            }
            //rip event callback
            if(DBGCustomHandler->chRipEvent != NULL)
            {
                myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chRipEvent);
                myCustomHandler(&DBGEvent);
            }
        }
        break;
        }

        if(IsDbgReplyLaterSupported && DBGEvent.dwDebugEventCode != EXIT_THREAD_DEBUG_EVENT)
        {
            CONTEXT DbgCtx;

            DbgCtx.ContextFlags = ContextControlFlags;

            hActiveThread = EngineOpenThread(THREAD_GETSETSUSPEND, false, DBGEvent.dwThreadId);

            if(hActiveThread != NULL)
            {
                // If TF is set (single step), then suspend all the other threads
                if(GetThreadContext(hActiveThread, &DbgCtx) && (DbgCtx.EFlags & UE_TRAP_FLAG))
                {
                    ThreadBeingProcessed = DBGEvent.dwThreadId;

                    for(auto & Thread : hListThread)
                    {
                        if(ThreadBeingProcessed == Thread.dwThreadId)
                            continue;

                        // Check if the thread is already suspended
                        for(auto & SuspendedThread : SuspendedThreads)
                            if(SuspendedThread.dwThreadId == Thread.dwThreadId)
                                continue;

                        if(SuspendThread(Thread.hThread) != -1)
                            SuspendedThreads.push_back(Thread);
                    }
                }

                EngineCloseHandle(hActiveThread);
            }
        }

continue_dbg_event:

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
        if(engineProcessIsNowDetached)
        {
            DebugActiveProcessStop(dbgProcessInformation.dwProcessId);
            DebugAttachedToProcess = false;
            break;
        }
        if(!ThreaderGetThreadInfo(0, DBGEvent.dwThreadId)) //switch thread
            DBGEvent.dwThreadId = dbgProcessInformation.dwThreadId;
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
    DebuggerReset();
}

__declspec(dllexport) void TITCALL DebugLoopEx(DWORD TimeOut)
{
    SetDebugLoopTimeOut(TimeOut);
    DebugLoop();
    SetDebugLoopTimeOut(INFINITE);
}

__declspec(dllexport) void TITCALL SetDebugLoopTimeOut(DWORD TimeOut)
{
    __debugbreak();
}
