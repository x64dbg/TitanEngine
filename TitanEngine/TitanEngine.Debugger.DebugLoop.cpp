#include "stdafx.h"
#include "definitions.h"
#include "Global.Debugger.h"
#include "Global.Handle.h"
#include "Global.Engine.h"
#include "Global.Breakpoints.h"
#include "Global.Threader.h"
#include "Global.Librarian.h"
#include "Global.TLS.h"
#include <unordered_map>
#include <functional>

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
    PLIBRARY_ITEM_DATAW hLoadedLibData = NULL;
    PLIBRARY_BREAK_DATA ptrLibrarianData = NULL;
    typedef void(TITCALL * fCustomBreakPoint)(void);
    typedef void(TITCALL * fCustomHandler)(void* SpecialDBG);
    typedef void(TITCALL * fFindOEPHandler)(LPPROCESS_INFORMATION fProcessInfo, LPVOID fCallBack);
    fCustomHandler myCustomHandler;
    fCustomBreakPoint myCustomBreakPoint;
    SIZE_T ResetBPXSize = 0;
    ULONG_PTR ResetBPXAddressTo =  0;
    std::function<void()> ResetMemBpxCallback;
    ULONG_PTR NumberOfBytesReadWritten = 0;
    HANDLE hActiveThread;
    DWORD OldProtect;
    DWORD DebugRegisterXId = NULL;
    HARDWARE_DATA DebugRegisterX;
    wchar_t DLLDebugFileName[512];
    char szAnsiLibraryName[MAX_PATH];
    ULONG_PTR DLLPatchAddress;
    LPVOID DBGEntryPoint;

    wchar_t* szTranslatedNativeName;

    DWORD ThreadBeingProcessed = 0;
    std::unordered_map<DWORD, THREAD_ITEM_DATA> SuspendedThreads;
    bool IsDbgReplyLaterSupported = false;

    // Check if DBG_REPLY_LATER is supported based on Windows version (Windows 10, version 1507 or above)
    // https://www.gaijin.at/en/infos/windows-version-numbers
    const uint32_t NtBuildNumber = *(uint32_t*)(0x7FFE0000 + 0x260);
    if(NtBuildNumber != 0 && NtBuildNumber >= 10240)
    {
        IsDbgReplyLaterSupported = engineSafeStep;
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
    engineFileIsBeingDebugged = true;

    while(!BreakDBG) //actual debug loop
    {
        bool synchronizedStep = false;
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
                    for(auto & itr : SuspendedThreads)
                        ResumeThread(itr.second.hThread);

                    SuspendedThreads.clear();
                    ThreadBeingProcessed = 0;
                }
            }
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
                        CONTEXT myDBGContext;
                        myDBGContext.ContextFlags = ContextControlFlags;
                        GetThreadContext(hActiveThread, &myDBGContext);
                        if (FoundBreakPoint.BreakPointType != UE_SINGLESHOOT)
                        {
                            myDBGContext.EFlags |= UE_TRAP_FLAG;
                            synchronizedStep = true;
                        }
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
                    for(auto & itr : SuspendedThreads)
                        ResumeThread(itr.second.hThread);

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
                            {
                                hActiveThread = EngineOpenThread(THREAD_GETSETSUSPEND, false, DBGEvent.dwThreadId);
                                CONTEXT myDBGContext;
                                myDBGContext.ContextFlags = ContextControlFlags;
                                GetThreadContext(hActiveThread, &myDBGContext);
                                myDBGContext.EFlags |= UE_TRAP_FLAG;
                                synchronizedStep = true;
                                SetThreadContext(hActiveThread, &myDBGContext);
                                EngineCloseHandle(hActiveThread);
                            }
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
                        ResetMemBpxCallback();
                        engineStep();
                    }
                }
                else //no resetting needed (debugger reached hardware breakpoint or the user stepped)
                {
                    //handle hardware breakpoints
                    hActiveThread = EngineOpenThread(THREAD_GETSETSUSPEND, false, DBGEvent.dwThreadId);
                    CONTEXT myDBGContext;
                    myDBGContext.ContextFlags = CONTEXT_DEBUG_REGISTERS | ContextControlFlags;
                    GetThreadContext(hActiveThread, &myDBGContext);
                    if((ULONG_PTR)DBGEvent.u.Exception.ExceptionRecord.ExceptionAddress == myDBGContext.Dr0 || (myDBGContext.Dr6 & 0x1))
                    {
                        if(DebugRegister[0].DrxEnabled)
                        {
                            DBGCode = DBG_CONTINUE;
                            {
                                myDBGContext.EFlags |= UE_TRAP_FLAG;
                                synchronizedStep = true;
                                SetThreadContext(hActiveThread, &myDBGContext);
                            }
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
                            {
                                myDBGContext.EFlags |= UE_TRAP_FLAG;
                                synchronizedStep = true;
                                SetThreadContext(hActiveThread, &myDBGContext);
                            }
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
                            {
                                myDBGContext.EFlags |= UE_TRAP_FLAG;
                                synchronizedStep = true;
                                SetThreadContext(hActiveThread, &myDBGContext);
                            }
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
                            {
                                myDBGContext.EFlags |= UE_TRAP_FLAG;
                                synchronizedStep = true;
                                SetThreadContext(hActiveThread, &myDBGContext);
                            }
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
            case STATUS_ACCESS_VIOLATION:
            {
                //  Plan (making sure the breakpoint is valid):
                // 1) Check if one of our BPs falls into the access address
                // 2) Check if this breakpoint is of the right type (READ, WRITE, etc)
                // 3) Somehow check if the exception wasn't maliciosly caused by the debugged program
                // 4) If all are true (i.e. the BP is ours):
                //      call the user callback, restore the original protection, single-step, put our protection back
                //    if not:
                //      - don't call the user callback
                //      - restore the protection if there are still our BPs on this page OR pass the exception to the debuggee

                DBGCode = DBG_EXCEPTION_NOT_HANDLED;
                ResetMemBPX = false;
                bool bCallUserCallback = false; // when we hit a correct BP

                // Access Types: 0 - read, 1 - write, 8 - execute (dep violation)
                ULONG_PTR accessType = DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[0];
                ULONG_PTR accessAddr = DBGEvent.u.Exception.ExceptionRecord.ExceptionInformation[1];
                ULONG_PTR currentPageAddr = ALIGN_DOWN_BY(accessAddr, TITANENGINE_PAGESIZE);
                bool isAccessViolation = DBGEvent.u.Exception.ExceptionRecord.ExceptionCode == STATUS_ACCESS_VIOLATION;


                // Part 1.
                // Find the breakpoint which was hit (if any)
                bool bFoundBreakPoint = false;
                BreakPointDetail foundBreakPoint;
                size_t bpcount = BreakPointBuffer.size();
                for(size_t i = 0; i < bpcount; i++)
                {
                    ULONG_PTR bpAddr = BreakPointBuffer.at(i).BreakPointAddress;
                    auto bpType = BreakPointBuffer.at(i).BreakPointType;
                    bool isMemBp = bpType == UE_MEMORY || bpType == UE_MEMORY_READ || bpType == UE_MEMORY_WRITE || bpType == UE_MEMORY_EXECUTE;
                    bool isActive = BreakPointBuffer.at(i).BreakPointActive == UE_BPXACTIVE;

                    if(isActive && isMemBp && accessAddr >= bpAddr && accessAddr < (bpAddr + BreakPointBuffer.at(i).BreakPointSize))
                    {
                        foundBreakPoint = BreakPointBuffer.at(i);
                        bFoundBreakPoint = true;
                        break;
                    }
                }

                auto hitPage = MemoryBreakpointPages.find(currentPageAddr);
                if(!bFoundBreakPoint)
                {
                    // There were no BPs at the accessed address.
                    // But this page may still contain our BPs somewhere else
                    if(hitPage != MemoryBreakpointPages.end())
                    {
                        // There is a breakpoint! Maybe it caused this exception?
                        // We should restore the page protection and continue execution.
                        ResetMemBPX = true;
                    }
                    else
                    {
                        // There are no breakpoints (our BP could not cause this exception).
                        // So don't do anything at all and pass the exception to the debuggee.
                    }
                }
                else if(hitPage == MemoryBreakpointPages.end())
                {
                    // Inconsistent page data; should never happen
                }
                else
                {
                    // The debuggee actually hit one of our breakpoints
                    MemoryBreakpointPageDetail pageData = hitPage->second;

                    // Part 2.
                    // Ensure that the access type was correct.
                    bool isCorrectAccessType = false;
                    switch(foundBreakPoint.BreakPointType)
                    {
                    case UE_MEMORY: // READ | WRITE | EXECUTE
                        isCorrectAccessType = true; // all access types are fine
                        break;
                    case UE_MEMORY_READ:
                        isCorrectAccessType = accessType == 0; // READ
                        break;
                    case UE_MEMORY_WRITE:
                        isCorrectAccessType = accessType == 1; // WRITE
                        break;
                    case UE_MEMORY_EXECUTE:
                        isCorrectAccessType = (accessType == 8 || accessType == 0) // EXECUTE or READ (when DEP is disabled/unsupported?)
                                              && accessAddr == (ULONG_PTR)DBGEvent.u.Exception.ExceptionRecord.ExceptionAddress;
                        break;
                    default:
                        isCorrectAccessType = false; // unreachable
                        break;
                    }

                    // Part 2.5.
                    // Maybe the debuggee intentially generated this exception OR changed the page protection?
                    //  In that case we shouldn't handle the exception.
                    //
                    // Sanity checks: the type of the exception loosely corresponds to the page protection we originally set.
                    bool bpTypeIsGuardPage = (pageData.newProtect & PAGE_GUARD) != 0;
                    if(bpTypeIsGuardPage && isAccessViolation || !bpTypeIsGuardPage && !isAccessViolation)
                    {
                        // We wouldn't make a BP with this kind of protection. Pass the exception to the debuggee.
                    }
                    else if(isAccessViolation  // STATUS_ACCESS_VIOLATION
                            && (accessType == 1 /*WRITE*/ && pageData.writeBps == 0 || accessType == 8 /*EXECUTE*/ && pageData.executeBps == 0)
                            && (pageData.newProtect & 0xFF) != PAGE_NOACCESS)
                    {
                        // The STATUS_ACCESS_VIOLATION exception was on Write (or Execute), but there is no BP on Write (or Execute).
                        // Probably the debuggee directly caused the exception. Don't handle it.
                    }
                    else if(!isAccessViolation  // STATUS_GUARD_PAGE_VIOLATION
                            && pageData.accessBps == 0 && pageData.readBps == 0     // no ACCESS and READ bps
                            && (pageData.executeBps == 0 || !bpTypeIsGuardPage))    // no EXECUTE bps (when implemented via guard pages)
                    {
                        // The STATUS_GUARD_PAGE_VIOLATION exception was within a page that had no BPs on READ, ACCESS,
                        //  and EXECUTE (and DEP is disabled, otherwise we wouldn't use the guard pages). Pass it on.
                    }
                    else if(!isCorrectAccessType)
                    {
                        // The access type was wrong, i.e. this is not "exactly" our breakpoint.
                        // Potentially, we could get here from our BP (e.g. by writing into a page with only a READ bp)
                        // Restore the protection and move on.
                        ResetMemBPX = true;
                    }
                    else
                    {
                        // Part 3.
                        // This was indeed our breakpoint, and of the right type, too. We can call the user callback now.
                        bCallUserCallback = true;

                        if(!foundBreakPoint.MemoryBpxRestoreOnHit)
                        {
                            // BP was singleshot and should be removed
                            RemoveMemoryBPX(foundBreakPoint.BreakPointAddress, foundBreakPoint.BreakPointSize);
                        }

                        // Even though this breakpoint might be singleshot, we still temporarily remove the protection
                        //  because there can be other breakpoints on this page that won't let us execute the current instruction normally
                        ResetMemBPX = true;
                    }
                }

                // Part 4
                //
                // At this point, if we want to restore the breakpoint, we should temporarily put the original
                // protection back. The problem is that the original protection might not allow us to continue execution
                // (e.g. when we put a WRITE bp on a page originally marked READONLY). In some cases, it may lead to
                // an infinite loop (single-stepping might fail and call this handler, which will try to automatically
                // single-step again and end up at this exact place, and so on). So if we are sure that resetting the BP is not a good idea,
                // we just pass the exception on. Or maybe it's better to set PAGE_EXECUTE_READWRITE and simply continue?
                DWORD originalProtect = hitPage->second.origProtect;
                if(ResetMemBPX && (bCallUserCallback || IsMemoryAccessAllowed(originalProtect, accessType)))
                {
                    // Mini Plan:
                    // 1) Set a protection option that would allow us to normally execute the instruction that caused this exception
                    // 2) Single-step (execute the instruction)
                    // 3) Restore the previous protection (i.e. our memory breakpoint)

                    VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)currentPageAddr, TITANENGINE_PAGESIZE, originalProtect, &OldProtect);

                    if(bCallUserCallback)
                    {
                        myCustomHandler = (fCustomHandler)(foundBreakPoint.ExecuteCallBack);
                        myCustomHandler((void*)accessAddr);
                    }

                    ResetMemBpxCallback = [currentPageAddr]
                    {
                        // We have successfully executed the instruction!
                        // But by this point the breakpoint could have been removed in a callback.
                        // We should check if it's still here (or some of our other breakpoints),
                        //  otherwise there's no need to restore the protection.

                        auto hitPage = MemoryBreakpointPages.find(currentPageAddr);
                        if(hitPage != MemoryBreakpointPages.end())
                        {
                            // The BP still exists OR it's been removed and a new one added
                            auto & pageData = hitPage->second;
                            DWORD oldProtect = 0;
                            VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)currentPageAddr, TITANENGINE_PAGESIZE, pageData.newProtect, &oldProtect);
                        }
                    };

                    // We've handled the exception
                    DBGCode = DBG_CONTINUE;

                    // Use the trap flag to schedule the page protection restoration on the next single-step event
                    synchronizedStep = true;
                    hActiveThread = EngineOpenThread(THREAD_GETSETSUSPEND, false, DBGEvent.dwThreadId);
                    CONTEXT myDBGContext;
                    myDBGContext.ContextFlags = ContextControlFlags;
                    GetThreadContext(hActiveThread, &myDBGContext);
                    myDBGContext.EFlags |= UE_TRAP_FLAG;
                    SetThreadContext(hActiveThread, &myDBGContext);
                    EngineCloseHandle(hActiveThread);

                    // Prevent the trap flag from leaking to the stack (by erasing it right after executing PUSHF)
                    ULONG_PTR ueCurrentPosition = GetContextData(UE_CIP);
                    unsigned char instr[16];
                    MemoryReadSafe(dbgProcessInformation.hProcess, (void*)ueCurrentPosition, instr, sizeof(instr), nullptr);
                    char* DisassembledString = (char*)StaticDisassembleEx(ueCurrentPosition, (LPVOID)instr);
                    if(strstr(DisassembledString, "PUSHF"))
                        PushfBPX = true;
                }


                // Debuggee generated the GUARD_PAGE or ACCESS_VIOLATION exception
                if(DBGCode == DBG_EXCEPTION_NOT_HANDLED)
                {
                    if(isAccessViolation)
                    {
                        if(DBGCustomHandler->chAccessViolation != NULL)
                        {
                            myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chAccessViolation);
                            myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                        }
                    }
                    else
                    {
                        if(DBGCustomHandler->chPageGuard != NULL)
                        {
                            myCustomHandler = (fCustomHandler)((LPVOID)DBGCustomHandler->chPageGuard);
                            myCustomHandler(&DBGEvent.u.Exception.ExceptionRecord);
                        }
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

                        {
                            hActiveThread = EngineOpenThread(THREAD_GETSETSUSPEND, false, DBGEvent.dwThreadId);
                            CONTEXT myDBGContext;
                            myDBGContext.ContextFlags = ContextControlFlags;
                            GetThreadContext(hActiveThread, &myDBGContext);
                            if (FoundBreakPoint.BreakPointType != UE_SINGLESHOOT)
                            {
                                myDBGContext.EFlags |= UE_TRAP_FLAG;
                                synchronizedStep = true;
                            }
                            SetThreadContext(hActiveThread, &myDBGContext);
                            EngineCloseHandle(hActiveThread);
                        }

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
            hActiveThread = EngineOpenThread(THREAD_GETSETSUSPEND, false, DBGEvent.dwThreadId);
            if(hActiveThread != NULL)
            {
                // If TF is set (single step), then suspend all the other threads
                if(synchronizedStep)
                {
                    ThreadBeingProcessed = DBGEvent.dwThreadId;

                    for(auto & Thread : hListThread)
                    {
                        // Do not suspend the current thread
                        if(ThreadBeingProcessed == Thread.dwThreadId)
                            continue;

                        // Check if the thread is already suspended
                        if (SuspendedThreads.count(Thread.dwThreadId) != 0)
                            continue;

                        if (SuspendThread(Thread.hThread) != -1)
                            SuspendedThreads.emplace(Thread.dwThreadId, Thread);
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
