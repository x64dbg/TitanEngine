#include "stdafx.h"
#include "definitions.h"
#include "Global.Debugger.h"
#include "Global.Threader.h"
#include "Global.Engine.h"
#include "Global.Handle.h"
#include "Global.Mapping.h"

// Global.Engine.Hooks:
static std::vector<HOOK_ENTRY> hookEntry;
static DWORD buffPatchedEntrySize = 0x3000;
static void* CwpBuffPatchedEntry;
static void* buffPatchedEntry;

// Internal.Engine.Hook.functions:
static bool ProcessHookScanAddNewHook(PHOOK_ENTRY HookDetails, void* ptrOriginalInstructions, PLIBRARY_ITEM_DATAW ModuleInformation, DWORD SizeOfImage)
{
    HOOK_ENTRY MyhookEntry = {};

    RtlMoveMemory(&MyhookEntry, HookDetails, sizeof HOOK_ENTRY);
    hookEntry.push_back(MyhookEntry);
    return true;
}

// Global.Engine.Hook.functions:
__declspec(dllexport) bool TITCALL HooksSafeTransitionEx(LPVOID HookAddressArray, int NumberOfHooks, bool TransitionStart)
{
    if(dbgProcessInformation.hProcess == NULL) //TODO: check
    {
        if(!TransitionStart || ThreaderImportRunningThreadData(GetCurrentProcessId()))
        {
            int threadcount = (int)hListThread.size();
            for(int i = 0; i < threadcount; i++)
            {
                PTHREAD_ITEM_DATA hListThreadPtr = &hListThread.at(i);
                if(hListThreadPtr->hThread != INVALID_HANDLE_VALUE)
                {
                    if(TransitionStart)
                    {
                        if(hListThreadPtr->dwThreadId != GetCurrentThreadId())
                        {
                            SuspendThread(hListThreadPtr->hThread);
                            ULONG_PTR CurrentIP = (ULONG_PTR)GetContextDataEx(hListThreadPtr->hThread, UE_CIP);
                            PMEMORY_COMPARE_HANDLER myHookAddressArray = (PMEMORY_COMPARE_HANDLER)HookAddressArray;
                            for(int j = 0; j < NumberOfHooks; j++)
                            {
#if defined (_WIN64)
                                ULONG_PTR HookAddress = (ULONG_PTR)myHookAddressArray->Array.qwArrayEntry[0];
                                myHookAddressArray = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)myHookAddressArray + sizeof ULONG_PTR);
#else
                                ULONG_PTR HookAddress = (ULONG_PTR)myHookAddressArray->Array.dwArrayEntry[0];
                                myHookAddressArray = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)myHookAddressArray + sizeof ULONG_PTR);
#endif
                                while(CurrentIP >= (ULONG_PTR)HookAddress && CurrentIP <= (ULONG_PTR)HookAddress + 5)
                                {
                                    ResumeThread(hListThreadPtr->hThread);
                                    Sleep(5);
                                    SuspendThread(hListThreadPtr->hThread);
                                    CurrentIP = (ULONG_PTR)GetContextDataEx(hListThreadPtr->hThread, UE_CIP);
                                    j = 0;
                                }
                            }
                        }
                    }
                    else
                    {
                        ResumeThread(hListThreadPtr->hThread);
                        EngineCloseHandle(hListThreadPtr->hThread);
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
    return false;
}

__declspec(dllexport) bool TITCALL HooksSafeTransition(LPVOID HookAddress, bool TransitionStart)
{
    void* aHookAddress[1];
    aHookAddress[0] = HookAddress;

    return(HooksSafeTransitionEx(&aHookAddress[0], sizeof aHookAddress, TransitionStart));
}

__declspec(dllexport) bool TITCALL HooksIsAddressRedirected(LPVOID HookAddress)
{
    for(unsigned int i = 0; i < hookEntry.size(); i++)
    {
        if(hookEntry[i].HookAddress == HookAddress && hookEntry[i].IATHook == false && hookEntry[i].HookIsEnabled == true)
        {
            return true;
        }
    }
    return false;
}

__declspec(dllexport) void* TITCALL HooksGetTrampolineAddress(LPVOID HookAddress)
{
    for(unsigned int i = 0; i < hookEntry.size(); i++)
    {
        if(hookEntry[i].HookAddress == HookAddress)
        {
            return(hookEntry[i].PatchedEntry);
        }
    }
    return(NULL);
}

__declspec(dllexport) void* TITCALL HooksGetHookEntryDetails(LPVOID HookAddress)
{
    for(unsigned int i = 0; i < hookEntry.size(); i++)
    {
        if(hookEntry[i].HookAddress == HookAddress)
        {
            return(&hookEntry[i]);
        }
    }
    return(NULL);
}

__declspec(dllexport) bool TITCALL HooksInsertNewRedirection(LPVOID HookAddress, LPVOID RedirectTo, int HookType)
{
#if !defined(_WIN64)
    int j;
    unsigned int i;
#endif
    HOOK_ENTRY myHook = {};
    DWORD CalculatedRealingJump;
    ULONG_PTR x64CalculatedRealingJump;
    ULONG_PTR RealignAddressTarget;
    int ProcessedBufferSize = NULL;
    int CurrentInstructionSize = NULL;
    PMEMORY_COMPARE_HANDLER WriteMemory = (PMEMORY_COMPARE_HANDLER)CwpBuffPatchedEntry;
    PMEMORY_COMPARE_HANDLER CompareMemory;
#if !defined(_WIN64)
    PMEMORY_COMPARE_HANDLER RelocateMemory;
#endif
    void* cHookAddress = HookAddress;
    DWORD OldProtect = PAGE_READONLY;
    void* TempBuffPatchedEntry;
    bool returnData;

    x64CalculatedRealingJump = NULL;
    if(buffPatchedEntry == NULL || (ULONG_PTR)CwpBuffPatchedEntry - (ULONG_PTR)buffPatchedEntry + TEE_MAXIMUM_HOOK_SIZE > buffPatchedEntrySize)
    {
        buffPatchedEntrySize = buffPatchedEntrySize + 0x1000;
        CwpBuffPatchedEntry = (void*)((ULONG_PTR)CwpBuffPatchedEntry - (ULONG_PTR)buffPatchedEntry);
        TempBuffPatchedEntry = VirtualAlloc(NULL, buffPatchedEntrySize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if(TempBuffPatchedEntry != NULL)
        {
            if(hookEntry.size() > NULL)
            {
                RtlMoveMemory(TempBuffPatchedEntry, buffPatchedEntry, (ULONG_PTR)CwpBuffPatchedEntry);
            }
#if !defined(_WIN64)
            for(i = 0; i < hookEntry.size(); i++)
            {
                hookEntry[i].PatchedEntry = (void*)((ULONG_PTR)hookEntry[i].PatchedEntry - (ULONG_PTR)buffPatchedEntry + (ULONG_PTR)TempBuffPatchedEntry);
                CalculatedRealingJump = (DWORD)((ULONG_PTR)hookEntry[i].PatchedEntry - (ULONG_PTR)hookEntry[i].HookAddress - 5);
                RtlMoveMemory(&hookEntry[i].HookBytes[1], &CalculatedRealingJump, 4);
                if(hookEntry[i].RelocationCount > NULL)
                {
                    for(j = 0; j < hookEntry[i].RelocationCount; j++)
                    {
                        CompareMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)buffPatchedEntry + hookEntry[i].RelocationInfo[j]);
                        RelocateMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)TempBuffPatchedEntry + hookEntry[i].RelocationInfo[j]);
                        CurrentInstructionSize = StaticLengthDisassemble((void*)CompareMemory);
                        RealignAddressTarget = (ULONG_PTR)GetJumpDestination(GetCurrentProcess(), (ULONG_PTR)CompareMemory);
                        if(RealignAddressTarget != NULL)
                        {
                            if(CompareMemory->Array.bArrayEntry[0] == 0xE9 && CurrentInstructionSize == 5)
                            {
                                CalculatedRealingJump = (DWORD)((ULONG_PTR)RealignAddressTarget - (ULONG_PTR)RelocateMemory - CurrentInstructionSize);
                                RtlMoveMemory(&RelocateMemory->Array.bArrayEntry[1], &CalculatedRealingJump, sizeof CalculatedRealingJump);
                            }
                            else if(CompareMemory->Array.bArrayEntry[0] >= 0x70 && CompareMemory->Array.bArrayEntry[0] <= 0x7F && CurrentInstructionSize == 2)
                            {
                                CalculatedRealingJump = (DWORD)((ULONG_PTR)RealignAddressTarget - (ULONG_PTR)RelocateMemory - CurrentInstructionSize);
                                RtlMoveMemory(&RelocateMemory->Array.bArrayEntry[2], &CalculatedRealingJump, sizeof CalculatedRealingJump);
                            }
                            else if(CompareMemory->Array.bArrayEntry[0] == 0x0F && CompareMemory->Array.bArrayEntry[1] >= 0x80 && CompareMemory->Array.bArrayEntry[1] <= 0x8F && CurrentInstructionSize == 6)
                            {
                                CalculatedRealingJump = (DWORD)((ULONG_PTR)RealignAddressTarget - (ULONG_PTR)RelocateMemory - CurrentInstructionSize);
                                RtlMoveMemory(&RelocateMemory->Array.bArrayEntry[2], &CalculatedRealingJump, sizeof CalculatedRealingJump);
                            }
                            else if(CompareMemory->Array.bArrayEntry[0] == 0xE8 && CurrentInstructionSize == 5)
                            {
                                CalculatedRealingJump = (DWORD)((ULONG_PTR)RealignAddressTarget - (ULONG_PTR)RelocateMemory - CurrentInstructionSize);
                                RtlMoveMemory(&RelocateMemory->Array.bArrayEntry[1], &CalculatedRealingJump, sizeof CalculatedRealingJump);
                            }
                        }
                    }
                }
            }
#endif
            if(hookEntry.size() > NULL)
            {
                VirtualFree(buffPatchedEntry, NULL, MEM_RELEASE);
            }
            CwpBuffPatchedEntry = (void*)((ULONG_PTR)CwpBuffPatchedEntry + (ULONG_PTR)TempBuffPatchedEntry);
            WriteMemory = (PMEMORY_COMPARE_HANDLER)CwpBuffPatchedEntry;
            buffPatchedEntry = TempBuffPatchedEntry;
        }
    }
    while(ProcessedBufferSize < TEE_MAXIMUM_HOOK_INSERT_SIZE)
    {
        CompareMemory = (PMEMORY_COMPARE_HANDLER)cHookAddress;
        CurrentInstructionSize = StaticLengthDisassemble(cHookAddress);
        RealignAddressTarget = (ULONG_PTR)GetJumpDestination(GetCurrentProcess(), (ULONG_PTR)cHookAddress);
        if(RealignAddressTarget != NULL)
        {
            if(CompareMemory->Array.bArrayEntry[0] == 0xE9 && CurrentInstructionSize == 5)
            {
                if(cHookAddress == HookAddress)
                {
                    if(HooksIsAddressRedirected(HookAddress))
                    {
                        if(HooksRemoveRedirection(HookAddress, false))
                        {
                            returnData = HooksInsertNewRedirection(HookAddress, RedirectTo, HookType);
                            if(returnData)
                            {
                                return true;
                            }
                            else
                            {
                                return false;
                            }
                        }
                    }
                }
                CalculatedRealingJump = (DWORD)((ULONG_PTR)RealignAddressTarget - (ULONG_PTR)WriteMemory - CurrentInstructionSize);
                WriteMemory->Array.bArrayEntry[0] = 0xE9;
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[1], &CalculatedRealingJump, sizeof CalculatedRealingJump);
                myHook.RelocationInfo[myHook.RelocationCount] = (DWORD)((ULONG_PTR)WriteMemory - (ULONG_PTR)buffPatchedEntry);
                WriteMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)WriteMemory + CurrentInstructionSize);
                myHook.RelocationCount++;
            }
            else if(CompareMemory->Array.bArrayEntry[0] == 0xEB && CurrentInstructionSize == 2)
            {
                CalculatedRealingJump = (DWORD)((ULONG_PTR)RealignAddressTarget - (ULONG_PTR)WriteMemory - 5);
                WriteMemory->Array.bArrayEntry[0] = 0xE9;
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[1], &CalculatedRealingJump, sizeof CalculatedRealingJump);
                myHook.RelocationInfo[myHook.RelocationCount] = (DWORD)((ULONG_PTR)WriteMemory - (ULONG_PTR)buffPatchedEntry);
                WriteMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)WriteMemory + 5);
                myHook.RelocationCount++;
            }
            else if(CompareMemory->Array.bArrayEntry[0] >= 0x70 && CompareMemory->Array.bArrayEntry[0] <= 0x7F && CurrentInstructionSize == 2)
            {
#if !defined(_WIN64)
                CalculatedRealingJump = (DWORD)((ULONG_PTR)RealignAddressTarget - (ULONG_PTR)WriteMemory - 6);
                WriteMemory->Array.bArrayEntry[0] = 0x0F;
                WriteMemory->Array.bArrayEntry[1] = CompareMemory->Array.bArrayEntry[0] + 0x10;
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[2], &CalculatedRealingJump, sizeof CalculatedRealingJump);
                myHook.RelocationInfo[myHook.RelocationCount] = (DWORD)((ULONG_PTR)WriteMemory - (ULONG_PTR)buffPatchedEntry);
                WriteMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)WriteMemory + 6);
                myHook.RelocationCount++;
#else
                x64CalculatedRealingJump = RealignAddressTarget;
                WriteMemory->Array.bArrayEntry[0] = CompareMemory->Array.bArrayEntry[0];
                WriteMemory->Array.bArrayEntry[1] = 0x02;
                WriteMemory->Array.bArrayEntry[2] = 0xEB;
                WriteMemory->Array.bArrayEntry[3] = 0x0E;
                WriteMemory->Array.bArrayEntry[4] = 0xFF;
                WriteMemory->Array.bArrayEntry[5] = 0x25;
                RtlZeroMemory(&WriteMemory->Array.bArrayEntry[6], 4);
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[10], &x64CalculatedRealingJump, sizeof x64CalculatedRealingJump);
                WriteMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)WriteMemory + 18);
#endif
            }
            else if(CompareMemory->Array.bArrayEntry[0] == 0x0F && CompareMemory->Array.bArrayEntry[1] >= 0x80 && CompareMemory->Array.bArrayEntry[1] <= 0x8F && CurrentInstructionSize == 6)
            {
#if !defined(_WIN64)
                CalculatedRealingJump = (DWORD)((ULONG_PTR)RealignAddressTarget - (ULONG_PTR)WriteMemory - CurrentInstructionSize);
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[0], &CompareMemory->Array.bArrayEntry[0], 2);
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[2], &CalculatedRealingJump, sizeof CalculatedRealingJump);
                myHook.RelocationInfo[myHook.RelocationCount] = (DWORD)((ULONG_PTR)WriteMemory - (ULONG_PTR)buffPatchedEntry);
                WriteMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)WriteMemory + CurrentInstructionSize);
                myHook.RelocationCount++;
#else
                x64CalculatedRealingJump = RealignAddressTarget;
                WriteMemory->Array.bArrayEntry[0] = CompareMemory->Array.bArrayEntry[0];
                WriteMemory->Array.bArrayEntry[1] = CompareMemory->Array.bArrayEntry[1];
                WriteMemory->Array.bArrayEntry[2] = 0x02;
                WriteMemory->Array.bArrayEntry[3] = 0x00;
                WriteMemory->Array.bArrayEntry[4] = 0x00;
                WriteMemory->Array.bArrayEntry[5] = 0x00;
                WriteMemory->Array.bArrayEntry[6] = 0xEB;
                WriteMemory->Array.bArrayEntry[7] = 0x0E;
                WriteMemory->Array.bArrayEntry[8] = 0xFF;
                WriteMemory->Array.bArrayEntry[9] = 0x25;
                RtlZeroMemory(&WriteMemory->Array.bArrayEntry[10], 4);
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[14], &x64CalculatedRealingJump, sizeof x64CalculatedRealingJump);
                WriteMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)WriteMemory + 22);
#endif
            }
            else if(CompareMemory->Array.bArrayEntry[0] == 0xE8 && CurrentInstructionSize == 5)
            {
                CalculatedRealingJump = (DWORD)((ULONG_PTR)RealignAddressTarget - (ULONG_PTR)WriteMemory - CurrentInstructionSize);
                WriteMemory->Array.bArrayEntry[0] = 0xE8;
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[1], &CalculatedRealingJump, sizeof CalculatedRealingJump);
                myHook.RelocationInfo[myHook.RelocationCount] = (DWORD)((ULONG_PTR)WriteMemory - (ULONG_PTR)buffPatchedEntry);
                WriteMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)WriteMemory + CurrentInstructionSize);
                myHook.RelocationCount++;
#if defined(_WIN64)
            }
            else if(CompareMemory->Array.bArrayEntry[0] == 0xFF && (CompareMemory->Array.bArrayEntry[1] == 0x15 || CompareMemory->Array.bArrayEntry[1] == 0x25) && CurrentInstructionSize == 6)
            {
                CalculatedRealingJump = (DWORD)((ULONG_PTR)RealignAddressTarget - (ULONG_PTR)WriteMemory - CurrentInstructionSize);
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[0], &CompareMemory->Array.bArrayEntry[0], 2);
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[2], &CalculatedRealingJump, sizeof CalculatedRealingJump);
                WriteMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)WriteMemory + CurrentInstructionSize);
#endif
            }
            else
            {
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[0], cHookAddress, CurrentInstructionSize);
                WriteMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)WriteMemory + CurrentInstructionSize);
            }
        }
        else
        {
            RtlMoveMemory(&WriteMemory->Array.bArrayEntry[0], cHookAddress, CurrentInstructionSize);
            WriteMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)WriteMemory + CurrentInstructionSize);
        }
        cHookAddress = (void*)((ULONG_PTR)cHookAddress + CurrentInstructionSize);
        ProcessedBufferSize = ProcessedBufferSize + CurrentInstructionSize;
    }
    if(ProcessedBufferSize >= TEE_MAXIMUM_HOOK_INSERT_SIZE)
    {
        WriteMemory->Array.bArrayEntry[0] = 0xFF;
        WriteMemory->Array.bArrayEntry[1] = 0x25;
#if !defined(_WIN64)
        CalculatedRealingJump = (DWORD)((ULONG_PTR)WriteMemory + 6);
#else
        CalculatedRealingJump = NULL;
#endif
        RtlMoveMemory(&WriteMemory->Array.bArrayEntry[2], &CalculatedRealingJump, sizeof CalculatedRealingJump);
        RtlMoveMemory(&WriteMemory->Array.bArrayEntry[6], &cHookAddress, sizeof CalculatedRealingJump);
        WriteMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)WriteMemory + 6 + sizeof ULONG_PTR);
        myHook.HookIsEnabled = true;
        myHook.HookType = (BYTE)HookType;
        myHook.HookAddress = HookAddress;
        myHook.RedirectionAddress = RedirectTo;
        myHook.PatchedEntry = CwpBuffPatchedEntry;
        myHook.HookSize = TEE_MAXIMUM_HOOK_SIZE;
        RtlMoveMemory(&myHook.OriginalBytes[0], HookAddress, TEE_MAXIMUM_HOOK_SIZE);
        CalculatedRealingJump = (DWORD)((ULONG_PTR)RedirectTo - (ULONG_PTR)HookAddress);
        CwpBuffPatchedEntry = (void*)((ULONG_PTR)WriteMemory);
        WriteMemory = (PMEMORY_COMPARE_HANDLER)HookAddress;
        if(HookType == TEE_HOOK_NRM_JUMP)
        {
#if !defined(_WIN64)
            CalculatedRealingJump = CalculatedRealingJump - 5;
            if(VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
            {
                WriteMemory->Array.bArrayEntry[0] = 0xE9;
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[1], &CalculatedRealingJump, sizeof CalculatedRealingJump);
                RtlMoveMemory(&myHook.HookBytes[0], HookAddress, TEE_MAXIMUM_HOOK_SIZE);
                VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                hookEntry.push_back(myHook);
                return true;
            }
#else
            if(VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
            {
                WriteMemory->Array.bArrayEntry[0] = 0xFF;
                WriteMemory->Array.bArrayEntry[1] = 0x25;
                RtlZeroMemory(&WriteMemory->Array.bArrayEntry[2], 4);
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[6], &RedirectTo, sizeof RedirectTo);
                RtlMoveMemory(&myHook.HookBytes[0], HookAddress, TEE_MAXIMUM_HOOK_SIZE);
                VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                hookEntry.push_back(myHook);
                return true;
            }
#endif
        }
        else if(HookType == TEE_HOOK_NRM_CALL)
        {
#if !defined(_WIN64)
            CalculatedRealingJump = CalculatedRealingJump - 5;
            if(VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
            {
                WriteMemory->Array.bArrayEntry[0] = 0xE8;
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[1], &CalculatedRealingJump, sizeof CalculatedRealingJump);
                RtlMoveMemory(&myHook.HookBytes[0], HookAddress, TEE_MAXIMUM_HOOK_SIZE);
                VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                hookEntry.push_back(myHook);
                return true;
            }
#else
            if(VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
            {
                WriteMemory->Array.bArrayEntry[0] = 0xFF;
                WriteMemory->Array.bArrayEntry[1] = 0x15;
                RtlZeroMemory(&WriteMemory->Array.bArrayEntry[2], 4);
                RtlMoveMemory(&WriteMemory->Array.bArrayEntry[6], &RedirectTo, sizeof RedirectTo);
                RtlMoveMemory(&myHook.HookBytes[0], HookAddress, TEE_MAXIMUM_HOOK_SIZE);
                VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                hookEntry.push_back(myHook);
                return true;
            }
#endif
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL HooksInsertNewIATRedirectionEx(ULONG_PTR FileMapVA, ULONG_PTR LoadedModuleBase, char* szHookFunction, LPVOID RedirectTo)
{

    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_IMPORT_DESCRIPTOR ImportIID;
    PIMAGE_THUNK_DATA32 ThunkData32;
    PIMAGE_THUNK_DATA64 ThunkData64;
    DWORD OldProtect = PAGE_READONLY;
    ULONG_PTR CurrentThunk;
    HOOK_ENTRY myHook = {};
    BOOL FileIs64;

    if(FileMapVA != NULL && LoadedModuleBase != NULL)
    {
        myHook.IATHook = true;
        myHook.HookIsEnabled = true;
        myHook.HookType = TEE_HOOK_IAT;
        myHook.HookSize = sizeof ULONG_PTR;
        myHook.RedirectionAddress = RedirectTo;
        myHook.IATHookModuleBase = (void*)LoadedModuleBase;
        myHook.IATHookNameHash = EngineHashString(szHookFunction);
        DOSHeader = (PIMAGE_DOS_HEADER)FileMapVA;
        if(EngineValidateHeader(FileMapVA, NULL, NULL, DOSHeader, true))
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
                return false;
            }
            if(!FileIs64)
            {
                if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != NULL)
                {
                    ImportIID = (PIMAGE_IMPORT_DESCRIPTOR)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + PEHeader32->OptionalHeader.ImageBase), true);
                    __try
                    {
                        while(ImportIID->FirstThunk != NULL)
                        {
                            if(ImportIID->OriginalFirstThunk != NULL)
                            {
                                ThunkData32 = (PIMAGE_THUNK_DATA32)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ImportIID->OriginalFirstThunk + PEHeader32->OptionalHeader.ImageBase), true);
                                CurrentThunk = (ULONG_PTR)ImportIID->FirstThunk;
                            }
                            else
                            {
                                ThunkData32 = (PIMAGE_THUNK_DATA32)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ImportIID->FirstThunk + PEHeader32->OptionalHeader.ImageBase), true);
                                CurrentThunk = (ULONG_PTR)ImportIID->FirstThunk;
                            }
                            while(ThunkData32 && ThunkData32->u1.AddressOfData != NULL)
                            {
                                if(!(ThunkData32->u1.Ordinal & IMAGE_ORDINAL_FLAG32))
                                {
                                    if(lstrcmpiA((char*)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ThunkData32->u1.AddressOfData + 2 + PEHeader32->OptionalHeader.ImageBase), true), szHookFunction) == NULL)
                                    {
                                        myHook.HookAddress = (void*)(CurrentThunk + LoadedModuleBase);
                                        if(VirtualProtect(myHook.HookAddress, myHook.HookSize, PAGE_EXECUTE_READWRITE, &OldProtect))
                                        {
                                            RtlMoveMemory(&myHook.OriginalBytes[0], myHook.HookAddress, myHook.HookSize);
                                            RtlMoveMemory(&myHook.HookBytes[0], &myHook.RedirectionAddress, myHook.HookSize);
                                            RtlMoveMemory(myHook.HookAddress, &myHook.RedirectionAddress, myHook.HookSize);
                                            VirtualProtect(myHook.HookAddress, myHook.HookSize, OldProtect, &OldProtect);
                                        }
                                        hookEntry.push_back(myHook);
                                    }
                                }
                                CurrentThunk = CurrentThunk + 4;
                                ThunkData32 = (PIMAGE_THUNK_DATA32)((ULONG_PTR)ThunkData32 + sizeof IMAGE_THUNK_DATA32);
                            }
                            ImportIID = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)ImportIID + sizeof IMAGE_IMPORT_DESCRIPTOR);
                        }
                        return true;
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        return false;
                    }
                }
            }
            else
            {
                if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != NULL)
                {
                    ImportIID = (PIMAGE_IMPORT_DESCRIPTOR)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + PEHeader64->OptionalHeader.ImageBase), true);
                    __try
                    {
                        while(ImportIID->FirstThunk != NULL)
                        {
                            if(ImportIID->OriginalFirstThunk != NULL)
                            {
                                ThunkData64 = (PIMAGE_THUNK_DATA64)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ImportIID->OriginalFirstThunk + PEHeader64->OptionalHeader.ImageBase), true);
                                CurrentThunk = (ULONG_PTR)ImportIID->OriginalFirstThunk;
                            }
                            else
                            {
                                ThunkData64 = (PIMAGE_THUNK_DATA64)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ImportIID->FirstThunk + PEHeader64->OptionalHeader.ImageBase), true);
                                CurrentThunk = (ULONG_PTR)ImportIID->FirstThunk;
                            }
                            while(ThunkData64 && ThunkData64->u1.AddressOfData != NULL)
                            {
                                if(!(ThunkData64->u1.Ordinal & IMAGE_ORDINAL_FLAG64))
                                {
                                    if(lstrcmpiA((char*)ConvertVAtoFileOffset(FileMapVA, (ULONG_PTR)((ULONG_PTR)ThunkData64->u1.AddressOfData + 2 + PEHeader64->OptionalHeader.ImageBase), true), szHookFunction) == NULL)
                                    {
                                        myHook.HookAddress = (void*)(CurrentThunk + LoadedModuleBase);
                                        if(VirtualProtect(myHook.HookAddress, myHook.HookSize, PAGE_EXECUTE_READWRITE, &OldProtect))
                                        {
                                            RtlMoveMemory(&myHook.OriginalBytes[0], myHook.HookAddress, myHook.HookSize);
                                            RtlMoveMemory(&myHook.HookBytes[0], &myHook.RedirectionAddress, myHook.HookSize);
                                            RtlMoveMemory(myHook.HookAddress, &myHook.RedirectionAddress, myHook.HookSize);
                                            VirtualProtect(myHook.HookAddress, myHook.HookSize, OldProtect, &OldProtect);
                                        }
                                        hookEntry.push_back(myHook);
                                    }
                                }
                                CurrentThunk = CurrentThunk + 8;
                                ThunkData64 = (PIMAGE_THUNK_DATA64)((ULONG_PTR)ThunkData64 + sizeof IMAGE_THUNK_DATA64);
                            }
                            ImportIID = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)ImportIID + sizeof IMAGE_IMPORT_DESCRIPTOR);
                        }
                        return true;
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER)
                    {
                        return false;
                    }
                }
            }
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
    return false;
}

__declspec(dllexport) bool TITCALL HooksInsertNewIATRedirection(char* szModuleName, char* szHookFunction, LPVOID RedirectTo)
{
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;
    DWORD NewSectionVO = NULL;
    DWORD NewSectionFO = NULL;
    HMODULE SelectedModule = NULL;

    SelectedModule = GetModuleHandleA(szModuleName);
    if(SelectedModule != NULL)
    {
        if(MapFileEx(szModuleName, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
        {
            if(HooksInsertNewIATRedirectionEx(FileMapVA, (ULONG_PTR)SelectedModule, szHookFunction, RedirectTo))
            {
                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                return true;
            }
            else
            {
                UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
            }
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL HooksRemoveRedirection(LPVOID HookAddress, bool RemoveAll)
{
    DWORD OldProtect = PAGE_READONLY;

    if(!RemoveAll)
    {
        for(unsigned int i = 0; i < hookEntry.size(); i++)
        {
            if(hookEntry[i].HookAddress == HookAddress && hookEntry[i].IATHook == false)
            {
                if(VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
                {
                    RtlMoveMemory(HookAddress, &hookEntry[i].OriginalBytes, hookEntry[i].HookSize);
                    VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                    hookEntry.erase(hookEntry.begin() + i);
                    return true;
                }
            }
        }
        return false;
    }
    else
    {
        for(unsigned int i = 0; i < hookEntry.size(); i++)
        {
            if(VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
            {
                RtlMoveMemory(hookEntry[i].HookAddress, &hookEntry[i].OriginalBytes, hookEntry[i].HookSize);
                VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
            }
        }
        hookEntry.clear();
        return true;
    }
}

__declspec(dllexport) bool TITCALL HooksRemoveRedirectionsForModule(HMODULE ModuleBase)
{
    int j = NULL;
    unsigned int i = (unsigned int)hookEntry.size();
    DWORD OldProtect = PAGE_READONLY;
    MODULEINFO RemoteModuleInfo;

    if(GetModuleInformation(GetCurrentProcess(), ModuleBase, &RemoteModuleInfo, sizeof MODULEINFO))
    {
        while(i > NULL)
        {
            if((ULONG_PTR)hookEntry[i].HookAddress >= (ULONG_PTR)ModuleBase && (ULONG_PTR)hookEntry[i].HookAddress <= (ULONG_PTR)ModuleBase + RemoteModuleInfo.SizeOfImage)
            {
                if(VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
                {
                    RtlMoveMemory(hookEntry[i].HookAddress, &hookEntry[i].OriginalBytes, hookEntry[i].HookSize);
                    VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                    hookEntry.erase(hookEntry.begin() + i);
                    j++;
                }
            }
            i--;
        }
        if(j == NULL)
        {
            return false;
        }
    }
    else
    {
        return false;
    }
    return true;
}

__declspec(dllexport) bool TITCALL HooksRemoveIATRedirection(char* szModuleName, char* szHookFunction, bool RemoveAll)
{
    unsigned int i = (unsigned int)hookEntry.size() - 1;
    DWORD OldProtect = PAGE_READONLY;
    HMODULE ModuleBase = GetModuleHandleA(szModuleName);
    DWORD FunctionNameHash = EngineHashString(szHookFunction);

    if(ModuleBase != NULL)
    {
        while(i > 0)
        {
            if((hookEntry[i].IATHookModuleBase == (void*)ModuleBase && RemoveAll == true) || (hookEntry[i].IATHookNameHash == FunctionNameHash && hookEntry[i].IATHook == true))
            {
                if(VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
                {
                    RtlMoveMemory(hookEntry[i].HookAddress, &hookEntry[i].OriginalBytes, hookEntry[i].HookSize);
                    VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                    hookEntry.erase(hookEntry.begin() + i);
                }
            }
            i--;
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL HooksDisableRedirection(LPVOID HookAddress, bool DisableAll)
{
    DWORD OldProtect = PAGE_READONLY;

    if(!DisableAll)
    {
        for(unsigned int i = 0; i < hookEntry.size(); i++)
        {
            if(hookEntry[i].HookAddress == HookAddress && hookEntry[i].HookIsEnabled == true)
            {
                if(VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
                {
                    RtlMoveMemory(HookAddress, &hookEntry[i].OriginalBytes, hookEntry[i].HookSize);
                    VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                    hookEntry[i].HookIsEnabled = false;
                    return true;
                }
            }
        }
        return false;
    }
    else
    {
        for(unsigned int i = 0; i < hookEntry.size(); i++)
        {
            if(VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
            {
                RtlMoveMemory(hookEntry[i].HookAddress, &hookEntry[i].OriginalBytes, hookEntry[i].HookSize);
                VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                hookEntry[i].HookIsEnabled = false;
            }
        }
        return true;
    }
}

__declspec(dllexport) bool TITCALL HooksDisableRedirectionsForModule(HMODULE ModuleBase)
{
    int j = NULL;
    unsigned int i = (unsigned int)hookEntry.size();
    DWORD OldProtect = PAGE_READONLY;
    MODULEINFO RemoteModuleInfo;

    if(GetModuleInformation(GetCurrentProcess(), ModuleBase, &RemoteModuleInfo, sizeof MODULEINFO))
    {
        while(i > NULL)
        {
            if((ULONG_PTR)hookEntry[i].HookAddress >= (ULONG_PTR)ModuleBase && (ULONG_PTR)hookEntry[i].HookAddress <= (ULONG_PTR)ModuleBase + RemoteModuleInfo.SizeOfImage)
            {
                if(VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
                {
                    RtlMoveMemory(hookEntry[i].HookAddress, &hookEntry[i].OriginalBytes, hookEntry[i].HookSize);
                    VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                    hookEntry[i].HookIsEnabled = false;
                    j++;
                }
            }
            i--;
        }
        if(j == NULL)
        {
            return false;
        }
    }
    else
    {
        return false;
    }
    return true;
}

__declspec(dllexport) bool TITCALL HooksDisableIATRedirection(char* szModuleName, char* szHookFunction, bool DisableAll)
{
    unsigned int i = (unsigned int)hookEntry.size() - 1;
    DWORD OldProtect = PAGE_READONLY;
    HMODULE ModuleBase = GetModuleHandleA(szModuleName);
    DWORD FunctionNameHash = EngineHashString(szHookFunction);

    if(ModuleBase != NULL)
    {
        while(i > 0)
        {
            if((hookEntry[i].IATHookModuleBase == (void*)ModuleBase && DisableAll == true) || (hookEntry[i].IATHookNameHash == FunctionNameHash && hookEntry[i].IATHook == true))
            {
                if(hookEntry[i].HookIsEnabled)
                {
                    if(VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
                    {
                        RtlMoveMemory(hookEntry[i].HookAddress, &hookEntry[i].OriginalBytes, hookEntry[i].HookSize);
                        VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                        hookEntry[i].HookIsEnabled = false;
                    }
                }
            }
            i--;
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL HooksEnableRedirection(LPVOID HookAddress, bool EnableAll)
{
    DWORD OldProtect = PAGE_READONLY;

    if(!EnableAll)
    {
        for(unsigned int i = 0; i < hookEntry.size(); i++)
        {
            if(hookEntry[i].HookAddress == HookAddress && hookEntry[i].HookIsEnabled == false)
            {
                if(VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
                {
                    RtlMoveMemory(HookAddress, &hookEntry[i].HookBytes, hookEntry[i].HookSize);
                    VirtualProtect(HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                    hookEntry[i].HookIsEnabled = true;
                    return true;
                }
            }
        }
        return false;
    }
    else
    {
        for(unsigned int i = 0; i < hookEntry.size(); i++)
        {
            if(VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
            {
                RtlMoveMemory(hookEntry[i].HookAddress, &hookEntry[i].HookBytes, hookEntry[i].HookSize);
                VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                hookEntry[i].HookIsEnabled = true;
            }
        }
        return true;
    }
}

__declspec(dllexport) bool TITCALL HooksEnableRedirectionsForModule(HMODULE ModuleBase)
{
    int j = NULL;
    unsigned int i = (unsigned int)hookEntry.size();
    DWORD OldProtect = PAGE_READONLY;
    MODULEINFO RemoteModuleInfo;

    if(GetModuleInformation(GetCurrentProcess(), ModuleBase, &RemoteModuleInfo, sizeof MODULEINFO))
    {
        while(i > NULL)
        {
            if((ULONG_PTR)hookEntry[i].HookAddress >= (ULONG_PTR)ModuleBase && (ULONG_PTR)hookEntry[i].HookAddress <= (ULONG_PTR)ModuleBase + RemoteModuleInfo.SizeOfImage)
            {
                if(VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
                {
                    RtlMoveMemory(hookEntry[i].HookAddress, &hookEntry[i].HookBytes, hookEntry[i].HookSize);
                    VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                    hookEntry[i].HookIsEnabled = true;
                    j++;
                }
            }
            i--;
        }
        if(j == NULL)
        {
            return false;
        }
    }
    else
    {
        return false;
    }
    return true;
}

__declspec(dllexport) bool TITCALL HooksEnableIATRedirection(char* szModuleName, char* szHookFunction, bool EnableAll)
{
    unsigned int i = (unsigned int)hookEntry.size() - 1;
    DWORD OldProtect = PAGE_READONLY;
    HMODULE ModuleBase = GetModuleHandleA(szModuleName);
    DWORD FunctionNameHash = EngineHashString(szHookFunction);

    if(ModuleBase != NULL)
    {
        while(i > 0)
        {
            if((hookEntry[i].IATHookModuleBase == (void*)ModuleBase && EnableAll == true) || (hookEntry[i].IATHookNameHash == FunctionNameHash && hookEntry[i].IATHook == true))
            {
                if(!hookEntry[i].HookIsEnabled)
                {
                    if(VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, PAGE_EXECUTE_READWRITE, &OldProtect))
                    {
                        RtlMoveMemory(hookEntry[i].HookAddress, &hookEntry[i].HookBytes, hookEntry[i].HookSize);
                        VirtualProtect(hookEntry[i].HookAddress, TEE_MAXIMUM_HOOK_SIZE, OldProtect, &OldProtect);
                        hookEntry[i].HookIsEnabled = true;
                    }
                }
            }
            i--;
        }
    }
    return false;
}

__declspec(dllexport) void TITCALL HooksScanModuleMemory(HMODULE ModuleBase, LPVOID CallBack)
{
    unsigned int i;
    bool FileIs64 = false;
    bool FileError = false;
    void* pOriginalInstruction;
    bool ManuallyMapped = false;
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_EXPORT_DIRECTORY PEExports;
    HANDLE hProcess = GetCurrentProcess();
    LIBRARY_ITEM_DATA RemoteLibInfo = {};
    PLIBRARY_ITEM_DATA pRemoteLibInfo = (PLIBRARY_ITEM_DATA)LibrarianGetLibraryInfoEx((void*)ModuleBase);
    typedef bool(TITCALL * fEnumCallBack)(PHOOK_ENTRY HookDetails, void* ptrOriginalInstructions, PLIBRARY_ITEM_DATA ModuleInformation, DWORD SizeOfImage);
    fEnumCallBack myEnumCallBack = (fEnumCallBack)CallBack;
    BYTE CheckHookMemory[TEE_MAXIMUM_HOOK_SIZE];
    PMEMORY_COMPARE_HANDLER ExportedFunctions;
    PMEMORY_COMPARE_HANDLER FunctionMemory;
    ULONG_PTR lpNumberOfBytesWritten;
    HOOK_ENTRY MyhookEntry = {};
    ULONG_PTR HookDestination;
    MODULEINFO ModuleInfo;
    BYTE HookType = NULL;
    DWORD hSize;

    if(pRemoteLibInfo == NULL)
    {
        RemoteLibInfo.BaseOfDll = (void*)ModuleBase;
        GetModuleBaseNameA(hProcess, ModuleBase, &RemoteLibInfo.szLibraryName[0], MAX_PATH);
        GetModuleFileNameExA(hProcess, ModuleBase, &RemoteLibInfo.szLibraryPath[0], MAX_PATH);
        RemoteLibInfo.hFile = CreateFileA(RemoteLibInfo.szLibraryPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if(RemoteLibInfo.hFile != INVALID_HANDLE_VALUE)
        {
            RemoteLibInfo.hFileMapping = CreateFileMappingA(RemoteLibInfo.hFile, NULL, 2, NULL, GetFileSize(RemoteLibInfo.hFile, NULL), NULL);
            if(RemoteLibInfo.hFileMapping != NULL)
            {
                RemoteLibInfo.hFileMappingView = MapViewOfFile(RemoteLibInfo.hFileMapping, 4, NULL, NULL, NULL);
                if(RemoteLibInfo.hFileMappingView == NULL)
                {
                    CloseHandle(RemoteLibInfo.hFile);
                    CloseHandle(RemoteLibInfo.hFileMapping);
                    FileError = true;
                }
                else
                {
                    ManuallyMapped = true;
                }
            }
            else
            {
                CloseHandle(RemoteLibInfo.hFile);
                FileError = true;
            }
        }
        else
        {
            FileError = true;
        }
    }
    else
    {
        RtlMoveMemory(&RemoteLibInfo, pRemoteLibInfo, sizeof LIBRARY_ITEM_DATA);
    }
    if(!FileError)
    {
        hSize = GetFileSize(RemoteLibInfo.hFile, NULL);
        GetModuleInformation(hProcess, ModuleBase, &ModuleInfo, sizeof MODULEINFO);
        DOSHeader = (PIMAGE_DOS_HEADER)RemoteLibInfo.hFileMappingView;
        __try
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
                FileError = true;
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            FileError = true;
        }
        if(!FileError)
        {
            FunctionMemory = (PMEMORY_COMPARE_HANDLER)&CheckHookMemory[0];
            if(!FileIs64)
            {
                __try
                {
                    if(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != NULL)
                    {
                        PEExports = (PIMAGE_EXPORT_DIRECTORY)ConvertVAtoFileOffsetEx((ULONG_PTR)RemoteLibInfo.hFileMappingView, hSize, PEHeader32->OptionalHeader.ImageBase, PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, true, true);
                        if(PEExports != NULL)
                        {
                            ExportedFunctions = (PMEMORY_COMPARE_HANDLER)(ConvertVAtoFileOffsetEx((ULONG_PTR)RemoteLibInfo.hFileMappingView, hSize, PEHeader32->OptionalHeader.ImageBase, PEExports->AddressOfFunctions, true, true));
                            for(i = 0; i < PEExports->NumberOfFunctions; i++)
                            {
                                if(ReadProcessMemory(hProcess, (void*)((ULONG_PTR)RemoteLibInfo.BaseOfDll + ExportedFunctions->Array.dwArrayEntry[i]), &CheckHookMemory[0], TEE_MAXIMUM_HOOK_SIZE, &lpNumberOfBytesWritten))
                                {
                                    if(FunctionMemory->Array.bArrayEntry[0] == 0xE9 || FunctionMemory->Array.bArrayEntry[0] == 0xE8)
                                    {
                                        HookDestination = (ULONG_PTR)GetJumpDestination(hProcess, (ULONG_PTR)RemoteLibInfo.BaseOfDll + ExportedFunctions->Array.dwArrayEntry[i]);
                                        if(HookDestination >= (ULONG_PTR)RemoteLibInfo.BaseOfDll && HookDestination <= (ULONG_PTR)RemoteLibInfo.BaseOfDll + (ULONG_PTR)ModuleInfo.SizeOfImage)
                                        {
                                            if(CallBack != NULL)
                                            {
                                                if(FunctionMemory->Array.bArrayEntry[0] == 0xE9)
                                                {
                                                    HookType = TEE_HOOK_NRM_JUMP;
                                                }
                                                else
                                                {
                                                    HookType = TEE_HOOK_NRM_CALL;
                                                }
                                                MyhookEntry.HookSize = 5;
                                                MyhookEntry.HookType = HookType;
                                                MyhookEntry.HookIsEnabled = true;
                                                MyhookEntry.RedirectionAddress = (void*)HookDestination;
                                                MyhookEntry.HookAddress = (void*)((ULONG_PTR)RemoteLibInfo.BaseOfDll + ExportedFunctions->Array.dwArrayEntry[i]);
                                                pOriginalInstruction = (void*)ConvertVAtoFileOffsetEx((ULONG_PTR)RemoteLibInfo.hFileMappingView, hSize, PEHeader32->OptionalHeader.ImageBase, ExportedFunctions->Array.dwArrayEntry[i], true, true);
                                                RtlZeroMemory(&MyhookEntry.HookBytes[0], TEE_MAXIMUM_HOOK_SIZE);
                                                RtlMoveMemory(&MyhookEntry.HookBytes[0], &CheckHookMemory[0], MyhookEntry.HookSize);
                                                RtlZeroMemory(&MyhookEntry.OriginalBytes[0], TEE_MAXIMUM_HOOK_SIZE);
                                                RtlMoveMemory(&MyhookEntry.OriginalBytes[0], pOriginalInstruction, MyhookEntry.HookSize);
                                                RelocaterRelocateMemoryBlock((ULONG_PTR)RemoteLibInfo.hFileMappingView, (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase + ExportedFunctions->Array.dwArrayEntry[i], &MyhookEntry.OriginalBytes[0], MyhookEntry.HookSize, (ULONG_PTR)PEHeader32->OptionalHeader.ImageBase, (ULONG_PTR)RemoteLibInfo.BaseOfDll);
                                                if(!myEnumCallBack(&MyhookEntry, pOriginalInstruction, &RemoteLibInfo, ModuleInfo.SizeOfImage))
                                                {
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {

                }
            }
            else
            {
                __try
                {
                    if(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != NULL)
                    {
                        PEExports = (PIMAGE_EXPORT_DIRECTORY)ConvertVAtoFileOffsetEx((ULONG_PTR)RemoteLibInfo.hFileMappingView, hSize, (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, true, true);
                        if(PEExports != NULL)
                        {
                            ExportedFunctions = (PMEMORY_COMPARE_HANDLER)(ConvertVAtoFileOffsetEx((ULONG_PTR)RemoteLibInfo.hFileMappingView, hSize, (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, PEExports->AddressOfFunctions, true, true));
                            for(i = 0; i < PEExports->NumberOfFunctions; i++)
                            {
                                if(ReadProcessMemory(hProcess, (void*)((ULONG_PTR)RemoteLibInfo.BaseOfDll + ExportedFunctions->Array.dwArrayEntry[i]), &CheckHookMemory[0], TEE_MAXIMUM_HOOK_SIZE, &lpNumberOfBytesWritten))
                                {
                                    if(FunctionMemory->Array.bArrayEntry[0] == 0xE9 || FunctionMemory->Array.bArrayEntry[0] == 0xE8)
                                    {
                                        HookDestination = (ULONG_PTR)GetJumpDestination(hProcess, (ULONG_PTR)RemoteLibInfo.BaseOfDll + ExportedFunctions->Array.dwArrayEntry[i]);
                                        if(HookDestination >= (ULONG_PTR)RemoteLibInfo.BaseOfDll && HookDestination <= (ULONG_PTR)RemoteLibInfo.BaseOfDll + (ULONG_PTR)ModuleInfo.SizeOfImage)
                                        {
                                            if(CallBack != NULL)
                                            {
                                                if(FunctionMemory->Array.bArrayEntry[0] == 0xE9)
                                                {
                                                    HookType = TEE_HOOK_NRM_JUMP;
                                                }
                                                else
                                                {
                                                    HookType = TEE_HOOK_NRM_CALL;
                                                }
                                                MyhookEntry.HookSize = 5;
                                                MyhookEntry.HookType = HookType;
                                                MyhookEntry.HookIsEnabled = true;
                                                MyhookEntry.RedirectionAddress = (void*)HookDestination;
                                                MyhookEntry.HookAddress = (void*)((ULONG_PTR)RemoteLibInfo.BaseOfDll + ExportedFunctions->Array.dwArrayEntry[i]);
                                                pOriginalInstruction = (void*)ConvertVAtoFileOffsetEx((ULONG_PTR)RemoteLibInfo.hFileMappingView, hSize, (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, ExportedFunctions->Array.dwArrayEntry[i], true, true);
                                                RtlZeroMemory(&MyhookEntry.HookBytes[0], TEE_MAXIMUM_HOOK_SIZE);
                                                RtlMoveMemory(&MyhookEntry.HookBytes[0], &CheckHookMemory[0], MyhookEntry.HookSize);
                                                RtlZeroMemory(&MyhookEntry.OriginalBytes[0], TEE_MAXIMUM_HOOK_SIZE);
                                                RtlMoveMemory(&MyhookEntry.OriginalBytes[0], pOriginalInstruction, MyhookEntry.HookSize);
                                                RelocaterRelocateMemoryBlock((ULONG_PTR)RemoteLibInfo.hFileMappingView, (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase + ExportedFunctions->Array.dwArrayEntry[i], &MyhookEntry.OriginalBytes[0], MyhookEntry.HookSize, (ULONG_PTR)PEHeader64->OptionalHeader.ImageBase, (ULONG_PTR)RemoteLibInfo.BaseOfDll);
                                                if(!myEnumCallBack(&MyhookEntry, pOriginalInstruction, &RemoteLibInfo, ModuleInfo.SizeOfImage))
                                                {
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                __except(EXCEPTION_EXECUTE_HANDLER)
                {

                }
            }
        }
        if(ManuallyMapped)
        {
            if(UnmapViewOfFile(RemoteLibInfo.hFileMappingView))
            {
                CloseHandle(RemoteLibInfo.hFileMapping);
                CloseHandle(RemoteLibInfo.hFile);
            }
        }
    }
}

__declspec(dllexport) void TITCALL HooksScanEntireProcessMemory(LPVOID CallBack)
{
    unsigned int i;
    DWORD cbNeeded = 0;
    HMODULE EnumeratedModules[1024] = {0};

    hookEntry.clear();
    if(EnumProcessModules(GetCurrentProcess(), EnumeratedModules, sizeof(EnumeratedModules), &cbNeeded))
    {
        for(i = 1; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            HooksScanModuleMemory(EnumeratedModules[i], CallBack);
        }
    }
}

__declspec(dllexport) void TITCALL HooksScanEntireProcessMemoryEx()
{
    HooksScanEntireProcessMemory(&ProcessHookScanAddNewHook);
}
