#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.h"
#include "Global.Debugger.h"
#include "Global.Mapping.h"
#include "Global.Engine.Hash.h"
#include "Global.Injector.h"


// Global.Engine.Tracer.functions:
static ULONG_PTR EngineGlobalTracerHandler1(HANDLE hProcess, ULONG_PTR AddressToTrace, bool HashInstructions, DWORD InputNumberOfInstructions)
{

    SIZE_T memSize = 0;
    int NumberOfInstructions = 0;
    int LengthOfValidInstruction = 0;
    int CurrentNumberOfInstructions = 0;
    MEMORY_BASIC_INFORMATION MemInfo;
    DynBuf tracmem;
    LPVOID TraceMemory, cTraceMemory;
    ULONG_PTR ueNumberOfBytesRead = NULL;
    DWORD LastPushValue = NULL;
    ULONG_PTR TraceStartAddress;
    ULONG_PTR TraceTestAddress;
    ULONG_PTR TraceTestReadAddress;
    DWORD CurrentInstructionSize;
    PMEMORY_CMP_HANDLER CompareMemory;
    PMEMORY_COMPARE_HANDLER longCompareMemory;
    DWORD InstructionHash = NULL;
    bool FoundValidAPI = false;
    bool SkipThisInstruction = false;
    bool LoopCondition = true;
    bool SkipHashing = false;
    BYTE EmptyCall[5] = {0xE8, 0x00, 0x00, 0x00, 0x00};

    if(VirtualQueryEx(hProcess, (LPVOID)AddressToTrace, &MemInfo, sizeof MEMORY_BASIC_INFORMATION) != NULL)
    {
        if(MemInfo.RegionSize > NULL)
        {
            memSize = MemInfo.RegionSize;
            if(memSize > 0x4000)
            {
                memSize = 0x4000;
            }
            TraceMemory = tracmem.Allocate(memSize);
            cTraceMemory = TraceMemory;
            if(ReadProcessMemory(hProcess, (LPVOID)MemInfo.BaseAddress, TraceMemory, memSize, &ueNumberOfBytesRead))
            {
                TraceStartAddress = AddressToTrace - (ULONG_PTR)MemInfo.BaseAddress + (ULONG_PTR)TraceMemory;
                if(HashInstructions && InputNumberOfInstructions > NULL)
                {
                    LoopCondition = true;
                }
                else
                {
                    LoopCondition = false;
                }

                while(LoopCondition)
                {
                    SkipHashing = false;
                    SkipThisInstruction = false;
                    CompareMemory = (PMEMORY_CMP_HANDLER)TraceStartAddress;
                    CurrentInstructionSize = StaticLengthDisassemble((LPVOID)TraceStartAddress);
                    CurrentNumberOfInstructions++;
                    /*
                        Long JUMP (0xE9)
                    */
                    if(HashInstructions == false && CompareMemory->DataByte[0] == 0xE9 && CurrentInstructionSize == 5)
                    {
                        TraceTestAddress = (ULONG_PTR)GetJumpDestination(NULL, TraceStartAddress) - (ULONG_PTR)TraceMemory + (ULONG_PTR)MemInfo.BaseAddress;
                        if(TraceTestAddress <= (ULONG_PTR)MemInfo.BaseAddress || TraceTestAddress >= (ULONG_PTR)MemInfo.BaseAddress + MemInfo.RegionSize)
                        {
                            if(LengthOfValidInstruction == NULL)
                            {
                                if(ImporterGetAPINameFromDebugee(hProcess, TraceTestAddress) != NULL)
                                {
                                    FoundValidAPI = true;
                                    break;
                                }
                            }
                            if(ImporterGetAPINameFromDebugee(hProcess, TraceTestAddress) != NULL)
                            {
                                FoundValidAPI = true;
                                break;
                            }
                            else
                            {
                                if(ImporterGetAPINameFromDebugee(hProcess, TraceTestAddress - LengthOfValidInstruction) != NULL)
                                {
                                    FoundValidAPI = true;
                                    TraceTestAddress = TraceTestAddress - LengthOfValidInstruction;
                                    break;
                                }
                            }
                        }
                        /*
                            Near JUMP (0xFF25)
                        */
                    }
                    else if(HashInstructions == false && CompareMemory->DataByte[0] == 0xFF && CompareMemory->DataByte[1] == 0x25 && CurrentInstructionSize == 6)
                    {
                        TraceTestAddress = (ULONG_PTR)GetJumpDestination(NULL, TraceStartAddress);
                        if(ReadProcessMemory(hProcess, (LPVOID)TraceTestAddress, &TraceTestAddress, 4, &ueNumberOfBytesRead))
                        {
                            if(TraceTestAddress <= (ULONG_PTR)MemInfo.BaseAddress || TraceTestAddress >= (ULONG_PTR)MemInfo.BaseAddress + MemInfo.RegionSize)
                            {
                                if(LengthOfValidInstruction == NULL)
                                {
                                    if(ImporterGetAPINameFromDebugee(hProcess, TraceTestAddress) != NULL)
                                    {
                                        FoundValidAPI = true;
                                        break;
                                    }
                                }
                                if(ImporterGetAPINameFromDebugee(hProcess, TraceTestAddress) != NULL)
                                {
                                    FoundValidAPI = true;
                                    break;
                                }
                                else
                                {
                                    if(ImporterGetAPINameFromDebugee(hProcess, TraceTestAddress - LengthOfValidInstruction) != NULL)
                                    {
                                        FoundValidAPI = true;
                                        TraceTestAddress = TraceTestAddress - LengthOfValidInstruction;
                                        break;
                                    }
                                }
                            }
                        }
                        /*
                            PUSH then RET (0x68 ???????? 0xC3)
                        */
                    }
                    else if(HashInstructions == false && CompareMemory->DataByte[0] == 0x68 && CompareMemory->DataByte[5] == 0xC3 && CurrentInstructionSize == 5)
                    {
                        longCompareMemory = (PMEMORY_COMPARE_HANDLER)((ULONG_PTR)CompareMemory + 1);
                        TraceTestAddress = (DWORD)(longCompareMemory->Array.dwArrayEntry[0]);
                        if(ReadProcessMemory(hProcess, (LPVOID)TraceTestAddress, &TraceTestReadAddress, 4, &ueNumberOfBytesRead))
                        {
                            if(TraceTestAddress <= (ULONG_PTR)MemInfo.BaseAddress || TraceTestAddress >= (ULONG_PTR)MemInfo.BaseAddress + MemInfo.RegionSize)
                            {
                                if(LengthOfValidInstruction == NULL)
                                {
                                    if(ImporterGetAPINameFromDebugee(hProcess, TraceTestAddress) != NULL)
                                    {
                                        FoundValidAPI = true;
                                        break;
                                    }
                                }
                                if(ImporterGetAPINameFromDebugee(hProcess, TraceTestAddress) != NULL)
                                {
                                    FoundValidAPI = true;
                                    break;
                                }
                                else
                                {
                                    if(ImporterGetAPINameFromDebugee(hProcess, TraceTestAddress - LengthOfValidInstruction) != NULL)
                                    {
                                        FoundValidAPI = true;
                                        TraceTestAddress = TraceTestAddress - LengthOfValidInstruction;
                                        break;
                                    }
                                }
                            }
                            else
                            {
                                TraceStartAddress = TraceStartAddress - (ULONG_PTR)MemInfo.BaseAddress + (ULONG_PTR)TraceMemory;
                            }
                        }
                        /*
                            CALL (0xE8)
                        */
                    }
                    else if(HashInstructions == true && CompareMemory->DataByte[0] == 0xE8 && CurrentInstructionSize == 5)
                    {
                        SkipHashing = true;
                        InstructionHash = EngineHashMemory((char*)&EmptyCall, CurrentInstructionSize, InstructionHash);
                        /*
                            PUSH (0x68)
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0x68 && CurrentInstructionSize == 5)
                    {
                        LastPushValue = (DWORD)(CompareMemory->DataByte[1] + CompareMemory->DataByte[2] * 0x1000 + CompareMemory->DataByte[3] * 0x100000 + CompareMemory->DataByte[4] * 0x10000000);
                        /*
                            ADD BYTE PTR[AL],AL (0x00, 0x00) -> End of page!
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0x00 && CurrentInstructionSize == 2)
                    {
                        FoundValidAPI = false;
                        break;
                        /*
                            RET (0xC3)
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0xC3 && CurrentInstructionSize == 1)
                    {
                        NumberOfInstructions++;
                        break;
                        /*
                            RET (0xC2)
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0xC2 && CurrentInstructionSize == 3)
                    {
                        NumberOfInstructions++;
                        break;
                        /*
                            Short JUMP (0xEB)
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0xEB && CurrentInstructionSize == 2)
                    {
                        TraceStartAddress = TraceStartAddress + CompareMemory->DataByte[1];
                        SkipThisInstruction = true;
                        /*
                            CLC (0xF8)
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0xF8 && CurrentInstructionSize == 1)
                    {
                        SkipThisInstruction = true;
                        /*
                            STC (0xF9)
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0xF9 && CurrentInstructionSize == 1)
                    {
                        SkipThisInstruction = true;
                        /*
                            NOP (0x90)
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0x90 && CurrentInstructionSize == 1)
                    {
                        SkipThisInstruction = true;
                        /*
                            FNOP (0xD9 0xD0)
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0xD9 && CompareMemory->DataByte[1] == 0xD0 && CurrentInstructionSize == 2)
                    {
                        SkipThisInstruction = true;
                        /*
                            Multiple MOV
                        */
                    }
                    else if(CompareMemory->DataByte[0] >= 0x8A && CompareMemory->DataByte[0] <= 0x8B)
                    {
                        /*
                            MOV EAX,EAX (0x8B 0xC8)
                        */
                        if(CompareMemory->DataByte[0] == 0x8B && CompareMemory->DataByte[1] == 0xC8 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                                MOV EBX,EBX (0x8B 0xC9)
                            */
                        else if(CompareMemory->DataByte[0] == 0x8B && CompareMemory->DataByte[1] == 0xC9 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                        MOV ECX,ECX (0x8B 0xDB)
                        */
                        else if(CompareMemory->DataByte[0] == 0x8B && CompareMemory->DataByte[1] == 0xDB && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                            MOV (0x8B 0xED)
                           */
                        else if(CompareMemory->DataByte[0] == 0x8B && CompareMemory->DataByte[1] == 0xED && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;

                        }
                        /*
                                MOV (0x8B 0xF6)
                            */
                        else if(CompareMemory->DataByte[0] == 0x8B && CompareMemory->DataByte[1] == 0xF6 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                        MOV (0x8B 0xE4)
                        */
                        else if(CompareMemory->DataByte[0] == 0x8B && CompareMemory->DataByte[1] == 0xE4 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                        MOV EDX,EDX (0x8B 0xD2)
                        */
                        else if(CompareMemory->DataByte[0] == 0x8B && CompareMemory->DataByte[1] == 0xD2 && CurrentNumberOfInstructions != 1 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                                MOV EDI,EDI (0x8B 0xFF)
                            */
                        else if(CompareMemory->DataByte[0] == 0x8B && CompareMemory->DataByte[1] == 0xFF && CurrentNumberOfInstructions != 1 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                                MOV AL,AL (0x8A 0xC0)
                            */
                        else if(CompareMemory->DataByte[0] == 0x8A && CompareMemory->DataByte[1] == 0xC0 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                                MOV BL,BL (0x8A 0xDB)
                            */
                        else if(CompareMemory->DataByte[0] == 0x8A && CompareMemory->DataByte[1] == 0xDB && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                                MOV CL,CL (0x8A 0xC9)
                            */
                        else if(CompareMemory->DataByte[0] == 0x8A && CompareMemory->DataByte[1] == 0xC9 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                            MOV (0x8A 0xD2)
                           */
                        else if(CompareMemory->DataByte[0] == 0x8A && CompareMemory->DataByte[1] == 0xD2 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                                MOV (0x8A 0xE4)
                            */
                        else if(CompareMemory->DataByte[0] == 0x8A && CompareMemory->DataByte[1] == 0xE4 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                            MOV (0x8A 0xED)
                           */
                        else if(CompareMemory->DataByte[0] == 0x8A && CompareMemory->DataByte[1] == 0xED && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                                MOV (0x8A 0xFF)
                            */
                        else if(CompareMemory->DataByte[0] == 0x8A && CompareMemory->DataByte[1] == 0xFF && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                                MOV (0x8A 0xF6)
                            */
                        else if(CompareMemory->DataByte[0] == 0x8A && CompareMemory->DataByte[1] == 0xF6 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                            MOV AX,AX (0x8B 0xC0)
                           */
                        else if(CompareMemory->DataByte[0] == 0x8B && CompareMemory->DataByte[1] == 0xC0 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                            MOV (0x8B 0xDB)
                           */
                        else if(CompareMemory->DataByte[0] == 0x8B && CompareMemory->DataByte[1] == 0xDB && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                                MOV (0x8B 0xC9)
                            */
                        else if(CompareMemory->DataByte[0] == 0x8B && CompareMemory->DataByte[1] == 0xC9 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                                MOV (0x8B 0xF6)
                            */
                        else if(CompareMemory->DataByte[0] == 0x8B && CompareMemory->DataByte[1] == 0xF6 && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                            MOV (0x8B 0xED)
                           */
                        else if(CompareMemory->DataByte[0] == 0x8B && CompareMemory->DataByte[1] == 0xED && CurrentInstructionSize == 2)
                        {
                            SkipThisInstruction = true;
                        }
                    }
                    /*
                            RDTSC (0x0F 0x31)
                        */
                    else if(CompareMemory->DataByte[0] == 0x0F && CompareMemory->DataByte[1] == 0x31 && CurrentInstructionSize == 2)
                    {
                        SkipThisInstruction = true;
                        /*
                            CPUID (0x0F 0xA2)
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0x0F && CompareMemory->DataByte[1] == 0xA2 && CurrentInstructionSize == 2)
                    {
                        SkipThisInstruction = true;
                        /*
                            XCHG EAX,EAX (0x87 0xC0)
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0x87 && CompareMemory->DataByte[1] == 0xC0 && CurrentInstructionSize == 2)
                    {
                        SkipThisInstruction = true;
                        /*
                            SHL EAX,0 - SHL EDI,0 && SHR EAX,0 - SHR EDI,0
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0xC1 && CurrentInstructionSize == 3)
                    {
                        if(CompareMemory->DataByte[1] >= 0xE0 && CompareMemory->DataByte[1] <= 0xEF && CompareMemory->DataByte[2] == 0x00)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                            ROR EAX,0 - ROR EDI,0 && ROL EAX,0 - ROL EDI,0
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0xC1 && CurrentInstructionSize == 3)
                    {
                        if(CompareMemory->DataByte[1] >= 0xC0 && CompareMemory->DataByte[1] <= 0xCF && CompareMemory->DataByte[2] == 0x00)
                        {
                            SkipThisInstruction = true;
                        }
                        /*
                            LEA EAX,DWORD PTR[EAX] -> LEA EDI,DWORD PTR[EDI]
                        */
                    }
                    else if(CompareMemory->DataByte[0] == 0x8D && CurrentInstructionSize == 2)
                    {
                        if(CompareMemory->DataByte[1] == 0x00 || CompareMemory->DataByte[1] == 0x09 || CompareMemory->DataByte[1] == 0x1B || CompareMemory->DataByte[1] == 0x12)
                        {
                            SkipThisInstruction = true;
                        }
                        if(CompareMemory->DataByte[1] == 0x36 || CompareMemory->DataByte[1] == 0x3F)
                        {
                            SkipThisInstruction = true;
                        }
                        if(CompareMemory->DataByte[1] == 0x6D && CompareMemory->DataByte[2] == 0x00)
                        {
                            SkipThisInstruction = true;
                        }
                    }
                    if(!SkipThisInstruction)
                    {
                        if(HashInstructions == true && SkipHashing == false)
                        {
                            InstructionHash = EngineHashMemory((char*)TraceStartAddress, CurrentInstructionSize, InstructionHash);
                        }
                        LengthOfValidInstruction = LengthOfValidInstruction + CurrentInstructionSize;
                        NumberOfInstructions++;
                    }
                    if(HashInstructions)
                    {
                        InputNumberOfInstructions--;
                        if(InputNumberOfInstructions > NULL)
                        {
                            LoopCondition = true;
                        }
                        else
                        {
                            LoopCondition = false;
                        }
                    }
                    else
                    {
                        if(CurrentNumberOfInstructions < 1000 && FoundValidAPI == false)
                        {
                            LoopCondition = true;
                        }
                        else
                        {
                            LoopCondition = false;
                        }
                    }
                    TraceStartAddress = TraceStartAddress + CurrentInstructionSize;
                }
                if(!HashInstructions)
                {
                    if(FoundValidAPI == true)
                    {
                        return((ULONG_PTR)TraceTestAddress);
                    }
                    else if(CurrentNumberOfInstructions < 1000)
                    {
                        if(ImporterGetAPINameFromDebugee(hProcess, LastPushValue) != NULL)
                        {
                            return((ULONG_PTR)LastPushValue);
                        }
                        else if(ImporterGetAPINameFromDebugee(hProcess, LastPushValue - LengthOfValidInstruction) != NULL)
                        {
                            return((ULONG_PTR)(LastPushValue - LengthOfValidInstruction));
                        }
                        return((DWORD)NumberOfInstructions);
                    }
                }
                else
                {
                    return((DWORD)InstructionHash);
                }
            }
            else
            {
            }
        }
    }
    return(NULL);
}

// TitanEngine.Tracer.functions:
__declspec(dllexport) void TITCALL TracerInit()
{
    return;     // UE 1.5 compatibility mode
}

__declspec(dllexport) ULONG_PTR TITCALL TracerLevel1(HANDLE hProcess, ULONG_PTR AddressToTrace)
{
    return((ULONG_PTR)EngineGlobalTracerHandler1(hProcess, AddressToTrace, false, NULL));
}

__declspec(dllexport) ULONG_PTR TITCALL HashTracerLevel1(HANDLE hProcess, ULONG_PTR AddressToTrace, DWORD InputNumberOfInstructions)
{

    unsigned int i = 0;
    unsigned int j = 0;
    DWORD Dummy = NULL;
    MODULEINFO RemoteModuleInfo;
    ULONG_PTR EnumeratedModules[0x2000] = {0};
    ULONG_PTR LoadedModules[1000][4] = {0};
    char RemoteDLLName[MAX_PATH];
    HANDLE hLoadedModule = NULL;
    HANDLE ModuleHandle = NULL;
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS32 PEHeader32;
    PIMAGE_NT_HEADERS64 PEHeader64;
    PIMAGE_EXPORT_DIRECTORY PEExports;
    PEXPORTED_DATA ExportedFunctions;
    ULONG_PTR APIFoundAddress = NULL;
    bool ValidateHeader = false;
    bool FileIs64 = false;
    bool FoundAPI = false;
    DWORD CompareHash = NULL;
    DWORD TestHash = NULL;

    if(InputNumberOfInstructions > NULL)
    {
        CompareHash = (DWORD)EngineGlobalTracerHandler1(hProcess, AddressToTrace, true, InputNumberOfInstructions);
    }
    else
    {
        InputNumberOfInstructions = (DWORD)TracerLevel1(hProcess, AddressToTrace);
        if(InputNumberOfInstructions < 1000)
        {
            CompareHash = (DWORD)EngineGlobalTracerHandler1(hProcess, AddressToTrace, true, InputNumberOfInstructions);
        }
        else
        {
            return(NULL);
        }
    }

    if(hProcess == NULL)
    {
        if(dbgProcessInformation.hProcess == NULL)
        {
            hProcess = GetCurrentProcess();
        }
        else
        {
            hProcess = dbgProcessInformation.hProcess;
        }
    }
    if(EnumProcessModules(hProcess, (HMODULE*)EnumeratedModules, sizeof(EnumeratedModules), &Dummy))
    {
        i++;
        while(FoundAPI == false && EnumeratedModules[i] != NULL)
        {
            ValidateHeader = false;
            RtlZeroMemory(&RemoteDLLName, MAX_PATH);
            GetModuleFileNameExA(hProcess, (HMODULE)EnumeratedModules[i], (LPSTR)RemoteDLLName, MAX_PATH);
            if(GetModuleHandleA(RemoteDLLName) == NULL)
            {
                RtlZeroMemory(&RemoteDLLName, MAX_PATH);
                GetModuleBaseNameA(hProcess, (HMODULE)EnumeratedModules[i], (LPSTR)RemoteDLLName, MAX_PATH);
                if(GetModuleHandleA(RemoteDLLName) == NULL)
                {
                    if(engineAlowModuleLoading)
                    {
                        hLoadedModule = LoadLibraryA(RemoteDLLName);
                        if(hLoadedModule != NULL)
                        {
                            LoadedModules[i][0] = EnumeratedModules[i];
                            LoadedModules[i][1] = (ULONG_PTR)hLoadedModule;
                            LoadedModules[i][2] = 1;
                        }
                    }
                    else
                    {
                        hLoadedModule = (HANDLE)EngineSimulateDllLoader(hProcess, RemoteDLLName);
                        if(hLoadedModule != NULL)
                        {
                            LoadedModules[i][0] = EnumeratedModules[i];
                            LoadedModules[i][1] = (ULONG_PTR)hLoadedModule;
                            LoadedModules[i][2] = 1;
                            ValidateHeader = true;
                        }
                    }
                }
                else
                {
                    LoadedModules[i][0] = EnumeratedModules[i];
                    LoadedModules[i][1] = (ULONG_PTR)GetModuleHandleA(RemoteDLLName);
                    LoadedModules[i][2] = 0;
                }
            }
            else
            {
                LoadedModules[i][0] = EnumeratedModules[i];
                LoadedModules[i][1] = (ULONG_PTR)GetModuleHandleA(RemoteDLLName);
                LoadedModules[i][2] = 0;
            }

            if(!FoundAPI)
            {
                DOSHeader = (PIMAGE_DOS_HEADER)LoadedModules[i][1];
                RtlZeroMemory(&RemoteModuleInfo, sizeof MODULEINFO);
                GetModuleInformation(hProcess, (HMODULE)LoadedModules[i][1], &RemoteModuleInfo, sizeof MODULEINFO);
                if(ValidateHeader || EngineValidateHeader((ULONG_PTR)LoadedModules[i][1], hProcess, RemoteModuleInfo.lpBaseOfDll, DOSHeader, false))
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
                        return(NULL);
                    }
                    if(!FileIs64)
                    {
                        PEExports = (PIMAGE_EXPORT_DIRECTORY)(PEHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + LoadedModules[i][1]);
                        ExportedFunctions = (PEXPORTED_DATA)(PEExports->AddressOfFunctions + LoadedModules[i][1]);
                    }
                    else
                    {
                        PEExports = (PIMAGE_EXPORT_DIRECTORY)(PEHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + LoadedModules[i][1]);
                        ExportedFunctions = (PEXPORTED_DATA)(PEExports->AddressOfFunctions + LoadedModules[i][1]);
                    }
                    for(j = 0; j < PEExports->NumberOfFunctions; j++)
                    {
                        TestHash = (DWORD)EngineGlobalTracerHandler1(hProcess, (ULONG_PTR)(ExportedFunctions->ExportedItem + LoadedModules[i][1]), true, InputNumberOfInstructions);
                        if(TestHash == CompareHash)
                        {
                            APIFoundAddress = (ULONG_PTR)(ExportedFunctions->ExportedItem + LoadedModules[i][0]);
                            FoundAPI = true;
                        }
                        ExportedFunctions = (PEXPORTED_DATA)((ULONG_PTR)ExportedFunctions + 4);
                    }
                }
            }
            i++;
        }
        i = 1;
        while(EnumeratedModules[i] != NULL)
        {
            if(engineAlowModuleLoading)
            {
                if(LoadedModules[i][2] == 1)
                {
                    FreeLibrary((HMODULE)LoadedModules[i][1]);
                }
            }
            else
            {
                if(LoadedModules[i][2] == 1)
                {
                    VirtualFree((void*)LoadedModules[i][1], NULL, MEM_RELEASE);
                }
            }
            i++;
        }
    }
    return((ULONG_PTR)APIFoundAddress);
}
__declspec(dllexport) long TITCALL TracerDetectRedirection(HANDLE hProcess, ULONG_PTR AddressToTrace)
{

    int i, j;
    MEMORY_BASIC_INFORMATION MemInfo;
    DWORD KnownRedirectionIndex = NULL;
    ULONG_PTR ueNumberOfBytesRead = NULL;
    PMEMORY_CMP_HANDLER cMem;
    DWORD MemoryHash = NULL;
    DWORD MaximumReadSize = 0;
    DWORD TestAddressX86;
    DynBuf tracemem;
    LPVOID TraceMemory;
    bool HashCheck = false;

    VirtualQueryEx(hProcess, (LPVOID)AddressToTrace, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
    if(MemInfo.RegionSize > NULL)
    {
        MaximumReadSize = (DWORD)((ULONG_PTR)MemInfo.AllocationBase + MemInfo.RegionSize - AddressToTrace);
        if(MaximumReadSize > 0x1000)
        {
            MaximumReadSize = 0x1000;
            HashCheck = true;
        }
        else if(MaximumReadSize > 256)
        {
            HashCheck = true;
        }
        if(sizeof HANDLE == 4)
        {
            TraceMemory = tracemem.Allocate(MaximumReadSize);
            if(!TraceMemory)
            {
                return (NULL);
            }
            if(ReadProcessMemory(hProcess, (LPVOID)AddressToTrace, TraceMemory, MaximumReadSize, &ueNumberOfBytesRead))
            {
                cMem = (PMEMORY_CMP_HANDLER)TraceMemory;
                if(cMem->DataByte[0] == 0xEB && cMem->DataByte[1] == 0x01 && ((cMem->DataByte[3] >= 0x50 && cMem->DataByte[3] <= 0x5F) || cMem->DataByte[3] == 0x6A || cMem->DataByte[3] == 0x68))
                {
                    KnownRedirectionIndex = NULL;               // ; PeX 0.99 fail safe!
                }
                else if(cMem->DataByte[0] == 0x68 && cMem->DataByte[5] == 0x81 && cMem->DataByte[12] == 0xC3)
                {
                    KnownRedirectionIndex = 1;                  //  ; RLP 0.7.4 & CryptoPeProtector 0.9.x & ACProtect
                    /*  ;$ ==>    >  68 904B4013     PUSH 13404B90
                        ;$+5      >  812C24 0A9E589B SUB DWORD PTR SS:[ESP],9B589E0A
                        ;$+C      >  C3              RET
                        ;$+D      >  68 E21554DF     PUSH DF5415E2
                        ;$+12     >  813424 B6DCB2A8 XOR DWORD PTR SS:[ESP],A8B2DCB6
                        ;$+19     >  C3              RET
                        ;$+1A     >  68 34B2C6B1     PUSH B1C6B234
                        ;$+1F     >  810424 4A2C21C6 ADD DWORD PTR SS:[ESP],C6212C4A
                        ;$+26     >  C3              RET */
                }
                else if(cMem->DataByte[0] == 0xFF && cMem->DataByte[1] == 0x25)
                {
                    KnownRedirectionIndex = 2;                  //  ; tELock 0.80 - 0.85
                    //  ;$ ==>    >- FF25 48018E00   JMP NEAR DWORD PTR DS:[8E0148]
                }
                else if((cMem->DataByte[0] == 0xFF && cMem->DataByte[1] == 0x35) || (cMem->DataByte[1] == 0xFF && cMem->DataByte[2] == 0x35) && (cMem->DataByte[8] == 0xC3 || cMem->DataByte[9] == 0xC3))
                {
                    KnownRedirectionIndex = 3;                  //  ; tELock 0.90 - 0.95
                    /*  ;$ ==>    >  FF35 AE018E00   PUSH DWORD PTR DS:[8E01AE]               ; kernel32.InitializeCriticalSection
                        ;$+6      >  A8 C3           TEST AL,0C3
                        ;$+8      >  C3              RET
                        ;$+9      >  F9              STC
                        ;$+A      >  FF35 B2018E00   PUSH DWORD PTR DS:[8E01B2]               ; kernel32.VirtualFree
                        ;$+10     >  80FA C3         CMP DL,0C3
                        ;$+13     >  C3              RET */
                }
                else if(cMem->DataByte[0] == 0xEB && cMem->DataByte[1] == 0x01 && cMem->DataByte[2] == 0xC9 && cMem->DataByte[3] == 0x60 && cMem->DataByte[4] == 0x0F && cMem->DataByte[5] == 0x31)
                {
                    KnownRedirectionIndex = 8;                  //  ; AlexProtector 1.x
                    /*  ;$ ==>    > /EB 01           JMP SHORT 008413F9
                        ;$+2      > |C9              LEAVE
                        ;$+3      > \60              PUSHAD
                        ;$+4      >  0F31            RDTSC
                        ;$+6      >  EB 01           JMP SHORT 008413FF
                        ;$+8      >  C9              LEAVE
                        ;$+9      >  8BD8            MOV EBX,EAX
                        ;$+B      >  EB 01           JMP SHORT 00841404
                        ;...
                        ;$+33     >  68 E9B9D477     PUSH USER32.PostQuitMessage
                        ;$+38     >  EB 01           JMP SHORT 00841431
                        ;$+3A     >- E9 C3EB01E9     JMP E985FFF8 */
                }
                else if((cMem->DataByte[0] == 0x0B && cMem->DataByte[1] == 0xC5) || (cMem->DataByte[0] == 0x05 && cMem->DataByte[5] == 0xB8 && cMem->DataByte[10] == 0xEB && cMem->DataByte[11] == 0x02))
                {
                    KnownRedirectionIndex = 5;                  //  ; tELock 0.99 - 1.0 Private!
                    /*  ;008E0122    05 F9DEBE71     ADD EAX,71BEDEF9
                        ;008E0127    B8 28018E00     MOV EAX,8E0128
                        ;008E012C    EB 02           JMP SHORT 008E0130
                        ;008E012E    CD 20           INT 20
                        ;008E0130    05 18000000     ADD EAX,18
                        ;008E0135    8B00            MOV EAX,DWORD PTR DS:[EAX]
                        ;008E0137    35 22018E00     XOR EAX,8E0122
                        ;008E013C    90              NOP
                        ;008E013D    90              NOP
                        ;008E013E    50              PUSH EAX
                        ;008E013F    C3              RET
                        ;
                        ;00850036    13C4            ADC EAX,ESP
                        ;00850038    E8 0A000000     CALL 00850047
                        ;0085003D    90              NOP
                        ;0085003E    1BC2            SBB EAX,EDX
                        ;00850040    E9 09000000     JMP 0085004E
                        ;00850045    1BC3            SBB EAX,EBX
                        ;00850047    83F8 74         CMP EAX,74
                        ;0085004A    C3              RET
                        ;0085004B    98              CWDE
                        ;0085004C    33C7            XOR EAX,EDI
                        ;0085004E    D6              SALC
                        ;0085004F    B8 50008500     MOV EAX,850050
                        ;00850054    EB 02           JMP SHORT 00850058
                        ;00850056    CD 20           INT 20
                        ;00850058    05 18000000     ADD EAX,18
                        ;0085005D    8B00            MOV EAX,DWORD PTR DS:[EAX]
                        ;0085005F    35 36008500     XOR EAX,850036
                        ;00850064    90              NOP
                        ;00850065    90              NOP
                        ;00850066    50              PUSH EAX
                        ;00850067    C3              RET */
                }
                else if((cMem->DataByte[0] == 0x13 && cMem->DataByte[1] == 0xC4 && cMem->DataByte[2] == 0xE8) || (cMem->DataByte[0] == 0x83 && cMem->DataByte[3] == 0xE8))
                {
                    KnownRedirectionIndex = 5;                  //  ; tELock 0.99 - 1.0 Private!
                }
                else if((cMem->DataByte[0] == 0xB8 || cMem->DataByte[0] == 0x1D || cMem->DataByte[0] == 0x0D || cMem->DataByte[0] == 0x2D) && cMem->DataByte[5] == 0xB8 && cMem->DataByte[10] == 0xEB && cMem->DataByte[11] == 0x02)
                {
                    KnownRedirectionIndex = 5;                  //  ; tELock 0.99 - 1.0 Private!
                    /*  ;011F0000    B8 2107F205     MOV EAX,5F20721
                        ;011F0005    B8 06008D00     MOV EAX,8D0006
                        ;011F000A    EB 02           JMP SHORT 011F000E
                        ;011F000C    CD 20           INT 20
                        ;011F000E    05 18000000     ADD EAX,18
                        ;011F0013    8B00            MOV EAX,DWORD PTR DS:[EAX]
                        ;011F0015    35 00008D00     XOR EAX,8D0000
                        ;011F001A    90              NOP
                        ;011F001B    90              NOP
                        ;011F001C    50              PUSH EAX
                        ;011F001D    C3              RET
                        ;
                        ;01360000    1D A508F205     SBB EAX,5F208A5
                        ;01360005    B8 28008D00     MOV EAX,8D0028
                        ;0136000A    EB 02           JMP SHORT 0136000E
                        ;0136000C    CD 20           INT 20
                        ;0136000E    05 18000000     ADD EAX,18
                        ;01360013    8B00            MOV EAX,DWORD PTR DS:[EAX]
                        ;01360015    35 22008D00     XOR EAX,8D0022
                        ;0136001A    90              NOP
                        ;0136001B    90              NOP
                        ;0136001C    50              PUSH EAX
                        ;0136001D    C3              RET
                        ;
                        ;014B0000    0D F918F205     OR EAX,5F218F9
                        ;014B0005    B8 4A008D00     MOV EAX,8D004A
                        ;014B000A    EB 02           JMP SHORT 014B000E
                        ;014B000C    CD 20           INT 20
                        ;014B000E    05 18000000     ADD EAX,18
                        ;014B0013    8B00            MOV EAX,DWORD PTR DS:[EAX]
                        ;014B0015    35 44008D00     XOR EAX,8D0044
                        ;014B001A    90              NOP
                        ;014B001B    90              NOP
                        ;014B001C    50              PUSH EAX
                        ;014B001D    C3              RET
                        ;
                        ;01750000    2D 0B37F205     SUB EAX,5F2370B
                        ;01750005    B8 8E008D00     MOV EAX,8D008E
                        ;0175000A    EB 02           JMP SHORT 0175000E
                        ;0175000C    CD 20           INT 20
                        ;0175000E    05 18000000     ADD EAX,18
                        ;01750013    8B00            MOV EAX,DWORD PTR DS:[EAX]
                        ;01750015    35 88008D00     XOR EAX,8D0088
                        ;0175001A    90              NOP
                        ;0175001B    90              NOP
                        ;0175001C    50              PUSH EAX
                        ;0175001D    C3              RET
                        ;
                        ;019F0000    0BC4            OR EAX,ESP
                        ;019F0002    F9              STC
                        ;019F0003    E8 0B000000     CALL 019F0013
                        ;019F0008    90              NOP
                        ;019F0009    13C4            ADC EAX,ESP
                        ;019F000B    E9 0A000000     JMP 019F001A
                        ;019F0010    F9              STC
                        ;019F0011    13C3            ADC EAX,EBX
                        ;019F0013    98              CWDE
                        ;019F0014    03C2            ADD EAX,EDX
                        ;019F0016    C3              RET
                        ;
                        ;01B40000    48              DEC EAX
                        ;01B40001    E8 0D000000     CALL 01B40013
                        ;01B40006    03C5            ADD EAX,EBP
                        ;01B40008    FC              CLD
                        ;01B40009    E9 0A000000     JMP 01B40018
                        ;01B4000E    35 D82FF205     XOR EAX,5F22FD8
                        ;01B40013    C1C8 9A         ROR EAX,9A
                        ;01B40016    C3              RET */
                }
                else if((cMem->DataByte[0] == 0x0B && cMem->DataByte[1] == 0xC4 && cMem->DataByte[2] == 0xF9 && cMem->DataByte[3] == 0xE8) || (cMem->DataByte[0] == 0x48 && cMem->DataByte[1] == 0xE8))
                {
                    KnownRedirectionIndex = 5;                  //  ; tELock 0.99 - 1.0 Private!
                }
                else if((cMem->DataByte[0] == 0xB8 && cMem->DataByte[5] == 0xE8 && cMem->DataByte[10] == 0xF9 && cMem->DataByte[11] == 0xE9) && (cMem->DataByte[0] == 0xE8 && cMem->DataByte[1] == 0x0B && cMem->DataByte[10] == 0xE9 && cMem->DataByte[11] == 0x05 && cMem->DataByte[15] == 0x90 && cMem->DataByte[16] == 0xC3))
                {
                    KnownRedirectionIndex = 5;                  //  ; tELock 0.99 - 1.0 Private!
                    /*  ;01C90000    B8 B853F205     MOV EAX,5F253B8
                        ;01C90005    E8 07000000     CALL 01C90011
                        ;01C9000A    F9              STC
                        ;01C9000B    E9 07000000     JMP 01C90017
                        ;01C90010    90              NOP
                        ;01C90011    23C3            AND EAX,EBX
                        ;01C90013    C3              RET
                        ;
                        ;00A40022    1BC2            SBB EAX,EDX
                        ;00A40024    E8 08000000     CALL 00A40031
                        ;00A40029    40              INC EAX
                        ;00A4002A    E9 09000000     JMP 00A40038
                        ;00A4002F    33C7            XOR EAX,EDI
                        ;00A40031    C1E8 92         SHR EAX,92
                        ;00A40034    C3              RET
                        ;00A40035    83E0 25         AND EAX,25
                        ;00A40038    25 E5AE65DD     AND EAX,DD65AEE5
                        ;00A4003D    B8 3E00A400     MOV EAX,0A4003E
                        ;00A40042    EB 02           JMP SHORT 00A40046
                        ;00A40044    CD 20           INT 20
                        ;00A40046    05 18000000     ADD EAX,18
                        ;00A4004B    8B00            MOV EAX,DWORD PTR DS:[EAX]
                        ;00A4004D    35 2200A400     XOR EAX,0A40022
                        ;00A40052    90              NOP
                        ;00A40053    90              NOP
                        ;00A40054    50              PUSH EAX
                        ;00A40055    C3              RET
                        ;
                        ;00A4005A    E8 0B000000     CALL 00A4006A
                        ;00A4005F    15 06F265DD     ADC EAX,DD65F206
                        ;00A40064    E9 05000000     JMP 00A4006E
                        ;00A40069    90              NOP
                        ;00A4006A    C3              RET
                        ;00A4006B    1BC5            SBB EAX,EBP
                        ;00A4006D    40              INC EAX
                        ;00A4006E    1BC0            SBB EAX,EAX
                        ;00A40070    F9              STC
                        ;00A40071    B8 7200A400     MOV EAX,0A40072
                        ;00A40076    EB 02           JMP SHORT 00A4007A
                        ;00A40078    CD 20           INT 20
                        ;00A4007A    05 18000000     ADD EAX,18
                        ;00A4007F    8B00            MOV EAX,DWORD PTR DS:[EAX]
                        ;00A40081    35 5A00A400     XOR EAX,0A4005A
                        ;00A40086    90              NOP
                        ;00A40087    90              NOP
                        ;00A40088    50              PUSH EAX
                        ;00A40089    C3              RET */
                }
                else if(cMem->DataByte[0] == 0x1B && cMem->DataByte[1] == 0xC2 && cMem->DataByte[2] == 0xE8 && cMem->DataByte[3] == 0x08 && cMem->DataByte[7] == 0x40 && cMem->DataByte[8] == 0xE9 && cMem->DataByte[9] == 0x09 && cMem->DataByte[10] == 0x00)
                {
                    KnownRedirectionIndex = 5;                  //  ; tELock 0.99 - 1.0 Private!
                }
                else if(cMem->DataByte[0] == 0x68 && cMem->DataByte[5] == 0xE9)
                {
                    RtlMoveMemory(&TestAddressX86, &cMem->DataByte[1], 4);
                    if(TestAddressX86 > AddressToTrace)
                    {
                        if(ImporterGetAPIName((ULONG_PTR)TestAddressX86) != NULL)
                        {
                            KnownRedirectionIndex = 6;          //  ; ReCrypt 0.74
                            /*  ;001739F1    68 E9D9D477     PUSH User32.EndDialog
                                ;001739F6  ^ E9 FDFEFFFF     JMP 001738F8 */
                        }
                    }
                }
                else if((cMem->DataByte[0] == 0xE8 && cMem->DataByte[5] == 0x58 && cMem->DataByte[6] == 0xEB && cMem->DataByte[7] == 0x01) || (cMem->DataByte[0] == 0xC8 && cMem->DataByte[4] == 0xE8 && cMem->DataByte[9] == 0x5B))
                {
                    KnownRedirectionIndex = 7;                  //  ; Orien 2.1x
                    /* ;GetCommandLineA
                    ;$ ==>    >/$  E8 00000000     CALL crackme_.0040DF8F
                    ;$+5      >|$  58              POP EAX
                    ;$+6      >|.  EB 01           JMP SHORT crackme_.0040DF93
                    ;$+8      >|   B8              DB B8
                    ;$+9      >|>  85DB            TEST EBX,EBX
                    ;$+B      >|.  2D 8F1F0000     SUB EAX,1F8F
                    ;$+10     >|.  EB 01           JMP SHORT crackme_.0040DF9D
                    ;$+12     >|   A8              DB A8
                    ;$+13     >|>  8D80 F0550000   LEA EAX,DWORD PTR DS:[EAX+55F0]
                    ;$+19     >\.  C3              RET
                    ;GetCommandLineW
                    ;$ ==>    > .  E8 00000000     CALL crackme_.0040DFA9
                    ;$+5      >/$  58              POP EAX
                    ;$+6      >|.  EB 01           JMP SHORT crackme_.0040DFAD
                    ;$+8      >|   B8              DB B8
                    ;$+9      >|>  85DB            TEST EBX,EBX
                    ;$+B      >|.  2D A91F0000     SUB EAX,1FA9
                    ;$+10     >|.  EB 01           JMP SHORT crackme_.0040DFB7
                    ;$+12     >|   A8              DB A8
                    ;$+13     >|>  8D80 F4560000   LEA EAX,DWORD PTR DS:[EAX+56F4]
                    ;$+19     >\.  C3              RET
                    ;ExitProcess
                    ;$ ==>    > $  C8 000000       ENTER 0,0
                    ;$+4      > .  E8 00000000     CALL crackme_.0040DF2A
                    ;$+9      > $  5B              POP EBX
                    ;$+A      > .  EB 01           JMP SHORT crackme_.0040DF2E
                    ;$+C      >    B8              DB B8
                    ;$+D      > >  85DB            TEST EBX,EBX
                    ;$+F      > .  81EB 2A1F0000   SUB EBX,1F2A
                    ;$+15     > .  EB 01           JMP SHORT crackme_.0040DF39
                    ;$+17     >    A8              DB A8
                    ;$+18     > >  8D83 4D310000   LEA EAX,DWORD PTR DS:[EBX+314D]
                    ;$+1E     > .  8038 00         CMP BYTE PTR DS:[EAX],0
                    ;$+21     > .  74 29           JE SHORT crackme_.0040DF6D
                    ;$+23     > .  EB 01           JMP SHORT crackme_.0040DF47
                    ;$+25     >    A8              DB A8
                    ;$+26     > >  8D93 55380000   LEA EDX,DWORD PTR DS:[EBX+3855]
                    ;$+2C     > .  E8 01000000     CALL crackme_.0040DF53
                    ;$+31     >    E9              DB E9
                    ;$+32     > $  83EC FC         SUB ESP,-4
                    ;$+35     > .  6A 00           PUSH 0
                    ;$+37     > .  52              PUSH EDX
                    ;$+38     > .  50              PUSH EAX
                    ;$+39     > .  6A 00           PUSH 0
                    ;$+3B     > .  E8 05000000     CALL crackme_.0040DF66
                    ;$+40     > .  EB 0A           JMP SHORT crackme_.0040DF6D
                    ;$+42     >    88              DB 88
                    ;$+43     >    FC              DB FC
                    ;$+44     >    B6              DB B6
                    ;$+45     > $  FFA3 FF3A0000   JMP NEAR DWORD PTR DS:[EBX+3AFF]
                    ;$+4B     >    CD              DB CD
                    ;$+4C     > >  E8 01000000     CALL crackme_.0040DF73
                    ;$+51     >    E9              DB E9
                    ;$+52     > $  83EC FC         SUB ESP,-4
                    ;$+55     > .  FF75 08         PUSH DWORD PTR SS:[EBP+8]
                    ;$+58     > .  E8 05000000     CALL crackme_.0040DF83
                    ;$+5D     > .  EB 0A           JMP SHORT crackme_.0040DF8A
                    ;$+5F     >    88              DB 88
                    ;$+60     >    FC              DB FC
                    ;$+61     >    B6              DB B6
                    ;$+62     > $  FFA3 BF3A0000   JMP NEAR DWORD PTR DS:[EBX+3ABF] */
                }
                else if((cMem->DataByte[0] == 0xEB && cMem->DataByte[1] == 0x01 && cMem->DataByte[2] == 0x66 && cMem->DataByte[3] == 0x1B) || (cMem->DataByte[0] == 0xEB && cMem->DataByte[1] == 0x02 && cMem->DataByte[2] == 0xCD && cMem->DataByte[3] == 0x20) || (cMem->DataByte[0] == 0xEB && cMem->DataByte[1] == 0x01 && cMem->DataByte[2] == 0xB8 && cMem->DataByte[3] == 0xEB))
                {
                    KnownRedirectionIndex = 4;                  // ; tELock 0.96 - 0.98
                    /* ;(BYTE PTR[ESI] == 0EBh && (BYTE PTR[ESI+3] == 0EBh || BYTE PTR[ESI+2] == 0EBh))
                    ;017B0000    0BE4            OR ESP,ESP
                    ;017B0002    75 01           JNZ SHORT 017B0005
                    ;
                    ;15940000    85E4            TEST ESP,ESP
                    ;15940002    79 03           JNS SHORT 15940007
                    ;
                    ;008E0359    B8 8DE44500     MOV EAX,45E48D
                    ;008E035E    90              NOP
                    ;008E035F    FF30            PUSH DWORD PTR DS:[EAX]
                    ;008E0361    C3              RET
                    ;
                    ;008F0033    B8 AF008F00     MOV EAX,8F00AF
                    ;008F0038    40              INC EAX
                    ;008F0039    FF30            PUSH DWORD PTR DS:[EAX]
                    ;008F003B    C3              RET
                    ;
                    ;008E02F7    B8 20078E00     MOV EAX,8E0720
                    ;008E02FC    FF20            JMP NEAR DWORD PTR DS:[EAX] */
                }
                else if((cMem->DataByte[0] == 0xEB && cMem->DataByte[1] == 0x03 && cMem->DataByte[2] == 0xFF && cMem->DataByte[3] == 0xEB) || (cMem->DataByte[0] == 0xEB && cMem->DataByte[1] == 0x01 && cMem->DataByte[2] == 0xB8 && cMem->DataByte[3] == 0x05) || (cMem->DataByte[0] == 0xEB && cMem->DataByte[1] == 0x02 && cMem->DataByte[2] == 0xFF && cMem->DataByte[3] == 0x20))
                {
                    KnownRedirectionIndex = 4;                  // ; tELock 0.96 - 0.98
                }
                else if((cMem->DataByte[0] == 0xF9 || cMem->DataByte[0] == 0xF8) || (cMem->DataByte[0] == 0x0B && cMem->DataByte[1] == 0xE4) || (cMem->DataByte[0] == 0x85 && cMem->DataByte[1] == 0xE4))
                {
                    KnownRedirectionIndex = 4;                  // ; tELock 0.96 - 0.98
                }
                else if(cMem->DataByte[0] == 0xEB && (cMem->DataByte[1] > NULL && cMem->DataByte[1] < 4))
                {
                    i = 2;
                    j = 30;
                    while(j > NULL)
                    {
                        if(cMem->DataByte[i] == 0xB8 && (cMem->DataByte[i + 5] == 0x40 || cMem->DataByte[i + 5] == 0x90) && cMem->DataByte[i + 6] == 0xFF && cMem->DataByte[i + 7] == 0x30 && cMem->DataByte[i + 8] == 0xC3)
                        {
                            KnownRedirectionIndex = 4;          // ; tELock 0.96 - 0.98
                            j = 1;
                        }
                        i++;
                        j--;
                    }
                }
                else if(HashCheck)
                {
                    if(cMem->DataByte[0] == 0x9C || cMem->DataByte[0] == 0xEB)
                    {
                        MemoryHash = EngineHashMemory((char*)TraceMemory, 192, MemoryHash);
                        if(MemoryHash == 0x5AF7E209 || MemoryHash == 0xEB480CAC || MemoryHash == 0x86218561 || MemoryHash == 0xCA9ABD85)
                        {
                            KnownRedirectionIndex = 9;          // ; SVKP 1.x
                        }
                        else if(MemoryHash == 0xF1F84A98 || MemoryHash == 0x91823290 || MemoryHash == 0xBEE6BAA0 || MemoryHash == 0x79603232)
                        {
                            KnownRedirectionIndex = 9;          // ; SVKP 1.x
                        }
                    }
                }
                return(KnownRedirectionIndex);
            }
            else
            {
            }
        }
    }
    return(NULL);
}
__declspec(dllexport) ULONG_PTR TITCALL TracerFixKnownRedirection(HANDLE hProcess, ULONG_PTR AddressToTrace, DWORD RedirectionId)
{

    int i = NULL;
    DWORD TestAddressX86;
    DWORD ReadAddressX86;
    DWORD MemoryHash = NULL;
    PMEMORY_CMP_HANDLER cMem;
    MEMORY_BASIC_INFORMATION MemInfo;
    ULONG_PTR ueNumberOfBytesRead = NULL;
    char TracerReadMemory[0x1000] = {0};
    DWORD MaximumReadSize = 0x1000;
    cMem = (PMEMORY_CMP_HANDLER)TracerReadMemory;

    VirtualQueryEx(hProcess, (LPVOID)AddressToTrace, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
    if(MemInfo.RegionSize > NULL)
    {
        MaximumReadSize = (DWORD)((ULONG_PTR)MemInfo.BaseAddress + MemInfo.RegionSize - AddressToTrace);
        if(MaximumReadSize > 0x1000)
        {
            MaximumReadSize = 0x1000;
        }
    }
    if(RedirectionId == NULL)
    {
        RedirectionId = (DWORD)TracerDetectRedirection(hProcess, AddressToTrace);
    }
    if(RedirectionId == 1)                                              //  TracerFix_ACProtect
    {
        __try
        {
            if(ReadProcessMemory(hProcess, (LPVOID)AddressToTrace, TracerReadMemory, MaximumReadSize, &ueNumberOfBytesRead))
            {
                RtlMoveMemory(&TestAddressX86, &cMem->DataByte[1], 4);
                if(cMem->DataByte[5] == 0x81 && cMem->DataByte[6] == 0x2C)
                {
                    RtlMoveMemory(&ReadAddressX86, &cMem->DataByte[8], 4);
                    TestAddressX86 = TestAddressX86 - ReadAddressX86;
                }
                else if(cMem->DataByte[5] == 0x81 && cMem->DataByte[6] == 0x34)
                {
                    RtlMoveMemory(&ReadAddressX86, &cMem->DataByte[8], 4);
                    TestAddressX86 = TestAddressX86 ^ ReadAddressX86;
                }
                else if(cMem->DataByte[5] == 0x81 && cMem->DataByte[6] == 0x04)
                {
                    RtlMoveMemory(&ReadAddressX86, &cMem->DataByte[8], 4);
                    TestAddressX86 = TestAddressX86 + ReadAddressX86;
                }
                return((DWORD)TestAddressX86);
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            return(NULL);
        }
    }
    else if(RedirectionId == 2)                                         //  TracerFix_tELock_varA
    {
        __try
        {
            if(ReadProcessMemory(hProcess, (LPVOID)AddressToTrace, TracerReadMemory, MaximumReadSize, &ueNumberOfBytesRead))
            {
                RtlMoveMemory(&TestAddressX86, &cMem->DataByte[2], 4);
                if(ReadProcessMemory(hProcess, (LPVOID)TestAddressX86, &TestAddressX86, 4, &ueNumberOfBytesRead))
                {
                    return((DWORD)TestAddressX86);
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            return(NULL);
        }
    }
    else if(RedirectionId == 3)                                         //  TracerFix_tELock_varB
    {
        __try
        {
            if(ReadProcessMemory(hProcess, (LPVOID)AddressToTrace, TracerReadMemory, MaximumReadSize, &ueNumberOfBytesRead))
            {
                if(cMem->DataByte[0] == 0xFF && cMem->DataByte[1] == 0x35)
                {
                    RtlMoveMemory(&TestAddressX86, &cMem->DataByte[2], 4);
                }
                else
                {
                    RtlMoveMemory(&TestAddressX86, &cMem->DataByte[3], 4);
                }
                if(ReadProcessMemory(hProcess, (LPVOID)TestAddressX86, &TestAddressX86, 4, &ueNumberOfBytesRead))
                {
                    return((DWORD)TestAddressX86);
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            return(NULL);
        }
    }
    else if(RedirectionId == 4)                                         //  TracerFix_tELock_varC
    {
        __try
        {
            if(ReadProcessMemory(hProcess, (LPVOID)AddressToTrace, TracerReadMemory, MaximumReadSize, &ueNumberOfBytesRead))
            {
                i = 100;
                if(cMem->DataByte[0] == 0xEB && (cMem->DataByte[1] > 0 && cMem->DataByte[1] < 4))
                {
                    cMem = (PMEMORY_CMP_HANDLER)((ULONG_PTR)cMem + cMem->DataByte[1] + 2);
                }
                while(i > NULL && (cMem->DataByte[0] == 0xFF && (cMem->DataByte[1] == 0x20 || cMem->DataByte[1] == 0x30)))
                {
                    cMem = (PMEMORY_CMP_HANDLER)((ULONG_PTR)cMem + 1);
                    i--;
                }
                if(i != NULL && cMem->DataByte[0] == 0xFF && cMem->DataByte[1] == 0x20)
                {
                    if(cMem->DataByte[2] != 0x90)
                    {
                        cMem = (PMEMORY_CMP_HANDLER)((ULONG_PTR)cMem + 1);
                        while(i > NULL && (cMem->DataByte[0] == 0xFF && (cMem->DataByte[1] == 0x20 || cMem->DataByte[1] == 0x30)))
                        {
                            cMem = (PMEMORY_CMP_HANDLER)((ULONG_PTR)cMem + 1);
                            i--;
                        }
                    }
                }
                if(i != NULL && cMem->DataByte[0] == 0xFF && cMem->DataByte[1] == 0x30)
                {
                    cMem = (PMEMORY_CMP_HANDLER)((ULONG_PTR)cMem - 6);
                    if(cMem->DataByte[0] == 0xB8)
                    {
                        RtlMoveMemory(&TestAddressX86, &cMem->DataByte[1], 4);
                        if(cMem->DataByte[5] == 0x40)
                        {
                            TestAddressX86++;
                        }
                    }
                    else
                    {
                        RtlMoveMemory(&TestAddressX86, &cMem->DataByte[2], 4);
                    }
                    if(ReadProcessMemory(hProcess, (LPVOID)TestAddressX86, &TestAddressX86, 4, &ueNumberOfBytesRead))
                    {
                        return((DWORD)TestAddressX86);
                    }
                }
                else if(i != NULL && cMem->DataByte[0] == 0xFF && cMem->DataByte[1] == 0x20)
                {
                    cMem = (PMEMORY_CMP_HANDLER)((ULONG_PTR)cMem - 6);
                    RtlMoveMemory(&TestAddressX86, &cMem->DataByte[2], 4);
                    if(ReadProcessMemory(hProcess, (LPVOID)TestAddressX86, &TestAddressX86, 4, &ueNumberOfBytesRead))
                    {
                        return((DWORD)TestAddressX86);
                    }
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            return(NULL);
        }
    }
    else if(RedirectionId == 5)                                         //  TracerFix_tELock_varD
    {
        __try
        {
            if(ReadProcessMemory(hProcess, (LPVOID)AddressToTrace, TracerReadMemory, MaximumReadSize, &ueNumberOfBytesRead))
            {
                i = 100;
                while(i > NULL && (cMem->DataByte[0] != 0x50 || cMem->DataByte[1] != 0xC3))
                {
                    cMem = (PMEMORY_CMP_HANDLER)((ULONG_PTR)cMem + 1);
                    i--;
                }
                if(i != NULL && cMem->DataByte[0] == 0x50 && cMem->DataByte[1] == 0xC3)
                {
                    cMem = (PMEMORY_CMP_HANDLER)((ULONG_PTR)cMem - 0x16);
                    RtlMoveMemory(&ReadAddressX86, &cMem->DataByte[0x10], 4);
                    RtlMoveMemory(&TestAddressX86, &cMem->DataByte[0], 4);
                    TestAddressX86 = TestAddressX86 + 0x18;
                    if(ReadProcessMemory(hProcess, (LPVOID)TestAddressX86, &TestAddressX86, 4, &ueNumberOfBytesRead))
                    {
                        TestAddressX86 = TestAddressX86 ^ ReadAddressX86;
                        return((DWORD)TestAddressX86);
                    }
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            return(NULL);
        }
    }
    else if(RedirectionId == 6)                                         //  TracerFix_ReCrypt
    {
        __try
        {
            if(ReadProcessMemory(hProcess, (LPVOID)AddressToTrace, TracerReadMemory, MaximumReadSize, &ueNumberOfBytesRead))
            {
                RtlMoveMemory(&TestAddressX86, &cMem->DataByte[1], 4);
                return((DWORD)TestAddressX86);
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            return(NULL);
        }
    }
    else if(RedirectionId == 7)                                         //  TracerFix_Orien
    {
        __try
        {
            if(ReadProcessMemory(hProcess, (LPVOID)AddressToTrace, TracerReadMemory, MaximumReadSize, &ueNumberOfBytesRead))
            {
                if(cMem->DataByte[0] == 0xE8)
                {
                    RtlMoveMemory(&ReadAddressX86, &cMem->DataByte[0x15], 4);
                    if(ReadAddressX86 == 0x55F0)
                    {
                        TestAddressX86 = (DWORD)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetCommandLineA"));
                    }
                    else
                    {
                        TestAddressX86 = (DWORD)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetCommandLineW"));
                    }
                    return((DWORD)TestAddressX86);
                }
                else if(cMem->DataByte[0] == 0xC8)
                {
                    TestAddressX86 = (DWORD)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitProcess"));
                    return((DWORD)TestAddressX86);
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            return(NULL);
        }
    }
    else if(RedirectionId == 8)                                         //  TracerFix_AlexProtector
    {
        __try
        {
            if(ReadProcessMemory(hProcess, (LPVOID)AddressToTrace, TracerReadMemory, MaximumReadSize, &ueNumberOfBytesRead))
            {
                cMem = (PMEMORY_CMP_HANDLER)((ULONG_PTR)cMem + 0x34);
                RtlMoveMemory(&TestAddressX86, &cMem->DataByte[0], 4);
                return((DWORD)TestAddressX86);
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            return(NULL);
        }
    }
    else if(RedirectionId == 9 && MaximumReadSize > 192)                //  TracerFix_SVKP
    {
        __try
        {
            if(ReadProcessMemory(hProcess, (LPVOID)AddressToTrace, TracerReadMemory, MaximumReadSize, &ueNumberOfBytesRead))
            {
                if(cMem->DataByte[0] == 0x9C || cMem->DataByte[0] == 0xEB)
                {
                    MemoryHash = EngineHashMemory((char*)TracerReadMemory, 192, MemoryHash);
                    if(MemoryHash == 0x5AF7E209)
                    {
                        TestAddressX86 = (DWORD)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetCommandLineA"));
                    }
                    else if(MemoryHash == 0xEB480CAC)
                    {
                        TestAddressX86 = (DWORD)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitProcess"));
                    }
                    else if(MemoryHash == 0x86218561)
                    {
                        TestAddressX86 = (DWORD)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetCurrentProcess"));
                    }
                    else if(MemoryHash == 0xCA9ABD85)
                    {
                        TestAddressX86 = (DWORD)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetVersion"));
                    }
                    else if(MemoryHash == 0xF1F84A98)
                    {
                        TestAddressX86 = (DWORD)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetVersionExA"));
                    }
                    else if(MemoryHash == 0x91823290)
                    {
                        TestAddressX86 = (DWORD)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetModuleHandleA"));
                    }
                    else if(MemoryHash == 0xBEE6BAA0)
                    {
                        TestAddressX86 = (DWORD)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA"));
                    }
                    else if(MemoryHash == 0x79603232)
                    {
                        TestAddressX86 = (DWORD)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetModuleHandleA"));
                    }
                    return((DWORD)TestAddressX86);
                }
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER)
        {
            return(NULL);
        }
    }
    return(NULL);
}

// TitanEngine.Tracer.functions:
__declspec(dllexport) long TITCALL TracerFixRedirectionViaImpRecPlugin(HANDLE hProcess, char* szPluginName, ULONG_PTR AddressToTrace)
{

    int szLenght = NULL;
    HMODULE hImpRecModule = NULL;
    ULONG_PTR fImpRecTrace = NULL;
    PMEMORY_CMP_HANDLER cmpModuleName;
    ULONG_PTR remInjectSize = (ULONG_PTR)((ULONG_PTR)&injectedRemoteLoadLibrary - (ULONG_PTR)&injectedImpRec);
    char szModuleName[0x1100] = {0};
    char szGarbageFile[0x1100] = {0};
    LPVOID cModuleName = szModuleName;
    ULONG_PTR NumberOfBytesWritten;
    InjectImpRecCodeData APIData;
    DWORD TracedAddress = NULL;
    DWORD TraceAddress = NULL;
    LPVOID remStringData;
    LPVOID remCodeData;
    DWORD ThreadId;
    HANDLE hThread;
    DWORD ExitCode;
    HANDLE FileHandle;
    DWORD FileSize;
    HANDLE FileMap;
    ULONG_PTR FileMapVA;

    if(GetModuleFileNameA(engineHandle, (LPCH)szModuleName, sizeof(szModuleName) - 0x100) > NULL)
    {
        cModuleName = (LPVOID)((ULONG_PTR)cModuleName + lstrlenA((LPCSTR)szModuleName));
        cmpModuleName = (PMEMORY_CMP_HANDLER)(cModuleName);
        while(cmpModuleName->DataByte[0] != 0x5C)
        {
            cmpModuleName = (PMEMORY_CMP_HANDLER)((ULONG_PTR)cmpModuleName - 1);
        }
        cmpModuleName = (PMEMORY_CMP_HANDLER)((ULONG_PTR)cmpModuleName + 1);
        cmpModuleName->DataByte[0] = 0x00;
        lstrcpyA((LPSTR)szGarbageFile, (LPCSTR)szModuleName);
        lstrcatA((LPSTR)szGarbageFile, "garbage\\ImpRec.txt");
        lstrcatA((LPSTR)szModuleName, "imports\\ImpRec\\");
        lstrcatA((LPSTR)szModuleName, szPluginName);
        if(ReadProcessMemory(hProcess, (LPVOID)AddressToTrace, &TraceAddress, 4, &NumberOfBytesWritten))
        {
            if(RemoteLoadLibrary(hProcess, (char*)szModuleName, true))
            {
                hImpRecModule = LoadLibraryA((char*)szModuleName);
                if(hImpRecModule != NULL)
                {
                    fImpRecTrace = (ULONG_PTR)GetProcAddress(hImpRecModule, "Trace");
                    if(fImpRecTrace != NULL)
                    {
                        fImpRecTrace = fImpRecTrace - (ULONG_PTR)hImpRecModule;
                        remCodeData = VirtualAllocEx(hProcess, NULL, remInjectSize, MEM_COMMIT, PAGE_READWRITE);
                        remStringData = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
                        RtlZeroMemory(&APIData, sizeof InjectImpRecCodeData);
                        APIData.fTrace = fImpRecTrace + (ULONG_PTR)ImporterGetRemoteDLLBase(hProcess, hImpRecModule);
                        APIData.AddressToTrace = (ULONG_PTR)TraceAddress;
                        APIData.fCreateFileA = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileA"));
                        APIData.fCreateFileMappingA = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileMappingA"));
                        APIData.fCloseHandle = (ULONG_PTR)ImporterGetRemoteAPIAddress(hProcess, (ULONG_PTR)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CloseHandle"));
                        if(WriteProcessMemory(hProcess, remCodeData, (LPCVOID)&injectedImpRec, remInjectSize, &NumberOfBytesWritten))
                        {
                            WriteProcessMemory(hProcess, remStringData, &APIData, sizeof InjectImpRecCodeData, &NumberOfBytesWritten);
                            WriteProcessMemory(hProcess, (LPVOID)((ULONG_PTR)remStringData + sizeof InjectImpRecCodeData), (LPCVOID)szGarbageFile, lstrlenA((LPSTR)szGarbageFile), &NumberOfBytesWritten);
                            hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)remCodeData, remStringData, CREATE_SUSPENDED, &ThreadId);

                            NtSetInformationThread(hThread, ThreadHideFromDebugger, NULL, NULL);

                            ResumeThread(hThread);
                            WaitForSingleObject(hThread, INFINITE);
                            if(GetExitCodeThread(hThread, &ExitCode))
                            {
                                if(ExitCode != NULL)
                                {
                                    if(MapFileEx((char*)szGarbageFile, UE_ACCESS_READ, &FileHandle, &FileSize, &FileMap, &FileMapVA, NULL))
                                    {
                                        RtlMoveMemory(&TracedAddress, (LPVOID)FileMapVA, 4);
                                        UnMapFileEx(FileHandle, FileSize, FileMap, FileMapVA);
                                    }
                                    if(!DeleteFileA((LPCSTR)szGarbageFile))
                                    {
                                        HandlerCloseAllLockHandles((char*)szGarbageFile, false, true);
                                        DeleteFileA((LPCSTR)szGarbageFile);
                                    }
                                }
                            }
                        }
                        RemoteFreeLibrary(hProcess, NULL, (char*)szModuleName, true);
                        VirtualFreeEx(hProcess, remCodeData, NULL, MEM_RELEASE);
                        VirtualFreeEx(hProcess, remStringData, NULL, MEM_RELEASE);
                    }
                    else
                    {
                        RemoteFreeLibrary(hProcess, NULL, (char*)szModuleName, true);
                    }
                    FreeLibrary(hImpRecModule);
                }
            }
        }
    }
    return(TracedAddress);
}