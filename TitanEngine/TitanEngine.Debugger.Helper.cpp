#include "stdafx.h"
#include "definitions.h"
#include "Global.Debugger.h"
#include "Global.Engine.Context.h"

static char szParameterString[512];

__declspec(dllexport) bool TITCALL GetRemoteString(HANDLE hProcess, LPVOID StringAddress, LPVOID StringStorage, int MaximumStringSize)
{

    MEMORY_BASIC_INFORMATION MemInfo;
    ULONG_PTR ueNumberOfBytesRW = NULL;
    DWORD StringReadSize = NULL;

    if(MaximumStringSize == NULL)
    {
        MaximumStringSize = 512;
    }
    VirtualQueryEx(hProcess, (LPVOID)StringAddress, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION));
    if((int)((ULONG_PTR)MemInfo.BaseAddress + (ULONG_PTR)MemInfo.RegionSize - (ULONG_PTR)StringAddress) < MaximumStringSize)
    {
        StringReadSize = (DWORD)((ULONG_PTR)StringAddress - (ULONG_PTR)MemInfo.BaseAddress);
        VirtualQueryEx(hProcess, (LPVOID)((ULONG_PTR)StringAddress + (ULONG_PTR)MemInfo.RegionSize), &MemInfo, sizeof(MEMORY_BASIC_INFORMATION));
        if(MemInfo.State == MEM_COMMIT)
        {
            StringReadSize = MaximumStringSize;
        }
    }
    else
    {
        StringReadSize = MaximumStringSize;
    }
    RtlZeroMemory(StringStorage, MaximumStringSize);
    if(ReadProcessMemory(hProcess, (LPVOID)StringAddress, StringStorage, StringReadSize, &ueNumberOfBytesRW))
    {
        return true;
    }
    else
    {
        return false;
    }
}
__declspec(dllexport) ULONG_PTR TITCALL GetFunctionParameter(HANDLE hProcess, DWORD FunctionType, DWORD ParameterNumber, DWORD ParameterType)
{

    MEMORY_BASIC_INFORMATION MemInfo;
    ULONG_PTR ueNumberOfBytesRW = NULL;
    ULONG_PTR StackReadBuffer = NULL;
    ULONG_PTR StackFinalBuffer = NULL;
    ULONG_PTR StackReadAddress = NULL;
    DWORD StackSecondReadSize = NULL;
    DWORD StackReadSize = 512;
    DWORD StringReadSize = 512;
    bool ValueIsPointer = false;
    auto mode = EngineGetCurrentContextMode();
    SIZE_T pointerSize = EngineGetContextPointerSize(mode);

    if(ParameterType == UE_PARAMETER_BYTE)
    {
        StackReadSize = 1;
    }
    else if(ParameterType == UE_PARAMETER_WORD)
    {
        StackReadSize = 2;
    }
    else if(ParameterType == UE_PARAMETER_DWORD)
    {
        StackReadSize = 4;
    }
    else if(ParameterType == UE_PARAMETER_QWORD)
    {
        StackReadSize = 8;
    }
    else
    {
        if(ParameterType >= UE_PARAMETER_PTR_BYTE && ParameterType <= UE_PARAMETER_UNICODE)
        {
            ValueIsPointer = true;
        }
        if(ParameterType == UE_PARAMETER_PTR_BYTE)
        {
            StackSecondReadSize = 1;
        }
        else if(ParameterType == UE_PARAMETER_PTR_WORD)
        {
            StackSecondReadSize = 2;
        }
        else if(ParameterType == UE_PARAMETER_PTR_DWORD)
        {
            StackSecondReadSize = 4;
        }
        else if(ParameterType == UE_PARAMETER_PTR_QWORD)
        {
            StackSecondReadSize = 8;
        }
        else
        {
            StackSecondReadSize = 0;
        }
        StackReadSize = (DWORD)pointerSize;
    }
    if(FunctionType >= UE_FUNCTION_STDCALL && FunctionType <= UE_FUNCTION_FASTCALL_CALL && FunctionType != UE_FUNCTION_FASTCALL_RET)
    {
        StackReadAddress = (ULONG_PTR)GetContextData(UE_CSP);
        if(FunctionType != UE_FUNCTION_FASTCALL_CALL)
        {
            StackReadAddress = StackReadAddress + (ParameterNumber * pointerSize);
            if(FunctionType >= UE_FUNCTION_STDCALL_CALL)
            {
                StackReadAddress = StackReadAddress - pointerSize;
            }
        }
        else
        {
            DWORD registerCount = mode == EngineContextMode::X86 ? 2 : 4;
            if(ParameterNumber <= registerCount)
            {
                static const DWORD x86Registers[] = { UE_ECX, UE_EDX };
                static const DWORD x64Registers[] = { UE_RCX, UE_RDX, UE_R8, UE_R9 };
                DWORD registerIndex = mode == EngineContextMode::X86
                                      ? x86Registers[ParameterNumber - 1]
                                      : x64Registers[ParameterNumber - 1];
                ULONG_PTR registerValue = (ULONG_PTR)GetContextData(registerIndex);
                if(!ValueIsPointer)
                    return registerValue;
                StackReadAddress = registerValue;
            }
            else
            {
                SIZE_T shadowSpace = mode == EngineContextMode::X86 ? 0 : 0x20;
                StackReadAddress += shadowSpace + ((ParameterNumber - registerCount) * pointerSize) - pointerSize;
            }
        }
        SIZE_T initialReadSize = ValueIsPointer ? pointerSize : (StackReadSize < sizeof(StackReadBuffer) ? StackReadSize : sizeof(StackReadBuffer));
        if(ReadProcessMemory(hProcess, (LPVOID)StackReadAddress, &StackReadBuffer, initialReadSize, &ueNumberOfBytesRW))
        {
            if(!ValueIsPointer)
            {
                RtlMoveMemory(&StackFinalBuffer, &StackReadBuffer, StackReadSize);
            }
            else
            {
                StackReadAddress = StackReadBuffer;
                if(StackSecondReadSize > NULL)
                {
                    if(ReadProcessMemory(hProcess, (LPVOID)StackReadAddress, &StackReadBuffer, StackSecondReadSize, &ueNumberOfBytesRW))
                    {
                        RtlMoveMemory(&StackFinalBuffer, &StackReadBuffer, StackSecondReadSize);
                    }
                    else
                    {
                        return(-1);
                    }
                }
                else
                {
                    VirtualQueryEx(hProcess, (LPVOID)StackReadAddress, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION));
                    if((ULONG_PTR)MemInfo.BaseAddress + (ULONG_PTR)MemInfo.RegionSize - StackReadAddress < 512)
                    {
                        StringReadSize = (DWORD)((ULONG_PTR)StackReadAddress - (ULONG_PTR)MemInfo.BaseAddress);
                        VirtualQueryEx(hProcess, (LPVOID)(StackReadAddress + (ULONG_PTR)MemInfo.RegionSize), &MemInfo, sizeof(MEMORY_BASIC_INFORMATION));
                        if(MemInfo.State == MEM_COMMIT)
                        {
                            StringReadSize = 512;
                        }
                    }
                    RtlZeroMemory(&szParameterString, 512);
                    if(ReadProcessMemory(hProcess, (LPVOID)StackReadAddress, &szParameterString, StringReadSize, &ueNumberOfBytesRW))
                    {
                        return((ULONG_PTR)&szParameterString);
                    }
                    else
                    {
                        return(-1);
                    }
                }
            }
            return(StackFinalBuffer);
        }
        else
        {
            return(-1);
        }
    }
    return(-1);
}
__declspec(dllexport) ULONG_PTR TITCALL GetJumpDestinationEx(HANDLE hProcess, ULONG_PTR InstructionAddress, bool JustJumps)
{

    char ReadMemory[MAXIMUM_INSTRUCTION_SIZE] = {0};
    MEMORY_BASIC_INFORMATION MemInfo;
    ULONG_PTR ueNumberOfBytesRead = NULL;
    PMEMORY_CMP_HANDLER CompareMemory;
    ULONG_PTR TargetedAddress = NULL;
    DWORD CurrentInstructionSize;
    int ReadMemData = NULL;
    BYTE ReadByteData = NULL;
    bool is32Bit = EngineGetCurrentContextMode() == EngineContextMode::X86;

    if(hProcess != NULL)
    {
        VirtualQueryEx(hProcess, (LPVOID)InstructionAddress, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION));
        if(MemInfo.RegionSize > NULL)
        {
            if(ReadProcessMemory(hProcess, (LPVOID)InstructionAddress, ReadMemory, MAXIMUM_INSTRUCTION_SIZE, &ueNumberOfBytesRead))
            {
                CompareMemory = (PMEMORY_CMP_HANDLER)ReadMemory;
                CurrentInstructionSize = EngineStaticLengthDisassemble(ReadMemory, is32Bit);
                if(CompareMemory->DataByte[0] == 0xE9 && CurrentInstructionSize == 5)
                {
                    RtlMoveMemory(&ReadMemData, (LPVOID)((ULONG_PTR)ReadMemory + 1), 4);
                    TargetedAddress = ReadMemData + InstructionAddress + CurrentInstructionSize;
                }
                else if(CompareMemory->DataByte[0] == 0xEB && CurrentInstructionSize == 2)
                {
                    RtlMoveMemory(&ReadByteData, (LPVOID)((ULONG_PTR)ReadMemory + 1), 1);
                    if(ReadByteData > 0x7F)
                    {
                        ReadByteData = 0xFF - ReadByteData;
                        ReadMemData = NULL - ReadByteData - CurrentInstructionSize + 1;
                    }
                    else
                    {
                        ReadMemData = ReadByteData;
                    }
                    TargetedAddress = InstructionAddress + ReadMemData + CurrentInstructionSize;
                }
                else if(CompareMemory->DataByte[0] == 0xE3 && CurrentInstructionSize == 2)
                {
                    RtlMoveMemory(&ReadByteData, (LPVOID)((ULONG_PTR)ReadMemory + 1), 1);
                    if(ReadByteData > 0x7F)
                    {
                        ReadByteData = 0xFF - ReadByteData;
                        ReadMemData = NULL - ReadByteData - CurrentInstructionSize + 1;
                    }
                    else
                    {
                        ReadMemData = ReadByteData;
                    }
                    TargetedAddress = InstructionAddress + ReadMemData + CurrentInstructionSize;
                }
                else if(CompareMemory->DataByte[0] >= 0x71 && CompareMemory->DataByte[0] <= 0x7F && CurrentInstructionSize == 2)
                {
                    RtlMoveMemory(&ReadByteData, (LPVOID)((ULONG_PTR)ReadMemory + 1), 1);
                    if(ReadByteData > 0x7F)
                    {
                        ReadByteData = 0xFF - ReadByteData;
                        ReadMemData = NULL - ReadByteData - CurrentInstructionSize + 1;
                    }
                    TargetedAddress = InstructionAddress + ReadMemData + CurrentInstructionSize;
                }
                else if(CompareMemory->DataByte[0] >= 0xE0 && CompareMemory->DataByte[0] <= 0xE2 && CurrentInstructionSize == 2)
                {
                    RtlMoveMemory(&ReadByteData, (LPVOID)((ULONG_PTR)ReadMemory + 1), 1);
                    if(ReadByteData > 0x7F)
                    {
                        ReadByteData = 0xFF - ReadByteData;
                        ReadMemData = NULL - ReadByteData - CurrentInstructionSize + 1;
                    }
                    else
                    {
                        ReadMemData = ReadByteData;
                    }
                    TargetedAddress = InstructionAddress + ReadMemData + CurrentInstructionSize;
                }
                else if(CompareMemory->DataByte[0] == 0x0F && CompareMemory->DataByte[1] >= 0x81 && CompareMemory->DataByte[1] <= 0x8F && CurrentInstructionSize == 6)
                {
                    RtlMoveMemory(&ReadMemData, (LPVOID)((ULONG_PTR)ReadMemory + 2), 4);
                    TargetedAddress = ReadMemData + InstructionAddress + CurrentInstructionSize;
                }
                else if(CompareMemory->DataByte[0] == 0x0F && CompareMemory->DataByte[1] >= 0x81 && CompareMemory->DataByte[1] <= 0x8F && CurrentInstructionSize == 4)
                {
                    ReadMemData = 0;
                    RtlMoveMemory(&ReadMemData, (LPVOID)((ULONG_PTR)ReadMemory + 2), 2);
                    TargetedAddress = ReadMemData + InstructionAddress + CurrentInstructionSize;
                }
                else if(CompareMemory->DataByte[0] == 0xE8 && CurrentInstructionSize == 5 && JustJumps == false)
                {
                    RtlMoveMemory(&ReadMemData, (LPVOID)((ULONG_PTR)ReadMemory + 1), 4);
                    TargetedAddress = ReadMemData + InstructionAddress + CurrentInstructionSize;
                }
                else if(CompareMemory->DataByte[0] == 0xFF && CompareMemory->DataByte[1] == 0x25 && CurrentInstructionSize == 6)
                {
                    RtlMoveMemory(&ReadMemData, (LPVOID)((ULONG_PTR)ReadMemory + 2), 4);
                    TargetedAddress = ReadMemData;
                    if(!is32Bit)
                    {
                        TargetedAddress = TargetedAddress + InstructionAddress;
                    }
                }
                else if(CompareMemory->DataByte[0] == 0xFF && CompareMemory->DataByte[1] == 0x15 && CurrentInstructionSize == 6 && JustJumps == false)
                {
                    RtlMoveMemory(&ReadMemData, (LPVOID)((ULONG_PTR)ReadMemory + 2), 4);
                    TargetedAddress = ReadMemData;
                    if(!is32Bit)
                    {
                        TargetedAddress = TargetedAddress + InstructionAddress;
                    }
                }
                else if(CompareMemory->DataByte[0] == 0xFF && CompareMemory->DataByte[1] != 0x64 && CompareMemory->DataByte[1] >= 0x60 && CompareMemory->DataByte[1] <= 0x67 && CurrentInstructionSize == 3)
                {
                    ReadMemData = 0;
                    RtlMoveMemory(&ReadMemData, (LPVOID)((ULONG_PTR)ReadMemory + 2), 1);
                    TargetedAddress = ReadMemData;
                    if(CompareMemory->DataByte[1] == 0x60)
                    {
                        TargetedAddress = TargetedAddress + (ULONG_PTR)GetContextData(UE_EAX);
                    }
                    else if(CompareMemory->DataByte[1] == 0x61)
                    {
                        TargetedAddress = TargetedAddress + (ULONG_PTR)GetContextData(UE_ECX);
                    }
                    else if(CompareMemory->DataByte[1] == 0x62)
                    {
                        TargetedAddress = TargetedAddress + (ULONG_PTR)GetContextData(UE_EDX);
                    }
                    else if(CompareMemory->DataByte[1] == 0x63)
                    {
                        TargetedAddress = TargetedAddress + (ULONG_PTR)GetContextData(UE_EBX);
                    }
                    else if(CompareMemory->DataByte[1] == 0x65)
                    {
                        TargetedAddress = TargetedAddress + (ULONG_PTR)GetContextData(UE_EBP);
                    }
                    else if(CompareMemory->DataByte[1] == 0x66)
                    {
                        TargetedAddress = TargetedAddress + (ULONG_PTR)GetContextData(UE_ESI);
                    }
                    else if(CompareMemory->DataByte[1] == 0x67)
                    {
                        TargetedAddress = TargetedAddress + (ULONG_PTR)GetContextData(UE_EDI);
                    }
                    ReadProcessMemory(hProcess, (LPVOID)TargetedAddress, &TargetedAddress, 4, &ueNumberOfBytesRead);
                }
            }
            return((ULONG_PTR)TargetedAddress);
        }
        return(NULL);
    }
    else
    {
        CompareMemory = (PMEMORY_CMP_HANDLER)InstructionAddress;
        CurrentInstructionSize = EngineStaticLengthDisassemble((LPVOID)InstructionAddress, is32Bit);
        if(CompareMemory->DataByte[0] == 0xE9 && CurrentInstructionSize == 5)
        {
            RtlMoveMemory(&ReadMemData, (LPVOID)((ULONG_PTR)InstructionAddress + 1), 4);
            TargetedAddress = ReadMemData + InstructionAddress + CurrentInstructionSize;
        }
        else if(CompareMemory->DataByte[0] == 0xEB && CurrentInstructionSize == 2)
        {
            RtlMoveMemory(&ReadByteData, (LPVOID)((ULONG_PTR)InstructionAddress + 1), 1);
            if(ReadByteData > 0x7F)
            {
                ReadByteData = 0xFF - ReadByteData;
                ReadMemData = NULL - ReadByteData - CurrentInstructionSize + 1;
            }
            else
            {
                ReadMemData = ReadByteData;
            }
            TargetedAddress = InstructionAddress + ReadMemData + CurrentInstructionSize;
        }
        else if(CompareMemory->DataByte[0] == 0xE3 && CurrentInstructionSize == 2)
        {
            RtlMoveMemory(&ReadByteData, (LPVOID)((ULONG_PTR)InstructionAddress + 1), 1);
            if(ReadByteData > 0x7F)
            {
                ReadByteData = 0xFF - ReadByteData;
                ReadMemData = NULL - ReadByteData - CurrentInstructionSize + 1;
            }
            else
            {
                ReadMemData = ReadByteData;
            }
            TargetedAddress = InstructionAddress + ReadMemData + CurrentInstructionSize;
        }
        else if(CompareMemory->DataByte[0] >= 0x71 && CompareMemory->DataByte[0] <= 0x7F && CurrentInstructionSize == 2)
        {
            RtlMoveMemory(&ReadByteData, (LPVOID)((ULONG_PTR)InstructionAddress + 1), 1);
            if(ReadByteData > 0x7F)
            {
                ReadByteData = 0xFF - ReadByteData;
                ReadMemData = NULL - ReadByteData - CurrentInstructionSize + 1;
            }
            TargetedAddress = InstructionAddress + ReadMemData + CurrentInstructionSize;
        }
        else if(CompareMemory->DataByte[0] >= 0xE0 && CompareMemory->DataByte[0] <= 0xE2 && CurrentInstructionSize == 2)
        {
            RtlMoveMemory(&ReadByteData, (LPVOID)((ULONG_PTR)InstructionAddress + 1), 1);
            if(ReadByteData > 0x7F)
            {
                ReadByteData = 0xFF - ReadByteData;
                ReadMemData = NULL - ReadByteData - CurrentInstructionSize + 1;
            }
            else
            {
                ReadMemData = ReadByteData;
            }
            TargetedAddress = InstructionAddress + ReadMemData + CurrentInstructionSize;
        }
        else if(CompareMemory->DataByte[0] == 0x0F && CompareMemory->DataByte[1] >= 0x81 && CompareMemory->DataByte[1] <= 0x8F && CurrentInstructionSize == 6)
        {
            RtlMoveMemory(&ReadMemData, (LPVOID)((ULONG_PTR)InstructionAddress + 2), 4);
            TargetedAddress = ReadMemData + InstructionAddress + CurrentInstructionSize;
        }
        else if(CompareMemory->DataByte[0] == 0x0F && CompareMemory->DataByte[1] >= 0x81 && CompareMemory->DataByte[1] <= 0x8F && CurrentInstructionSize == 4)
        {
            ReadMemData = 0;
            RtlMoveMemory(&ReadMemData, (LPVOID)((ULONG_PTR)InstructionAddress + 2), 2);
            TargetedAddress = ReadMemData + InstructionAddress + CurrentInstructionSize;
        }
        else if(CompareMemory->DataByte[0] == 0xE8 && CurrentInstructionSize == 5 && JustJumps == false)
        {
            RtlMoveMemory(&ReadMemData, (LPVOID)((ULONG_PTR)InstructionAddress + 1), 4);
            TargetedAddress = ReadMemData + InstructionAddress + CurrentInstructionSize;
        }
        else if(CompareMemory->DataByte[0] == 0xFF && CompareMemory->DataByte[1] == 0x25 && CurrentInstructionSize == 6)
        {
            RtlMoveMemory(&ReadMemData, (LPVOID)((ULONG_PTR)InstructionAddress + 2), 4);
            TargetedAddress = ReadMemData;
            if(!is32Bit)
            {
                TargetedAddress = TargetedAddress + InstructionAddress;
            }
        }
        else if(CompareMemory->DataByte[0] == 0xFF && CompareMemory->DataByte[1] == 0x15 && CurrentInstructionSize == 6 && JustJumps == false)
        {
            RtlMoveMemory(&ReadMemData, (LPVOID)((ULONG_PTR)InstructionAddress + 2), 4);
            TargetedAddress = ReadMemData;
            if(!is32Bit)
            {
                TargetedAddress = TargetedAddress + InstructionAddress;
            }
        }
        else if(CompareMemory->DataByte[0] == 0xFF && CompareMemory->DataByte[1] != 0x64 && CompareMemory->DataByte[1] >= 0x60 && CompareMemory->DataByte[1] <= 0x67 && CurrentInstructionSize == 3)
        {
            ReadMemData = 0;
            RtlMoveMemory(&ReadMemData, (LPVOID)((ULONG_PTR)InstructionAddress + 2), 1);
            TargetedAddress = ReadMemData;
            if(CompareMemory->DataByte[1] == 0x60)
            {
                TargetedAddress = TargetedAddress + (ULONG_PTR)GetContextData(UE_EAX);
            }
            else if(CompareMemory->DataByte[1] == 0x61)
            {
                TargetedAddress = TargetedAddress + (ULONG_PTR)GetContextData(UE_ECX);
            }
            else if(CompareMemory->DataByte[1] == 0x62)
            {
                TargetedAddress = TargetedAddress + (ULONG_PTR)GetContextData(UE_EDX);
            }
            else if(CompareMemory->DataByte[1] == 0x63)
            {
                TargetedAddress = TargetedAddress + (ULONG_PTR)GetContextData(UE_EBX);
            }
            else if(CompareMemory->DataByte[1] == 0x65)
            {
                TargetedAddress = TargetedAddress + (ULONG_PTR)GetContextData(UE_EBP);
            }
            else if(CompareMemory->DataByte[1] == 0x66)
            {
                TargetedAddress = TargetedAddress + (ULONG_PTR)GetContextData(UE_ESI);
            }
            else if(CompareMemory->DataByte[1] == 0x67)
            {
                TargetedAddress = TargetedAddress + (ULONG_PTR)GetContextData(UE_EDI);
            }
            RtlMoveMemory(&TargetedAddress, (LPVOID)((ULONG_PTR)TargetedAddress), 4);
        }
        return((ULONG_PTR)TargetedAddress);
    }
    return(NULL);
}
__declspec(dllexport) ULONG_PTR TITCALL GetJumpDestination(HANDLE hProcess, ULONG_PTR InstructionAddress)
{
    return((ULONG_PTR)GetJumpDestinationEx(hProcess, InstructionAddress, false));
}
__declspec(dllexport) bool TITCALL IsJumpGoingToExecuteEx(HANDLE hProcess, HANDLE hThread, ULONG_PTR InstructionAddress, ULONG_PTR RegFlags)
{
    ULONG_PTR ThreadCIP = NULL;
    DWORD ThreadEflags = NULL;
    char* DisassembledString;
    bool bCF = false;
    bool bPF = false;
    bool bAF = false;
    bool bZF = false;
    bool bSF = false;
    bool bTF = false;
    bool bIF = false;
    bool bDF = false;
    bool bOF = false;

    if(hProcess != NULL && (hThread || RegFlags))
    {
        if(InstructionAddress == NULL)
        {
            ThreadCIP = (ULONG_PTR)GetContextDataEx(hThread, UE_CIP);
        }
        else
        {
            ThreadCIP = InstructionAddress;
        }
        if(RegFlags == NULL)
        {
            ThreadEflags = (DWORD)GetContextDataEx(hThread, UE_EFLAGS);
        }
        else
        {
            ThreadEflags = (DWORD)RegFlags;
        }
        auto mode = hThread != NULL ? EngineGetThreadContextMode(hThread) : EngineGetCurrentContextMode();
        DisassembledString = (char*)EngineDisassembleEx(hProcess, (LPVOID)ThreadCIP, true, mode == EngineContextMode::X86);
        if(DisassembledString != NULL)
        {
            if(ThreadEflags & (1 << 0))
            {
                bCF = true;
            }
            if(ThreadEflags & (1 << 2))
            {
                bPF = true;
            }
            if(ThreadEflags & (1 << 4))
            {
                bAF = true;
            }
            if(ThreadEflags & (1 << 6))
            {
                bZF = true;
            }
            if(ThreadEflags & (1 << 7))
            {
                bSF = true;
            }
            if(ThreadEflags & (1 << 8))
            {
                bTF = true;
            }
            if(ThreadEflags & (1 << 9))
            {
                bIF = true;
            }
            if(ThreadEflags & (1 << 10))
            {
                bDF = true;
            }
            if(ThreadEflags & (1 << 11))
            {
                bOF = true;
            }
            if(lstrcmpiA(DisassembledString, "RET") == NULL)
            {
                return (true);
            }
            else if(lstrcmpiA(DisassembledString, "RETF") == NULL)
            {
                return (true);
            }
            else if(lstrcmpiA(DisassembledString, "JMP") == NULL)
            {
                return true;
            }
            else if(lstrcmpiA(DisassembledString, "JA") == NULL)
            {
                if(bCF == false && bZF == false)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JAE") == NULL)
            {
                if(!bCF)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JB") == NULL)
            {
                if(bCF)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JBE") == NULL)
            {
                if(bCF == true || bZF == true)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JC") == NULL)
            {
                if(bCF)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JCXZ") == NULL)
            {
                if((WORD)GetContextDataEx(hThread, UE_ECX) == NULL)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JECXZ") == NULL)
            {
                if((DWORD)GetContextDataEx(hThread, UE_ECX) == NULL)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JRCXZ") == NULL)
            {
                if((ULONG_PTR)GetContextDataEx(hThread, UE_RCX) == NULL)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JZ") == NULL)
            {
                if(bZF)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JNZ") == NULL)
            {
                if(!bZF)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JE") == NULL)
            {
                if(bZF)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JNE") == NULL)
            {
                if(!bZF)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JG") == NULL)
            {
                if(bZF == false && bSF == bOF)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JGE") == NULL)
            {
                if(bSF == bOF)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JL") == NULL)
            {
                if(bSF != bOF)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JLE") == NULL)
            {
                if(bZF == true || bSF != bOF)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JNA") == NULL)
            {
                if(bCF == true || bZF == true)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JNAE") == NULL)
            {
                if(bCF)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JNB") == NULL)
            {
                if(!bCF)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JNBE") == NULL)
            {
                if(bCF == false && bZF == false)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JNC") == NULL)
            {
                if(!bCF)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JNG") == NULL)
            {
                if(bZF == true || bSF != bOF)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JNGE") == NULL)
            {
                if(bSF != bOF)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JNL") == NULL)
            {
                if(bSF == bOF)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JNLE") == NULL)
            {
                if(bZF == false && bSF == bOF)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JNO") == NULL)
            {
                if(!bOF)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JNP") == NULL)
            {
                if(!bPF)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JNS") == NULL)
            {
                if(!bSF)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JO") == NULL)
            {
                if(bOF)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JP") == NULL)
            {
                if(bPF)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JPE") == NULL)
            {
                if(bPF)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JPO") == NULL)
            {
                if(!bPF)
                {
                    return true;
                }
            }
            else if(lstrcmpiA(DisassembledString, "JS") == NULL)
            {
                if(bSF)
                {
                    return true;
                }
            }
        }
    }
    return false;
}
__declspec(dllexport) bool TITCALL IsJumpGoingToExecute()
{
    return(IsJumpGoingToExecuteEx(dbgProcessInformation.hProcess, dbgProcessInformation.hThread, NULL, NULL));
}
