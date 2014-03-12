#include "stdafx.h"
#include "definitions.h"
#include "Global.Debugger.h"
#include "distorm.h"

static char engineDisassembledInstruction[128];

__declspec(dllexport) void* TITCALL StaticDisassembleEx(ULONG_PTR DisassmStart, LPVOID DisassmAddress)
{
    _DecodeResult DecodingResult;
    _DecodedInst engineDecodedInstructions[MAX_DECODE_INSTRUCTIONS];
    unsigned int DecodedInstructionsCount = 0;
#if !defined(_WIN64)
    _DecodeType DecodingType = Decode32Bits;
#else
    _DecodeType DecodingType = Decode64Bits;
#endif
    MEMORY_BASIC_INFORMATION MemInfo;
    DWORD MaxDisassmSize;

    VirtualQueryEx(GetCurrentProcess(), DisassmAddress, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
    if(MemInfo.State == MEM_COMMIT)
    {
        if((ULONG_PTR)MemInfo.BaseAddress + (ULONG_PTR)MemInfo.RegionSize - (ULONG_PTR)DisassmAddress <= MAXIMUM_INSTRUCTION_SIZE)
        {
            MaxDisassmSize = (DWORD)((ULONG_PTR)MemInfo.BaseAddress + (ULONG_PTR)MemInfo.RegionSize - (ULONG_PTR)DisassmAddress - 1);
            VirtualQueryEx(GetCurrentProcess(), (LPVOID)((ULONG_PTR)DisassmAddress + (ULONG_PTR)MemInfo.RegionSize), &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
            if(MemInfo.State == MEM_COMMIT)
            {
                MaxDisassmSize = MAXIMUM_INSTRUCTION_SIZE;
            }
        }
        else
        {
            MaxDisassmSize = MAXIMUM_INSTRUCTION_SIZE;
        }
        DecodingResult = distorm_decode((ULONG_PTR)DisassmStart, (const unsigned char*)DisassmAddress, MaxDisassmSize, DecodingType, engineDecodedInstructions, MAX_DECODE_INSTRUCTIONS, &DecodedInstructionsCount);
        RtlZeroMemory(&engineDisassembledInstruction, 128);
        lstrcpyA(engineDisassembledInstruction, (LPCSTR)engineDecodedInstructions[0].mnemonic.p);
        if(engineDecodedInstructions[0].size != NULL)
        {
            lstrcatA(engineDisassembledInstruction, " ");
        }
        lstrcatA(engineDisassembledInstruction, (LPCSTR)engineDecodedInstructions[0].operands.p);
        return((char*)engineDisassembledInstruction);
    }
    else
    {
        return(NULL);
    }
}
__declspec(dllexport) void* TITCALL StaticDisassemble(LPVOID DisassmAddress)
{
    return(StaticDisassembleEx((ULONG_PTR)DisassmAddress, DisassmAddress));
}
__declspec(dllexport) void* TITCALL DisassembleEx(HANDLE hProcess, LPVOID DisassmAddress, bool ReturnInstructionType)
{

    _DecodeResult DecodingResult;
    _DecodedInst engineDecodedInstructions[MAX_DECODE_INSTRUCTIONS];
    unsigned int DecodedInstructionsCount = 0;
#if !defined(_WIN64)
    _DecodeType DecodingType = Decode32Bits;
#else
    _DecodeType DecodingType = Decode64Bits;
#endif
    ULONG_PTR ueNumberOfBytesRead = 0;
    DynBuf ueReadBuf;
    LPVOID ueReadBuffer = ueReadBuf.Allocate(0x1000);
    MEMORY_BASIC_INFORMATION MemInfo;
    DWORD MaxDisassmSize;

    if(hProcess != NULL)
    {
        VirtualQueryEx(hProcess, DisassmAddress, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
        if(MemInfo.State == MEM_COMMIT)
        {
            if((ULONG_PTR)MemInfo.BaseAddress + (ULONG_PTR)MemInfo.RegionSize - (ULONG_PTR)DisassmAddress <= MAXIMUM_INSTRUCTION_SIZE)
            {
                MaxDisassmSize = (DWORD)((ULONG_PTR)MemInfo.BaseAddress + (ULONG_PTR)MemInfo.RegionSize - (ULONG_PTR)DisassmAddress - 1);
                VirtualQueryEx(hProcess, (LPVOID)((ULONG_PTR)DisassmAddress + (ULONG_PTR)MemInfo.RegionSize), &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
                if(MemInfo.State == MEM_COMMIT)
                {
                    MaxDisassmSize = MAXIMUM_INSTRUCTION_SIZE;
                }
            }
            else
            {
                MaxDisassmSize = MAXIMUM_INSTRUCTION_SIZE;
            }
            bool isbp=false;
            if(IsBPXEnabled((ULONG_PTR)DisassmAddress))
            {
                isbp=true;
                DisableBPX((ULONG_PTR)DisassmAddress);
            }
            BOOL rpm=ReadProcessMemory(hProcess, (LPVOID)DisassmAddress, ueReadBuffer, MaxDisassmSize, &ueNumberOfBytesRead);
            if(isbp)
            {
                EnableBPX((ULONG_PTR)DisassmAddress);
            }
            if(rpm)
            {
                DecodingResult = distorm_decode((ULONG_PTR)DisassmAddress, (const unsigned char*)ueReadBuffer, MaxDisassmSize, DecodingType, engineDecodedInstructions, MAX_DECODE_INSTRUCTIONS, &DecodedInstructionsCount);
                RtlZeroMemory(&engineDisassembledInstruction, 128);
                lstrcpyA(engineDisassembledInstruction, (LPCSTR)engineDecodedInstructions[0].mnemonic.p);
                if(!ReturnInstructionType)
                {
                    if(engineDecodedInstructions[0].size != NULL)
                    {
                        lstrcatA(engineDisassembledInstruction, " ");
                    }
                    lstrcatA(engineDisassembledInstruction, (LPCSTR)engineDecodedInstructions[0].operands.p);
                }
                return((char*)engineDisassembledInstruction);
            }
            else
            {
                return(NULL);
            }
        }
        else
        {
            return(NULL);
        }
    }
    else
    {
        return(NULL);
    }
}
__declspec(dllexport) void* TITCALL Disassemble(LPVOID DisassmAddress)
{
    return(DisassembleEx(dbgProcessInformation.hProcess, DisassmAddress, false));
}
__declspec(dllexport) long TITCALL StaticLengthDisassemble(LPVOID DisassmAddress)
{
    return LengthDisassembleEx(GetCurrentProcess(), DisassmAddress);
}
__declspec(dllexport) long TITCALL LengthDisassembleEx(HANDLE hProcess, LPVOID DisassmAddress)
{
    unsigned int DecodedInstructionsCount = 0;
#if !defined(_WIN64)
    _DecodeType DecodingType = Decode32Bits;
#else
    _DecodeType DecodingType = Decode64Bits;
#endif
    _CodeInfo decomposerCi = {0};
    _DInst decomposerResult[2] = {0};
    BYTE readBuffer[20] = {0}; //The maximum length of an Intel 64 and IA-32 instruction remains 15 bytes, but we are generous

    if(hProcess != NULL)
    {
        if (MemoryReadSafe(hProcess, (LPVOID)DisassmAddress, readBuffer, sizeof(readBuffer), 0))
        {
            decomposerCi.code = readBuffer;
            decomposerCi.codeLen = sizeof(readBuffer);
            decomposerCi.dt = DecodingType;
            decomposerCi.codeOffset = (LONG_PTR)DisassmAddress;

            if (distorm_decompose(&decomposerCi, decomposerResult, _countof(decomposerResult), &DecodedInstructionsCount) != DECRES_INPUTERR)
            {
                if (decomposerResult[0].flags != FLAG_NOT_DECODABLE)
                {
                    return decomposerResult[0].size;
                }
            }
        }
    }

    return -1;
}
__declspec(dllexport) long TITCALL LengthDisassemble(LPVOID DisassmAddress)
{
    return LengthDisassembleEx(dbgProcessInformation.hProcess, DisassmAddress);
}