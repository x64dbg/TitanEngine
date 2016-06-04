#include "stdafx.h"
#include "definitions.h"
#include "Global.Debugger.h"
#include "distorm.h"

static char engineDisassembledInstruction[128];

#if !defined(_WIN64)
_DecodeType DecodingType = Decode32Bits;
#else
_DecodeType DecodingType = Decode64Bits;
#endif


SIZE_T IsBadReadPtrRemote(HANDLE hProcess, const VOID* lp, SIZE_T length)
{
    MEMORY_BASIC_INFORMATION MemInfo = {0};
    ULONG_PTR section = 0;

    if(VirtualQueryEx(hProcess, lp, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
    {
        if(MemInfo.State == MEM_COMMIT)
        {
            SIZE_T res = (SIZE_T)MemInfo.BaseAddress + (SIZE_T)MemInfo.RegionSize - (SIZE_T)lp;
            if(res >= length)
            {
                return length; //good
            }
            else
            {
                section = ((ULONG_PTR)MemInfo.BaseAddress + (ULONG_PTR)MemInfo.RegionSize);

                do
                {
                    if(VirtualQueryEx(hProcess, (LPVOID)section, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
                    {
                        if(MemInfo.State == MEM_COMMIT)
                        {
                            res += MemInfo.RegionSize;
                        }
                        else
                        {
                            return res; //this is bad
                        }
                    }
                    else
                    {
                        return res; //this is bad
                    }

                    section += (ULONG_PTR)MemInfo.RegionSize;

                }
                while(res < length);

                return length; //good
            }
        }

    }

    return 0;
}

__declspec(dllexport) void* TITCALL StaticDisassembleEx(ULONG_PTR DisassmStart, LPVOID DisassmAddress)
{
    _DecodedInst engineDecodedInstructions[1];
    unsigned int DecodedInstructionsCount = 0;

    int MaxDisassmSize = MAXIMUM_INSTRUCTION_SIZE; // (int)IsBadReadPtrRemote(GetCurrentProcess(), DisassmAddress, MAXIMUM_INSTRUCTION_SIZE);
    if(MaxDisassmSize)
    {
        if(distorm_decode((ULONG_PTR)DisassmStart, (const unsigned char*)DisassmAddress, MaxDisassmSize, DecodingType, engineDecodedInstructions, _countof(engineDecodedInstructions), &DecodedInstructionsCount) != DECRES_INPUTERR)
        {
            RtlZeroMemory(engineDisassembledInstruction, sizeof(engineDisassembledInstruction));

            lstrcpyA(engineDisassembledInstruction, (LPCSTR)engineDecodedInstructions[0].mnemonic.p);
            if(engineDecodedInstructions[0].size != NULL)
            {
                lstrcatA(engineDisassembledInstruction, " ");
            }
            lstrcatA(engineDisassembledInstruction, (LPCSTR)engineDecodedInstructions[0].operands.p);
            return((char*)engineDisassembledInstruction);
        }
    }

    return 0;
}

__declspec(dllexport) void* TITCALL StaticDisassemble(LPVOID DisassmAddress)
{
    return StaticDisassembleEx((ULONG_PTR)DisassmAddress, DisassmAddress);
}

__declspec(dllexport) void* TITCALL DisassembleEx(HANDLE hProcess, LPVOID DisassmAddress, bool ReturnInstructionType)
{
    _DecodedInst engineDecodedInstructions[1];
    unsigned int DecodedInstructionsCount = 0;
    BYTE readBuffer[MAXIMUM_INSTRUCTION_SIZE] = {0};

    if(hProcess != NULL)
    {
        int MaxDisassmSize = MAXIMUM_INSTRUCTION_SIZE; // (int)IsBadReadPtrRemote(hProcess, DisassmAddress, sizeof(readBuffer));

        if(MaxDisassmSize)
        {
            BOOL rpm = MemoryReadSafe(hProcess, DisassmAddress, readBuffer, MaxDisassmSize, 0);
            if(rpm)
            {
                if(distorm_decode((ULONG_PTR)DisassmAddress, readBuffer, MaxDisassmSize, DecodingType, engineDecodedInstructions, _countof(engineDecodedInstructions), &DecodedInstructionsCount) != DECRES_INPUTERR)
                {
                    RtlZeroMemory(engineDisassembledInstruction, sizeof(engineDisassembledInstruction));

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

            }
        }
    }

    return 0;
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
    _CodeInfo decomposerCi = {0};
    _DInst decomposerResult[1] = {0};
    BYTE readBuffer[MAXIMUM_INSTRUCTION_SIZE] = {0}; //The maximum length of an Intel 64 and IA-32 instruction remains 15 bytes, but we are generous

    if(hProcess != NULL)
    {
        int MaxDisassmSize = (int)IsBadReadPtrRemote(hProcess, DisassmAddress, sizeof(readBuffer));

        if(MaxDisassmSize && MemoryReadSafe(hProcess, (LPVOID)DisassmAddress, readBuffer, MaxDisassmSize, 0))
        {
            decomposerCi.code = readBuffer;
            decomposerCi.codeLen = MaxDisassmSize;
            decomposerCi.dt = DecodingType;
            decomposerCi.codeOffset = (LONG_PTR)DisassmAddress;

            if(distorm_decompose(&decomposerCi, decomposerResult, _countof(decomposerResult), &DecodedInstructionsCount) != DECRES_INPUTERR)
            {
                if(decomposerResult[0].flags != FLAG_NOT_DECODABLE)
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
