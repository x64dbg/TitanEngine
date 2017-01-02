#include "stdafx.h"
#include "definitions.h"
#include "Global.Debugger.h"
#include "Global.Breakpoints.h"

__declspec(dllexport) bool TITCALL MatchPatternEx(HANDLE hProcess, void* MemoryToCheck, int SizeOfMemoryToCheck, void* PatternToMatch, int SizeOfPatternToMatch, PBYTE WildCard)
{
    if(!MemoryToCheck || !PatternToMatch || !SizeOfPatternToMatch || !SizeOfMemoryToCheck)
        return false;

    BYTE intWildCard = 0;
    LPVOID ueReadBuffer = NULL;
    DynBuf ueReadBuf;
    SIZE_T ueNumberOfBytesRead = 0;
    MEMORY_BASIC_INFORMATION memoryInformation = {};
    PMEMORY_COMPARE_HANDLER memCmp = (PMEMORY_COMPARE_HANDLER)MemoryToCheck;
    PMEMORY_COMPARE_HANDLER memPattern = (PMEMORY_COMPARE_HANDLER)PatternToMatch;

    if(WildCard == NULL)
    {
        WildCard = &intWildCard;
    }

    if(SizeOfMemoryToCheck >= SizeOfPatternToMatch)
    {
        if(hProcess != GetCurrentProcess())
        {
            ueReadBuffer = ueReadBuf.Allocate(SizeOfMemoryToCheck);
            if(ueReadBuffer && ReadProcessMemory(hProcess, MemoryToCheck, ueReadBuffer, SizeOfMemoryToCheck, &ueNumberOfBytesRead))
            {
                if(ueNumberOfBytesRead == 0)
                {
                    if(VirtualQueryEx(hProcess, MemoryToCheck, &memoryInformation, sizeof memoryInformation) != NULL)
                    {
                        SizeOfMemoryToCheck = (int)((ULONG_PTR)memoryInformation.BaseAddress + memoryInformation.RegionSize - (ULONG_PTR)MemoryToCheck);
                        if(!ReadProcessMemory(hProcess, MemoryToCheck, ueReadBuffer, SizeOfMemoryToCheck, &ueNumberOfBytesRead))
                        {
                            return false;
                        }
                    }
                    else
                    {
                        return false;
                    }
                }
            }

            memCmp = (PMEMORY_COMPARE_HANDLER)ueReadBuffer;
        }
    }

    if(memCmp)
    {
        for(int i = 0; i < SizeOfMemoryToCheck && i < SizeOfPatternToMatch; i++)
        {
            if(memCmp->Array.bArrayEntry[i] != memPattern->Array.bArrayEntry[i] && memPattern->Array.bArrayEntry[i] != *WildCard)
            {
                return false;
            }
        }
    }

    return true;
}

__declspec(dllexport) bool TITCALL MatchPattern(void* MemoryToCheck, int SizeOfMemoryToCheck, void* PatternToMatch, int SizeOfPatternToMatch, PBYTE WildCard)
{

    if(dbgProcessInformation.hProcess != NULL)
    {
        return(MatchPatternEx(dbgProcessInformation.hProcess, MemoryToCheck, SizeOfMemoryToCheck, PatternToMatch, SizeOfPatternToMatch, WildCard));
    }
    else
    {
        return(MatchPatternEx(GetCurrentProcess(), MemoryToCheck, SizeOfMemoryToCheck, PatternToMatch, SizeOfPatternToMatch, WildCard));
    }
}

__declspec(dllexport) ULONG_PTR TITCALL FindEx(HANDLE hProcess, LPVOID MemoryStart, DWORD MemorySize, LPVOID SearchPattern, DWORD PatternSize, LPBYTE WildCard)
{
    if(!hProcess || !MemoryStart || !MemorySize || !SearchPattern || !PatternSize)
        return 0;

    ULONG_PTR Return = NULL;
    LPVOID ueReadBuffer = NULL;
    DynBuf ueReadBuf;
    PUCHAR SearchBuffer = NULL;
    PUCHAR CompareBuffer = NULL;
    MEMORY_BASIC_INFORMATION memoryInformation = {};
    ULONG_PTR ueNumberOfBytesRead = NULL;
    LPVOID currentSearchPosition = NULL;
    DWORD currentSizeOfSearch = NULL;
    BYTE nWildCard = NULL;

    if(WildCard == NULL)
    {
        WildCard = &nWildCard;
    }

    if(hProcess != GetCurrentProcess())
    {
        ueReadBuffer = ueReadBuf.Allocate(MemorySize);
        if(ueReadBuffer && !MemoryReadSafe(hProcess, MemoryStart, ueReadBuffer, MemorySize, &ueNumberOfBytesRead))
        {
            if(ueNumberOfBytesRead == NULL)
            {
                if(VirtualQueryEx(hProcess, MemoryStart, &memoryInformation, sizeof memoryInformation) != NULL)
                {
                    MemorySize = (DWORD)((ULONG_PTR)memoryInformation.BaseAddress + memoryInformation.RegionSize - (ULONG_PTR)MemoryStart);
                    if(!MemoryReadSafe(hProcess, MemoryStart, ueReadBuffer, MemorySize, &ueNumberOfBytesRead))
                    {
                        return 0;
                    }
                }
                else
                {
                    return 0;
                }
            }
        }

        SearchBuffer = (PUCHAR)ueReadBuffer;
    }
    else
    {
        SearchBuffer = (PUCHAR)MemoryStart;
    }

    CompareBuffer = (PUCHAR)SearchPattern;

    DWORD i, j;
    for(i = 0; i < MemorySize && Return == NULL; i++)
    {
        for(j = 0; j < PatternSize; j++)
        {
            if(CompareBuffer[j] != *(PUCHAR)WildCard && SearchBuffer[i + j] != CompareBuffer[j])
            {
                break;
            }
        }
        if(j == PatternSize)
        {
            Return = (ULONG_PTR)MemoryStart + i;
        }
    }

    return Return;
}

extern "C" __declspec(dllexport) ULONG_PTR TITCALL Find(LPVOID MemoryStart, DWORD MemorySize, LPVOID SearchPattern, DWORD PatternSize, LPBYTE WildCard)
{

    if(dbgProcessInformation.hProcess != NULL)
    {
        return(FindEx(dbgProcessInformation.hProcess, MemoryStart, MemorySize, SearchPattern, PatternSize, WildCard));
    }
    else
    {
        return(FindEx(GetCurrentProcess(), MemoryStart, MemorySize, SearchPattern, PatternSize, WildCard));
    }
}

__declspec(dllexport) bool TITCALL FillEx(HANDLE hProcess, LPVOID MemoryStart, DWORD MemorySize, PBYTE FillByte)
{

    unsigned int i;
    MEMORY_BASIC_INFORMATION MemInfo;
    ULONG_PTR ueNumberOfBytesRead;
    BYTE defFillByte = 0x90;
    DWORD OldProtect;

    if(hProcess != NULL)
    {
        if(FillByte == NULL)
        {
            FillByte = &defFillByte;
        }
        VirtualQueryEx(hProcess, MemoryStart, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
        OldProtect = MemInfo.Protect;
        VirtualProtectEx(hProcess, MemoryStart, MemorySize, PAGE_EXECUTE_READWRITE, &OldProtect);
        for(i = 0; i < MemorySize; i++)
        {
            WriteProcessMemory(hProcess, MemoryStart, FillByte, 1, &ueNumberOfBytesRead);
            MemoryStart = (LPVOID)((ULONG_PTR)MemoryStart + 1);
        }
        VirtualProtectEx(hProcess, MemoryStart, MemorySize, OldProtect, &OldProtect);
        return true;
    }
    return false;
}

__declspec(dllexport) bool TITCALL Fill(LPVOID MemoryStart, DWORD MemorySize, PBYTE FillByte)
{

    if(dbgProcessInformation.hProcess != NULL)
    {
        return(FillEx(dbgProcessInformation.hProcess, MemoryStart, MemorySize, FillByte));
    }
    else
    {
        return(FillEx(GetCurrentProcess(), MemoryStart, MemorySize, FillByte));
    }
}

__declspec(dllexport) bool TITCALL PatchEx(HANDLE hProcess, LPVOID MemoryStart, DWORD MemorySize, LPVOID ReplacePattern, DWORD ReplaceSize, bool AppendNOP, bool PrependNOP)
{

    unsigned int i, recalcSize;
    LPVOID lpMemoryStart = MemoryStart;
    MEMORY_BASIC_INFORMATION MemInfo;
    ULONG_PTR ueNumberOfBytesRead;
    BYTE FillByte = 0x90;
    DWORD OldProtect;

    if(hProcess != NULL)
    {
        VirtualQueryEx(hProcess, MemoryStart, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
        OldProtect = MemInfo.Protect;
        VirtualProtectEx(hProcess, MemoryStart, MemorySize, PAGE_EXECUTE_READWRITE, &OldProtect);

        if(MemorySize - ReplaceSize != NULL)
        {
            recalcSize = abs((long)(MemorySize - ReplaceSize));
            if(AppendNOP)
            {
                WriteProcessMemory(hProcess, MemoryStart, ReplacePattern, ReplaceSize, &ueNumberOfBytesRead);
                lpMemoryStart = (LPVOID)((ULONG_PTR)MemoryStart + ReplaceSize);
                for(i = 0; i < recalcSize; i++)
                {
                    WriteProcessMemory(hProcess, lpMemoryStart, &FillByte, 1, &ueNumberOfBytesRead);
                    lpMemoryStart = (LPVOID)((ULONG_PTR)lpMemoryStart + 1);
                }
            }
            else if(PrependNOP)
            {
                lpMemoryStart = MemoryStart;
                for(i = 0; i < recalcSize; i++)
                {
                    WriteProcessMemory(hProcess, lpMemoryStart, &FillByte, 1, &ueNumberOfBytesRead);
                    lpMemoryStart = (LPVOID)((ULONG_PTR)lpMemoryStart + 1);
                }
                WriteProcessMemory(hProcess, lpMemoryStart, ReplacePattern, ReplaceSize, &ueNumberOfBytesRead);
            }
            else
            {
                WriteProcessMemory(hProcess, MemoryStart, ReplacePattern, ReplaceSize, &ueNumberOfBytesRead);
            }
        }
        else
        {
            WriteProcessMemory(hProcess, MemoryStart, ReplacePattern, ReplaceSize, &ueNumberOfBytesRead);
        }
        VirtualProtectEx(hProcess, MemoryStart, MemorySize, OldProtect, &OldProtect);
        return true;
    }
    return false;
}

__declspec(dllexport) bool TITCALL Patch(LPVOID MemoryStart, DWORD MemorySize, LPVOID ReplacePattern, DWORD ReplaceSize, bool AppendNOP, bool PrependNOP)
{

    if(dbgProcessInformation.hProcess != NULL)
    {
        return(PatchEx(dbgProcessInformation.hProcess, MemoryStart, MemorySize, ReplacePattern, ReplaceSize, AppendNOP, PrependNOP));
    }
    else
    {
        return(PatchEx(GetCurrentProcess(), MemoryStart, MemorySize, ReplacePattern, ReplaceSize, AppendNOP, PrependNOP));
    }
}

__declspec(dllexport) bool TITCALL ReplaceEx(HANDLE hProcess, LPVOID MemoryStart, DWORD MemorySize, LPVOID SearchPattern, DWORD PatternSize, DWORD NumberOfRepetitions, LPVOID ReplacePattern, DWORD ReplaceSize, PBYTE WildCard)
{

    unsigned int i;
    ULONG_PTR ueNumberOfBytesRead;
    ULONG_PTR CurrentFoundPattern;
    LPVOID cMemoryStart = MemoryStart;
    DWORD cMemorySize = MemorySize;
    DynBuf lpReadMem;
    LPVOID lpReadMemory = lpReadMem.Allocate(PatternSize);

    CurrentFoundPattern = (ULONG_PTR)FindEx(hProcess, cMemoryStart, cMemorySize, SearchPattern, PatternSize, WildCard);
    NumberOfRepetitions--;
    while(CurrentFoundPattern != NULL && NumberOfRepetitions != NULL)
    {
        if(ReadProcessMemory(hProcess, (LPVOID)CurrentFoundPattern, lpReadMemory, PatternSize, &ueNumberOfBytesRead))
        {
            for(i = 0; i < ReplaceSize; i++)
            {
                if(memcmp((LPVOID)((ULONG_PTR)ReplacePattern + i), WildCard, 1) != NULL)
                {
                    RtlMoveMemory((LPVOID)((ULONG_PTR)lpReadMemory + i), (LPVOID)((ULONG_PTR)ReplacePattern + i), 1);
                }
            }
            PatchEx(hProcess, (LPVOID)CurrentFoundPattern, PatternSize, lpReadMemory, ReplaceSize, true, false);
        }
        cMemoryStart = (LPVOID)(CurrentFoundPattern + PatternSize);
        cMemorySize = (DWORD)((ULONG_PTR)MemoryStart + MemorySize - CurrentFoundPattern);
        CurrentFoundPattern = (ULONG_PTR)FindEx(hProcess, cMemoryStart, cMemorySize, SearchPattern, PatternSize, WildCard);
        NumberOfRepetitions--;
    }
    if(NumberOfRepetitions != NULL)
    {
        return false;
    }
    else
    {
        return true;
    }
}

__declspec(dllexport) bool TITCALL Replace(LPVOID MemoryStart, DWORD MemorySize, LPVOID SearchPattern, DWORD PatternSize, DWORD NumberOfRepetitions, LPVOID ReplacePattern, DWORD ReplaceSize, PBYTE WildCard)
{

    if(dbgProcessInformation.hProcess != NULL)
    {
        return(ReplaceEx(dbgProcessInformation.hProcess, MemoryStart, MemorySize, SearchPattern, PatternSize, NumberOfRepetitions, ReplacePattern, ReplaceSize, WildCard));
    }
    else
    {
        return(ReplaceEx(GetCurrentProcess(), MemoryStart, MemorySize, SearchPattern, PatternSize, NumberOfRepetitions, ReplacePattern, ReplaceSize, WildCard));
    }
}

//what should this function do:
//- do all possible effort to read memory
//- filter out breakpoints
__declspec(dllexport) bool TITCALL MemoryReadSafe(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
{
    SIZE_T ueNumberOfBytesRead = 0;
    SIZE_T* pNumBytes = 0;
    DWORD dwProtect = 0;
    bool retValue = false;

    //read memory
    if((hProcess == 0) || (lpBaseAddress == 0) || (lpBuffer == 0) || (nSize == 0))
    {
        return false;
    }

    if(!lpNumberOfBytesRead)
    {
        pNumBytes = &ueNumberOfBytesRead;
    }
    else
    {
        pNumBytes = lpNumberOfBytesRead;
    }

    if(!ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, pNumBytes))
    {
        if(VirtualProtectEx(hProcess, lpBaseAddress, nSize, PAGE_EXECUTE_READ, &dwProtect))
        {
            if(ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, pNumBytes))
            {
                retValue = true;
            }
            VirtualProtectEx(hProcess, lpBaseAddress, nSize, dwProtect, &dwProtect);
        }
    }
    else
    {
        retValue = true;
    }

    //filter breakpoints
    if(retValue)
        BreakPointPostReadFilter((ULONG_PTR)lpBaseAddress, (unsigned char*)lpBuffer, nSize);

    return retValue;
}

//what should this function do:
//- do all possible effort to write memory
//- re-set breakpoints when overwritten
__declspec(dllexport) bool TITCALL MemoryWriteSafe(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
    SIZE_T ueNumberOfBytesWritten = 0;
    SIZE_T* pNumBytes = 0;
    DWORD dwProtect = 0;
    bool retValue = false;

    //read memory
    if((hProcess == 0) || (lpBaseAddress == 0) || (lpBuffer == 0) || (nSize == 0))
    {
        return false;
    }

    CriticalSectionLocker lock(LockBreakPointBuffer); //thread-safe
    //disable breakpoints that interfere with the memory to write
    BreakPointPreWriteFilter((ULONG_PTR)lpBaseAddress, nSize);

    if(!lpNumberOfBytesWritten)
    {
        pNumBytes = &ueNumberOfBytesWritten;
    }
    else
    {
        pNumBytes = lpNumberOfBytesWritten;
    }

    if(!WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, pNumBytes))
    {
        if(VirtualProtectEx(hProcess, lpBaseAddress, nSize, PAGE_EXECUTE_READWRITE, &dwProtect))
        {
            if(WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, pNumBytes))
            {
                retValue = true;
            }
            VirtualProtectEx(hProcess, lpBaseAddress, nSize, dwProtect, &dwProtect);
        }
    }
    else
    {
        retValue = true;
    }

    //re-enable breakpoints that interfere with the memory to write
    BreakPointPostWriteFilter((ULONG_PTR)lpBaseAddress, nSize);

    return retValue;
}
