#include "stdafx.h"
#include "definitions.h"
#include "Global.Breakpoints.h"
#include "Global.Debugger.h"
#include "Global.Engine.h"
#include "Global.Engine.Threading.h"
#include "Global.Engine.Importer.h"
#include "Global.Threader.h"

static long engineDefaultBreakPointType = UE_BREAKPOINT_INT3;
static BYTE UD2BreakPoint[2] = {0x0F, 0x0B};
static BYTE INT3BreakPoint = 0xCC;
static BYTE INT3LongBreakPoint[2] = {0xCD, 0x03};

__declspec(dllexport) void TITCALL SetBPXOptions(long DefaultBreakPointType)
{
    if(DefaultBreakPointType == UE_BREAKPOINT_INT3 || DefaultBreakPointType == UE_BREAKPOINT_LONG_INT3 || DefaultBreakPointType == UE_BREAKPOINT_UD2)
        engineDefaultBreakPointType = DefaultBreakPointType;
    else if(DefaultBreakPointType == UE_BREAKPOINT_TYPE_INT3)
        engineDefaultBreakPointType = UE_BREAKPOINT_INT3;
    else if(DefaultBreakPointType == UE_BREAKPOINT_TYPE_LONG_INT3)
        engineDefaultBreakPointType = UE_BREAKPOINT_LONG_INT3;
    else if(DefaultBreakPointType == UE_BREAKPOINT_TYPE_UD2)
        engineDefaultBreakPointType = UE_BREAKPOINT_UD2;
}

__declspec(dllexport) bool TITCALL IsBPXEnabled(ULONG_PTR bpxAddress)
{
    CriticalSectionLocker lock(LockBreakPointBuffer);
    ULONG_PTR NumberOfBytesReadWritten = 0;
    DWORD MaximumBreakPoints = 0;
    BYTE ReadData[10] = {};
    int bpcount = (int)BreakPointBuffer.size();
    for(int i = 0; i < bpcount; i++)
    {
        if(BreakPointBuffer.at(i).BreakPointAddress == bpxAddress)
        {
            if(BreakPointBuffer.at(i).BreakPointActive != UE_BPXINACTIVE)
            {
                if(ReadProcessMemory(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, &ReadData[0], UE_MAX_BREAKPOINT_SIZE, &NumberOfBytesReadWritten))
                {
                    if(BreakPointBuffer.at(i).AdvancedBreakPointType == UE_BREAKPOINT_INT3 && ReadData[0] == INT3BreakPoint)
                        return true;
                    else if(BreakPointBuffer.at(i).AdvancedBreakPointType == UE_BREAKPOINT_LONG_INT3 && ReadData[0] == INT3LongBreakPoint[0] && ReadData[1] == INT3LongBreakPoint[1])
                        return true;
                    else if(BreakPointBuffer.at(i).AdvancedBreakPointType == UE_BREAKPOINT_UD2 && ReadData[0] == UD2BreakPoint[0] && ReadData[1] == UD2BreakPoint[1])
                        return true;
                    else //TODO: delete breakpoint from list?
                        return false;
                }
                else
                    return false;
            }
            else
                return false;
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL EnableBPX(ULONG_PTR bpxAddress)
{
    CriticalSectionLocker lock(LockBreakPointBuffer);
    MEMORY_BASIC_INFORMATION MemInfo;
    ULONG_PTR NumberOfBytesReadWritten = 0;
    DWORD MaximumBreakPoints = 0;
    bool testWrite = false;
    DWORD OldProtect;
    int bpcount = (int)BreakPointBuffer.size();
    for(int i = 0; i < bpcount; i++)
    {
        if(BreakPointBuffer.at(i).BreakPointAddress == bpxAddress)
        {
            VirtualQueryEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
            OldProtect = MemInfo.Protect;
            VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer.at(i).BreakPointSize, PAGE_EXECUTE_READWRITE, &OldProtect);
            if(BreakPointBuffer.at(i).BreakPointActive == UE_BPXINACTIVE && (BreakPointBuffer.at(i).BreakPointType == UE_BREAKPOINT || BreakPointBuffer.at(i).BreakPointType == UE_SINGLESHOOT))
            {
                //re-read original byte(s)
                if(ReadProcessMemory(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer.at(i).OriginalByte, BreakPointBuffer.at(i).BreakPointSize, 0))
                {
                    if(BreakPointBuffer.at(i).AdvancedBreakPointType == UE_BREAKPOINT_INT3)
                    {
                        if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, &INT3BreakPoint, 1, &NumberOfBytesReadWritten))
                        {
                            FlushInstructionCache(dbgProcessInformation.hProcess, NULL, 0);
                            testWrite = true;
                        }
                    }
                    else if(BreakPointBuffer.at(i).AdvancedBreakPointType == UE_BREAKPOINT_LONG_INT3)
                    {
                        if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, &INT3LongBreakPoint, 2, &NumberOfBytesReadWritten))
                        {
                            FlushInstructionCache(dbgProcessInformation.hProcess, NULL, 0);
                            testWrite = true;
                        }
                    }
                    else if(BreakPointBuffer.at(i).AdvancedBreakPointType == UE_BREAKPOINT_UD2)
                    {
                        if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, &UD2BreakPoint, 2, &NumberOfBytesReadWritten))
                        {
                            FlushInstructionCache(dbgProcessInformation.hProcess, NULL, 0);
                            testWrite = true;
                        }
                    }
                    if(testWrite)
                    {
                        BreakPointBuffer.at(i).BreakPointActive = UE_BPXACTIVE;
                        VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer.at(i).BreakPointSize, OldProtect, &OldProtect);
                        return true;
                    }
                    else
                    {
                        VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer.at(i).BreakPointSize, OldProtect, &OldProtect);
                        return false;
                    }
                }
                else
                {
                    VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer.at(i).BreakPointSize, OldProtect, &OldProtect);
                    return false;
                }
            }
            else
            {
                VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer.at(i).BreakPointSize, OldProtect, &OldProtect);
                return false;
            }
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL DisableBPX(ULONG_PTR bpxAddress)
{
    CriticalSectionLocker lock(LockBreakPointBuffer);
    MEMORY_BASIC_INFORMATION MemInfo;
    ULONG_PTR NumberOfBytesReadWritten = 0;
    DWORD MaximumBreakPoints = 0;
    DWORD OldProtect;
    int bpcount = (int)BreakPointBuffer.size();
    for(int i = 0; i < bpcount; i++)
    {
        if(BreakPointBuffer.at(i).BreakPointAddress == bpxAddress)
        {
            VirtualQueryEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
            OldProtect = MemInfo.Protect;
            VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer.at(i).BreakPointSize, PAGE_EXECUTE_READWRITE, &OldProtect);
            if(BreakPointBuffer.at(i).BreakPointActive == UE_BPXACTIVE && (BreakPointBuffer.at(i).BreakPointType == UE_BREAKPOINT || BreakPointBuffer.at(i).BreakPointType == UE_SINGLESHOOT))
            {
                if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, &BreakPointBuffer.at(i).OriginalByte[0], BreakPointBuffer.at(i).BreakPointSize, &NumberOfBytesReadWritten))
                {
                    FlushInstructionCache(dbgProcessInformation.hProcess, NULL, 0);
                    BreakPointBuffer.at(i).BreakPointActive = UE_BPXINACTIVE;
                    VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer.at(i).BreakPointSize, OldProtect, &OldProtect);
                    return true;
                }
                else
                {
                    VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer.at(i).BreakPointSize, OldProtect, &OldProtect);
                    return false;
                }
            }
            else
            {
                VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer.at(i).BreakPointSize, OldProtect, &OldProtect);
                return false;
            }
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL SetBPX(ULONG_PTR bpxAddress, DWORD bpxType, LPVOID bpxCallBack)
{
    CriticalSectionLocker lock(LockBreakPointBuffer);
    void* bpxDataPrt;
    PMEMORY_COMPARE_HANDLER bpxDataCmpPtr;
    ULONG_PTR NumberOfBytesReadWritten = 0;
    BYTE SelectedBreakPointType;
    DWORD checkBpxType;
    DWORD OldProtect;

    if(bpxCallBack == NULL)
    {
        return false;
    }
    int bpcount = (int)BreakPointBuffer.size();
    //search for breakpoint
    for(int i = 0; i < bpcount; i++)
    {
        if(BreakPointBuffer.at(i).BreakPointAddress == bpxAddress && BreakPointBuffer.at(i).BreakPointActive == UE_BPXACTIVE && (BreakPointBuffer.at(i).BreakPointType == UE_SINGLESHOOT || BreakPointBuffer.at(i).BreakPointType == UE_BREAKPOINT))
            return false;
        else if(BreakPointBuffer.at(i).BreakPointAddress == bpxAddress && BreakPointBuffer.at(i).BreakPointActive == UE_BPXINACTIVE && (BreakPointBuffer.at(i).BreakPointType == UE_SINGLESHOOT || BreakPointBuffer.at(i).BreakPointType == UE_BREAKPOINT))
        {
            lock.unlock();
            return EnableBPX(bpxAddress);
        }
    }
    //setup new breakpoint structure
    BreakPointDetail NewBreakPoint;
    memset(&NewBreakPoint, 0, sizeof(BreakPointDetail));
    if(bpxType < UE_BREAKPOINT_TYPE_INT3)
    {
        if(engineDefaultBreakPointType == UE_BREAKPOINT_LONG_INT3)
        {
            SelectedBreakPointType = UE_BREAKPOINT_LONG_INT3;
            NewBreakPoint.BreakPointSize = 2;
            bpxDataPrt = &INT3LongBreakPoint;
        }
        else if(engineDefaultBreakPointType == UE_BREAKPOINT_UD2)
        {
            SelectedBreakPointType = UE_BREAKPOINT_UD2;
            NewBreakPoint.BreakPointSize = 2;
            bpxDataPrt = &UD2BreakPoint;
        }
        else //default
        {
            SelectedBreakPointType = UE_BREAKPOINT_INT3;
            NewBreakPoint.BreakPointSize = 1;
            bpxDataPrt = &INT3BreakPoint;
        }
    }
    else
    {
        checkBpxType = bpxType >> 24;
        checkBpxType = checkBpxType << 24;
        if(checkBpxType == UE_BREAKPOINT_TYPE_INT3)
        {
            SelectedBreakPointType = UE_BREAKPOINT_INT3;
            NewBreakPoint.BreakPointSize = 1;
            bpxDataPrt = &INT3BreakPoint;
        }
        else if(checkBpxType == UE_BREAKPOINT_TYPE_LONG_INT3)
        {
            SelectedBreakPointType = UE_BREAKPOINT_LONG_INT3;
            NewBreakPoint.BreakPointSize = 2;
            bpxDataPrt = &INT3LongBreakPoint;
        }
        else if(checkBpxType == UE_BREAKPOINT_TYPE_UD2)
        {
            SelectedBreakPointType = UE_BREAKPOINT_UD2;
            NewBreakPoint.BreakPointSize = 2;
            bpxDataPrt = &UD2BreakPoint;
        }
    }
    //set breakpoint in process
    bpxDataCmpPtr = (PMEMORY_COMPARE_HANDLER)bpxDataPrt;
    if(!VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, NewBreakPoint.BreakPointSize, PAGE_EXECUTE_READWRITE, &OldProtect))
        return false;
    if(ReadProcessMemory(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, &NewBreakPoint.OriginalByte[0], NewBreakPoint.BreakPointSize, &NumberOfBytesReadWritten))
    {
        if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, bpxDataPrt, NewBreakPoint.BreakPointSize, &NumberOfBytesReadWritten))
        {
            FlushInstructionCache(dbgProcessInformation.hProcess, NULL, 0);
            //add new breakpoint to the list
            NewBreakPoint.AdvancedBreakPointType = SelectedBreakPointType & 0xFF;
            NewBreakPoint.BreakPointActive = UE_BPXACTIVE;
            NewBreakPoint.BreakPointAddress = bpxAddress;
            NewBreakPoint.BreakPointType = bpxType & 0xFF;
            NewBreakPoint.ExecuteCallBack = (ULONG_PTR)bpxCallBack;
            BreakPointBuffer.push_back(NewBreakPoint);
            VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, NewBreakPoint.BreakPointSize, OldProtect, &OldProtect);
            return true;
        }
        else
        {
            VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, NewBreakPoint.BreakPointSize, OldProtect, &OldProtect);
            return false;
        }
    }
    VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, NewBreakPoint.BreakPointSize, OldProtect, &OldProtect);
    return false;
}

__declspec(dllexport) bool TITCALL DeleteBPX(ULONG_PTR bpxAddress)
{
    CriticalSectionLocker lock(LockBreakPointBuffer);
    ULONG_PTR NumberOfBytesReadWritten = 0;
    DWORD OldProtect;
    int bpcount = (int)BreakPointBuffer.size();
    int found = -1;
    for(int i = 0; i < bpcount; i++)
    {
        if(BreakPointBuffer.at(i).BreakPointAddress == bpxAddress && (BreakPointBuffer.at(i).BreakPointType == UE_SINGLESHOOT || BreakPointBuffer.at(i).BreakPointType == UE_BREAKPOINT))
        {
            found = i;
            break;
        }
    }
    if(found == -1) //not found
        return false;
    VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer.at(found).BreakPointSize, PAGE_EXECUTE_READWRITE, &OldProtect);
    if(IsBPXEnabled(bpxAddress))
    {
        if(!WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, &BreakPointBuffer.at(found).OriginalByte[0], BreakPointBuffer.at(found).BreakPointSize, &NumberOfBytesReadWritten))
        {
            VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer.at(found).BreakPointSize, OldProtect, &OldProtect);
            return false;
        }
    }
    FlushInstructionCache(dbgProcessInformation.hProcess, NULL, 0);
    VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer.at(found).BreakPointSize, OldProtect, &OldProtect);
    BreakPointBuffer.erase(BreakPointBuffer.begin() + found);
    return true;
}

__declspec(dllexport) bool TITCALL SafeDeleteBPX(ULONG_PTR bpxAddress)
{
    //TODO: remove?
    return DeleteBPX(bpxAddress);
}

__declspec(dllexport) bool TITCALL SetAPIBreakPoint(const char* szDLLName, const char* szAPIName, DWORD bpxType, DWORD bpxPlace, LPVOID bpxCallBack)
{
    ULONG_PTR APIAddress = NULL;
    if(szDLLName && szAPIName)
    {
        APIAddress = EngineGetProcAddressRemote(0, szDLLName, szAPIName); //get remote proc address
        if(APIAddress)
        {
            if(bpxPlace == UE_APIEND)
            {
                int i = 0;
                int len = 0;
                unsigned char CmdBuffer[MAXIMUM_INSTRUCTION_SIZE];
                if(!_stricmp(szDLLName, "kernel32.dll"))
                {
                    ULONG_PTR APIAddress_ = EngineGetProcAddressRemote(0, "kernelbase.dll", szAPIName);
                    if(APIAddress_)
                    {
                        bool KernelBase = true;
                        do //search for forwarding indicators
                        {
                            i += len;
                            if(!MemoryReadSafe(dbgProcessInformation.hProcess, (void*)(APIAddress + i), CmdBuffer, sizeof(CmdBuffer), 0))
                                return false;
                            if(CmdBuffer[0] == 0xCC || CmdBuffer[0] == 0x90) //padding
                            {
                                KernelBase = false; //failed to find forward indicator
                                break;
                            }
                            len = StaticLengthDisassemble(CmdBuffer);
                        }
#ifdef _WIN64
                        while(!(CmdBuffer[0] == 0x48 && CmdBuffer[1] == 0xFF && CmdBuffer[2] == 0x25));
#else
                        while(!(CmdBuffer[0] == 0xFF && CmdBuffer[1] == 0x25));
#endif //_WIN64
                        if(KernelBase)
                            APIAddress = APIAddress_;
                        i = 0;
                        len = 0;
                    }
                }
                do  //search for RET
                {
                    i += len;
                    if(!MemoryReadSafe(dbgProcessInformation.hProcess, (void*)(APIAddress + i), CmdBuffer, sizeof(CmdBuffer), 0))
                        return false;
                    len = StaticLengthDisassemble(CmdBuffer);
                }
                while(CmdBuffer[0] != 0xC3 && CmdBuffer[0] != 0xC2);
                APIAddress += i;
            }
            return SetBPX(APIAddress, bpxType, bpxCallBack);
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL DeleteAPIBreakPoint(const char* szDLLName, const char* szAPIName, DWORD bpxPlace)
{
    ULONG_PTR APIAddress = NULL;
    if(szDLLName && szAPIName)
    {
        APIAddress = EngineGetProcAddressRemote(0, szDLLName, szAPIName); //get remote proc address
        if(APIAddress)
        {
            if(bpxPlace == UE_APIEND)
            {
                int i = 0;
                int len = 0;
                unsigned char CmdBuffer[MAXIMUM_INSTRUCTION_SIZE];
                if(!_stricmp(szDLLName, "kernel32.dll"))
                {
                    ULONG_PTR APIAddress_ = EngineGetProcAddressRemote(0, "kernelbase.dll", szAPIName);
                    if(APIAddress_)
                    {
                        bool KernelBase = true;
                        do //search for forwarding indicators
                        {
                            i += len;
                            if(!MemoryReadSafe(dbgProcessInformation.hProcess, (void*)(APIAddress + i), CmdBuffer, sizeof(CmdBuffer), 0))
                                return false;
                            if(CmdBuffer[0] == 0xCC || CmdBuffer[0] == 0x90) //padding
                            {
                                KernelBase = false; //failed to find forward indicator
                                break;
                            }
                            len = StaticLengthDisassemble(CmdBuffer);
                        }
#ifdef _WIN64
                        while(!(CmdBuffer[0] == 0x48 && CmdBuffer[1] == 0xFF && CmdBuffer[2] == 0x25));
#else
                        while(!(CmdBuffer[0] == 0xFF && CmdBuffer[1] == 0x25));
#endif //_WIN64
                        if(KernelBase)
                            APIAddress = APIAddress_;
                        i = 0;
                        len = 0;
                    }
                }
                do  //search for RET
                {
                    i += len;
                    if(!MemoryReadSafe(dbgProcessInformation.hProcess, (void*)(APIAddress + i), CmdBuffer, sizeof(CmdBuffer), 0))
                        return false;
                    len = StaticLengthDisassemble(CmdBuffer);
                }
                while(CmdBuffer[0] != 0xC3 && CmdBuffer[0] != 0xC2);
                APIAddress += i;
            }
            return DeleteBPX(APIAddress);
        }
    }
    return false;
}

__declspec(dllexport) bool TITCALL SafeDeleteAPIBreakPoint(const char* szDLLName, const char* szAPIName, DWORD bpxPlace)
{
    //TODO: remove?
    return DeleteAPIBreakPoint(szDLLName, szAPIName, bpxPlace);
}

__declspec(dllexport) bool TITCALL SetMemoryBPX(ULONG_PTR MemoryStart, SIZE_T SizeOfMemory, LPVOID bpxCallBack)
{
    return SetMemoryBPXEx(MemoryStart, SizeOfMemory, UE_MEMORY, false, bpxCallBack);
}

__declspec(dllexport) bool TITCALL SetMemoryBPXEx(ULONG_PTR MemoryStart, SIZE_T SizeOfMemory, DWORD BreakPointType, bool RestoreOnHit, LPVOID bpxCallBack)
{
    if(MemoryStart % TITANENGINE_PAGESIZE || !SizeOfMemory || SizeOfMemory % TITANENGINE_PAGESIZE) //ensure the data is aligned with the page size
        return false;
    CriticalSectionLocker lock(LockBreakPointBuffer);
    MEMORY_BASIC_INFORMATION MemInfo;
    ULONG_PTR NumberOfBytesReadWritten = 0;
    int bpcount = (int)BreakPointBuffer.size();
    DWORD OldProtect = 0;
    //search for breakpoint
    for(int i = 0; i < bpcount; i++)
    {
        if(BreakPointBuffer.at(i).BreakPointAddress == MemoryStart &&
                (BreakPointBuffer.at(i).BreakPointType == UE_MEMORY ||
                 BreakPointBuffer.at(i).BreakPointType == UE_MEMORY_READ ||
                 BreakPointBuffer.at(i).BreakPointType == UE_MEMORY_WRITE ||
                 BreakPointBuffer.at(i).BreakPointType == UE_MEMORY_EXECUTE)
          )
        {
            return false;
        }
    }
    //set PAGE_GUARD on all the pages separately
    size_t pages = SizeOfMemory / TITANENGINE_PAGESIZE;

    for(size_t i = 0; i < pages; i++)
    {
        const LPVOID curPage = (LPVOID)(MemoryStart + i * TITANENGINE_PAGESIZE);

        VirtualQueryEx(dbgProcessInformation.hProcess, curPage, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION));

        if(OldProtect == 0)
            OldProtect = MemInfo.Protect;

        // Check if the alternative memory breakpoint method should be used
        if(engineMembpAlt)
        {
            if(!(MemInfo.Protect & PAGE_NOACCESS))
            {
                VirtualProtectEx(dbgProcessInformation.hProcess, curPage, TITANENGINE_PAGESIZE, PAGE_NOACCESS, &MemInfo.Protect);
            }
        }
        else
        {
            // Default to using PAGE_GUARD memory breakpoint
            if(!(MemInfo.Protect & PAGE_GUARD))
            {
                DWORD NewProtect = MemInfo.Protect ^ PAGE_GUARD;
                VirtualProtectEx(dbgProcessInformation.hProcess, curPage, TITANENGINE_PAGESIZE, NewProtect, &MemInfo.Protect);
            }
        }
    }
    //add new breakpoint
    BreakPointDetail NewBreakPoint;
    memset(&NewBreakPoint, 0, sizeof(BreakPointDetail));
    NewBreakPoint.BreakPointActive = UE_BPXACTIVE;
    NewBreakPoint.BreakPointAddress = MemoryStart;
    NewBreakPoint.BreakPointType = BreakPointType;
    NewBreakPoint.BreakPointSize = SizeOfMemory;
    NewBreakPoint.OldProtect = OldProtect;
    NewBreakPoint.MemoryBpxRestoreOnHit = (BYTE)RestoreOnHit;
    NewBreakPoint.ExecuteCallBack = (ULONG_PTR)bpxCallBack;
    BreakPointBuffer.push_back(NewBreakPoint);
    return true;
}

__declspec(dllexport) bool TITCALL RemoveMemoryBPX(ULONG_PTR MemoryStart, SIZE_T SizeOfMemory)
{
    if(MemoryStart % TITANENGINE_PAGESIZE || SizeOfMemory % TITANENGINE_PAGESIZE) //ensure the data is aligned with the page size
        return false;
    CriticalSectionLocker lock(LockBreakPointBuffer);
    MEMORY_BASIC_INFORMATION MemInfo;
    ULONG_PTR NumberOfBytesReadWritten = 0;
    int bpcount = (int)BreakPointBuffer.size();
    int found = -1;
    //search for breakpoint
    for(int i = 0; i < bpcount; i++)
    {
        if(BreakPointBuffer.at(i).BreakPointAddress == MemoryStart &&
                (BreakPointBuffer.at(i).BreakPointType == UE_MEMORY ||
                 BreakPointBuffer.at(i).BreakPointType == UE_MEMORY_READ ||
                 BreakPointBuffer.at(i).BreakPointType == UE_MEMORY_WRITE ||
                 BreakPointBuffer.at(i).BreakPointType == UE_MEMORY_EXECUTE)
          )
        {
            found = i;
            break;
        }
    }

    if(found == -1) //not found
        return false;

    if(!SizeOfMemory)
        SizeOfMemory = BreakPointBuffer.at(found).BreakPointSize;

    // Revert to the original permission on all the pages in the range
    size_t pages = SizeOfMemory / TITANENGINE_PAGESIZE;

    for(size_t i = 0; i < pages; i++)
    {
        const LPVOID curPage = (LPVOID)(MemoryStart + i * TITANENGINE_PAGESIZE);

        VirtualQueryEx(dbgProcessInformation.hProcess, curPage, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION));

        // Check if the alternative memory breakpoint method is being used
        if(engineMembpAlt)
        {
            if(MemInfo.Protect & PAGE_NOACCESS)
            {
                VirtualProtectEx(dbgProcessInformation.hProcess, curPage, TITANENGINE_PAGESIZE,
                                 BreakPointBuffer.at(found).OldProtect, &MemInfo.Protect);
            }
        }
        else
        {
            if(MemInfo.Protect & PAGE_GUARD)
            {
                DWORD NewProtect = MemInfo.Protect ^ PAGE_GUARD;

                VirtualProtectEx(dbgProcessInformation.hProcess, curPage, TITANENGINE_PAGESIZE, NewProtect, &MemInfo.Protect);
            }
        }
    }

    //remove breakpoint from list
    BreakPointBuffer.erase(BreakPointBuffer.begin() + found);

    return true;
}

__declspec(dllexport) bool TITCALL GetUnusedHardwareBreakPointRegister(LPDWORD RegisterIndex)
{
    return EngineIsThereFreeHardwareBreakSlot(RegisterIndex);
}

__declspec(dllexport) bool TITCALL SetHardwareBreakPoint(ULONG_PTR bpxAddress, DWORD IndexOfRegister, DWORD bpxType, DWORD bpxSize, LPVOID bpxCallBack)
{
    HWBP_SIZE hwbpSize;
    HWBP_MODE hwbpMode;
    HWBP_TYPE hwbpType;
    int hwbpIndex = -1;
    DR7 dr7;

    switch(bpxSize)
    {
    case UE_HARDWARE_SIZE_1:
        hwbpSize = SIZE_1;
        break;
    case UE_HARDWARE_SIZE_2:
        hwbpSize = SIZE_2;
        if((bpxAddress % 2) != 0)
            return false;
        break;
    case UE_HARDWARE_SIZE_4:
        hwbpSize = SIZE_4;
        if((bpxAddress % 4) != 0)
            return false;
        break;
    case UE_HARDWARE_SIZE_8:
        hwbpSize = SIZE_8;
        if((bpxAddress % 8) != 0)
            return false;
        break;
    default:
        return false;
    }

    if(!IndexOfRegister)
    {
        if(!DebugRegister[0].DrxEnabled)
            IndexOfRegister = UE_DR0;
        else if(!DebugRegister[1].DrxEnabled)
            IndexOfRegister = UE_DR1;
        else if(!DebugRegister[2].DrxEnabled)
            IndexOfRegister = UE_DR2;
        else if(!DebugRegister[3].DrxEnabled)
            IndexOfRegister = UE_DR3;
        else
            return false;
    }

    switch(IndexOfRegister)
    {
    case UE_DR0:
        hwbpIndex = 0;
        break;
    case UE_DR1:
        hwbpIndex = 1;
        break;
    case UE_DR2:
        hwbpIndex = 2;
        break;
    case UE_DR3:
        hwbpIndex = 3;
        break;
    default:
        return false;
    }

    uintdr7((ULONG_PTR)GetContextData(UE_DR7), &dr7);

    DebugRegister[hwbpIndex].DrxExecution = false;

    switch(bpxType)
    {
    case UE_HARDWARE_EXECUTE:
        hwbpSize = SIZE_1;
        hwbpType = TYPE_EXECUTE;
        DebugRegister[hwbpIndex].DrxExecution = true;
        break;
    case UE_HARDWARE_WRITE:
        hwbpType = TYPE_WRITE;
        break;
    case UE_HARDWARE_READWRITE:
        hwbpType = TYPE_READWRITE;
        break;
    default:
        return false;
    }

    hwbpMode = MODE_LOCAL;

    dr7.HWBP_MODE[hwbpIndex] = hwbpMode;
    dr7.HWBP_SIZE[hwbpIndex] = hwbpSize;
    dr7.HWBP_TYPE[hwbpIndex] = hwbpType;

    for(unsigned int i = 0; i < hListThread.size(); i++)
    {
        SetContextDataEx(hListThread.at(i).hThread, UE_DR7, dr7uint(&dr7)); //NOTE: MUST SET THIS FIRST FOR X64!
        SetContextDataEx(hListThread.at(i).hThread, IndexOfRegister, bpxAddress);
    }

    DebugRegister[hwbpIndex].DrxBreakPointType = bpxType;
    DebugRegister[hwbpIndex].DrxBreakPointSize = bpxSize;
    DebugRegister[hwbpIndex].DrxEnabled = true;
    DebugRegister[hwbpIndex].DrxBreakAddress = (ULONG_PTR)bpxAddress;
    DebugRegister[hwbpIndex].DrxCallBack = (ULONG_PTR)bpxCallBack;

    return true;
}

__declspec(dllexport) bool TITCALL SetHardwareBreakPointEx(HANDLE hActiveThread, ULONG_PTR bpxAddress, DWORD IndexOfRegister, DWORD bpxType, DWORD bpxSize, LPVOID bpxCallBack, LPDWORD IndexOfSelectedRegister)
{
    HWBP_SIZE hwbpSize;
    HWBP_MODE hwbpMode;
    HWBP_TYPE hwbpType;
    int hwbpIndex = -1;
    DR7 dr7;

    switch(bpxSize)
    {
    case UE_HARDWARE_SIZE_1:
        hwbpSize = SIZE_1;
        break;
    case UE_HARDWARE_SIZE_2:
        hwbpSize = SIZE_2;
        if((bpxAddress % 2) != 0)
            return false;
        break;
    case UE_HARDWARE_SIZE_4:
        hwbpSize = SIZE_4;
        if((bpxAddress % 4) != 0)
            return false;
        break;
    case UE_HARDWARE_SIZE_8:
        hwbpSize = SIZE_8;
        if((bpxAddress % 8) != 0)
            return false;
        break;
    default:
        return false;
    }

    if(!IndexOfRegister)
    {
        if(!DebugRegister[0].DrxEnabled)
            IndexOfRegister = UE_DR0;
        else if(!DebugRegister[1].DrxEnabled)
            IndexOfRegister = UE_DR1;
        else if(!DebugRegister[2].DrxEnabled)
            IndexOfRegister = UE_DR2;
        else if(!DebugRegister[3].DrxEnabled)
            IndexOfRegister = UE_DR3;
        else
            return false;
    }

    if(IndexOfSelectedRegister)
        *IndexOfSelectedRegister = IndexOfRegister;

    switch(IndexOfRegister)
    {
    case UE_DR0:
        hwbpIndex = 0;
        break;
    case UE_DR1:
        hwbpIndex = 1;
        break;
    case UE_DR2:
        hwbpIndex = 2;
        break;
    case UE_DR3:
        hwbpIndex = 3;
        break;
    default:
        return false;
    }

    uintdr7((ULONG_PTR)GetContextDataEx(hActiveThread, UE_DR7), &dr7);

    DebugRegister[hwbpIndex].DrxExecution = false;

    switch(bpxType)
    {
    case UE_HARDWARE_EXECUTE:
        hwbpSize = SIZE_1;
        hwbpType = TYPE_EXECUTE;
        DebugRegister[hwbpIndex].DrxExecution = true;
        break;
    case UE_HARDWARE_WRITE:
        hwbpType = TYPE_WRITE;
        break;
    case UE_HARDWARE_READWRITE:
        hwbpType = TYPE_READWRITE;
        break;
    default:
        return false;
    }

    hwbpMode = MODE_LOCAL;

    dr7.HWBP_MODE[hwbpIndex] = hwbpMode;
    dr7.HWBP_SIZE[hwbpIndex] = hwbpSize;
    dr7.HWBP_TYPE[hwbpIndex] = hwbpType;

    SetContextDataEx(hActiveThread, UE_DR7, dr7uint(&dr7));
    SetContextDataEx(hActiveThread, IndexOfRegister, (ULONG_PTR)bpxAddress);

    DebugRegister[hwbpIndex].DrxBreakPointType = bpxType;
    DebugRegister[hwbpIndex].DrxBreakPointSize = bpxSize;
    DebugRegister[hwbpIndex].DrxEnabled = true;
    DebugRegister[hwbpIndex].DrxBreakAddress = (ULONG_PTR)bpxAddress;
    DebugRegister[hwbpIndex].DrxCallBack = (ULONG_PTR)bpxCallBack;

    return true;
}

__declspec(dllexport) bool TITCALL DeleteHardwareBreakPoint(DWORD IndexOfRegister)
{
    ULONG_PTR HardwareBPX = NULL;
    ULONG_PTR bpxAddress = NULL;

    if(IndexOfRegister == UE_DR0)
    {
        HardwareBPX = (ULONG_PTR)GetContextData(UE_DR7);
        HardwareBPX = HardwareBPX & ~(1 << 0);
        HardwareBPX = HardwareBPX & ~(1 << 1);
        for(unsigned int i = 0; i < hListThread.size(); i++)
        {
            SetContextDataEx(hListThread.at(i).hThread, UE_DR0, bpxAddress);
            SetContextDataEx(hListThread.at(i).hThread, UE_DR7, HardwareBPX);
        }
        DebugRegister[0].DrxEnabled = false;
        DebugRegister[0].DrxBreakAddress = NULL;
        DebugRegister[0].DrxCallBack = NULL;
        return true;
    }
    else if(IndexOfRegister == UE_DR1)
    {
        HardwareBPX = (ULONG_PTR)GetContextData(UE_DR7);
        HardwareBPX = HardwareBPX & ~(1 << 2);
        HardwareBPX = HardwareBPX & ~(1 << 3);
        for(unsigned int i = 0; i < hListThread.size(); i++)
        {
            SetContextDataEx(hListThread.at(i).hThread, UE_DR1, bpxAddress);
            SetContextDataEx(hListThread.at(i).hThread, UE_DR7, HardwareBPX);
        }
        DebugRegister[1].DrxEnabled = false;
        DebugRegister[1].DrxBreakAddress = NULL;
        DebugRegister[1].DrxCallBack = NULL;
        return true;
    }
    else if(IndexOfRegister == UE_DR2)
    {
        HardwareBPX = (ULONG_PTR)GetContextData(UE_DR7);
        HardwareBPX = HardwareBPX & ~(1 << 4);
        HardwareBPX = HardwareBPX & ~(1 << 5);
        for(unsigned int i = 0; i < hListThread.size(); i++)
        {
            SetContextDataEx(hListThread.at(i).hThread, UE_DR2, bpxAddress);
            SetContextDataEx(hListThread.at(i).hThread, UE_DR7, HardwareBPX);
        }
        DebugRegister[2].DrxEnabled = false;
        DebugRegister[2].DrxBreakAddress = NULL;
        DebugRegister[2].DrxCallBack = NULL;
        return true;
    }
    else if(IndexOfRegister == UE_DR3)
    {
        HardwareBPX = (ULONG_PTR)GetContextData(UE_DR7);
        HardwareBPX = HardwareBPX & ~(1 << 6);
        HardwareBPX = HardwareBPX & ~(1 << 7);
        for(unsigned int i = 0; i < hListThread.size(); i++)
        {
            SetContextDataEx(hListThread.at(i).hThread, UE_DR3, bpxAddress);
            SetContextDataEx(hListThread.at(i).hThread, UE_DR7, HardwareBPX);
        }
        DebugRegister[3].DrxEnabled = false;
        DebugRegister[3].DrxBreakAddress = NULL;
        DebugRegister[3].DrxCallBack = NULL;
        return true;
    }
    else
    {
        return false;
    }
    return false;
}

__declspec(dllexport) bool TITCALL RemoveAllBreakPoints(DWORD RemoveOption)
{
    CriticalSectionLocker lock(LockBreakPointBuffer);
    int bpcount = (int)BreakPointBuffer.size();
    if(RemoveOption == UE_OPTION_REMOVEALL)
    {
        for(int i = bpcount - 1; i > -1; i--)
        {
            if(BreakPointBuffer.at(i).BreakPointType == UE_BREAKPOINT || BreakPointBuffer.at(i).BreakPointType == UE_SINGLESHOOT)
            {
                DeleteBPX((ULONG_PTR)BreakPointBuffer.at(i).BreakPointAddress);
            }
            else if(BreakPointBuffer.at(i).BreakPointType == UE_MEMORY ||
                    BreakPointBuffer.at(i).BreakPointType == UE_MEMORY_READ ||
                    BreakPointBuffer.at(i).BreakPointType == UE_MEMORY_WRITE ||
                    BreakPointBuffer.at(i).BreakPointType == UE_MEMORY_EXECUTE)
            {
                RemoveMemoryBPX((ULONG_PTR)BreakPointBuffer.at(i).BreakPointAddress, BreakPointBuffer.at(i).BreakPointSize);
            }
        }
        DeleteHardwareBreakPoint(UE_DR0);
        DeleteHardwareBreakPoint(UE_DR1);
        DeleteHardwareBreakPoint(UE_DR2);
        DeleteHardwareBreakPoint(UE_DR3);
        return true;
    }
    else if(RemoveOption == UE_OPTION_DISABLEALL)
    {
        for(int i = bpcount - 1; i > -1; i--)
        {
            if((BreakPointBuffer.at(i).BreakPointType == UE_BREAKPOINT || BreakPointBuffer.at(i).BreakPointType == UE_SINGLESHOOT) && BreakPointBuffer.at(i).BreakPointActive == UE_BPXACTIVE)
            {
                DisableBPX((ULONG_PTR)BreakPointBuffer.at(i).BreakPointAddress);
            }
            else if(BreakPointBuffer.at(i).BreakPointType == UE_MEMORY ||
                    BreakPointBuffer.at(i).BreakPointType == UE_MEMORY_READ ||
                    BreakPointBuffer.at(i).BreakPointType == UE_MEMORY_WRITE ||
                    BreakPointBuffer.at(i).BreakPointType == UE_MEMORY_EXECUTE)
            {
                RemoveMemoryBPX((ULONG_PTR)BreakPointBuffer.at(i).BreakPointAddress, BreakPointBuffer.at(i).BreakPointSize);
            }
        }
        return true;
    }
    else if(RemoveOption == UE_OPTION_REMOVEALLDISABLED)
    {
        for(int i = bpcount - 1; i > -1; i--)
        {
            if((BreakPointBuffer.at(i).BreakPointType == UE_BREAKPOINT || BreakPointBuffer.at(i).BreakPointType == UE_SINGLESHOOT) && BreakPointBuffer.at(i).BreakPointActive == UE_BPXINACTIVE)
            {
                DeleteBPX((ULONG_PTR)BreakPointBuffer.at(i).BreakPointAddress);
            }
        }
        return true;
    }
    else if(RemoveOption == UE_OPTION_REMOVEALLENABLED)
    {
        for(int i = bpcount - 1; i > -1; i--)
        {
            if((BreakPointBuffer.at(i).BreakPointType == UE_BREAKPOINT || BreakPointBuffer.at(i).BreakPointType == UE_SINGLESHOOT) && BreakPointBuffer.at(i).BreakPointActive == UE_BPXACTIVE)
            {
                DeleteBPX((ULONG_PTR)BreakPointBuffer.at(i).BreakPointAddress);
            }
        }
        return true;
    }
    return false;
}
