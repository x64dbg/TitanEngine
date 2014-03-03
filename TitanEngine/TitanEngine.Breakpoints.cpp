#include "stdafx.h"
#include "definitions.h"
#include "Global.Breakpoints.h"
#include "Global.Debugger.h"
#include "Global.Engine.h"

static long engineDefaultBreakPointType = UE_BREAKPOINT_INT3;
static BYTE UD2BreakPoint[2] = {0x0F, 0x0B};
static BYTE INT3BreakPoint = 0xCC;
static BYTE INT3LongBreakPoint[2] = {0xCD, 0x03};

__declspec(dllexport) void TITCALL SetBPXOptions(long DefaultBreakPointType)
{
    engineDefaultBreakPointType = DefaultBreakPointType;
}
__declspec(dllexport) bool TITCALL IsBPXEnabled(ULONG_PTR bpxAddress)
{

    int i;
    ULONG_PTR NumberOfBytesReadWritten = 0;
    DWORD MaximumBreakPoints = 0;
    BYTE ReadData[10] = {};

    for(i = 0; i < BreakPointSetCount; i++)
    {
        if(BreakPointBuffer[i].BreakPointAddress == bpxAddress)
        {
            if(BreakPointBuffer[i].BreakPointActive != UE_BPXINACTIVE && BreakPointBuffer[i].BreakPointActive != UE_BPXREMOVED)
            {
                if(ReadProcessMemory(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, &ReadData[0], UE_MAX_BREAKPOINT_SIZE, &NumberOfBytesReadWritten))
                {
                    if(BreakPointBuffer[i].AdvancedBreakPointType == UE_BREAKPOINT_INT3 && ReadData[0] == INT3BreakPoint)
                    {
                        return(true);
                    }
                    else if(BreakPointBuffer[i].AdvancedBreakPointType == UE_BREAKPOINT_LONG_INT3 && ReadData[0] == INT3LongBreakPoint[0] && ReadData[1] == INT3LongBreakPoint[1])
                    {
                        return(true);
                    }
                    else if(BreakPointBuffer[i].AdvancedBreakPointType == UE_BREAKPOINT_UD2 && ReadData[0] == UD2BreakPoint[0] && ReadData[1] == UD2BreakPoint[1])
                    {
                        return(true);
                    }
                    else
                    {
                        return(false);
                    }
                }
                else
                {
                    return(false);
                }
            }
            else
            {
                return(false);
            }
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL EnableBPX(ULONG_PTR bpxAddress)
{

    int i;
    MEMORY_BASIC_INFORMATION MemInfo;
    ULONG_PTR NumberOfBytesReadWritten = 0;
    DWORD MaximumBreakPoints = 0;
    bool testWrite = false;
    DWORD OldProtect;

    for(i = 0; i < BreakPointSetCount; i++)
    {
        if(BreakPointBuffer[i].BreakPointAddress == bpxAddress)
        {
            VirtualQueryEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
            OldProtect = MemInfo.Protect;
            VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer[i].BreakPointSize, PAGE_EXECUTE_READWRITE, &OldProtect);
            if(BreakPointBuffer[i].BreakPointActive == UE_BPXINACTIVE && (BreakPointBuffer[i].BreakPointType == UE_BREAKPOINT || BreakPointBuffer[i].BreakPointType == UE_SINGLESHOOT))
            {
                if(BreakPointBuffer[i].AdvancedBreakPointType == UE_BREAKPOINT_INT3)
                {
                    if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, &INT3BreakPoint, 1, &NumberOfBytesReadWritten))
                    {
                        testWrite = true;
                    }
                }
                else if(BreakPointBuffer[i].AdvancedBreakPointType == UE_BREAKPOINT_LONG_INT3)
                {
                    if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, &INT3LongBreakPoint, 2, &NumberOfBytesReadWritten))
                    {
                        testWrite = true;
                    }
                }
                else if(BreakPointBuffer[i].AdvancedBreakPointType == UE_BREAKPOINT_UD2)
                {
                    if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, &UD2BreakPoint, 2, &NumberOfBytesReadWritten))
                    {
                        testWrite = true;
                    }
                }
                if(testWrite)
                {
                    BreakPointBuffer[i].BreakPointActive = UE_BPXACTIVE;
                    VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer[i].BreakPointSize, OldProtect, &OldProtect);
                    return(true);
                }
                else
                {
                    VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer[i].BreakPointSize, OldProtect, &OldProtect);
                    return(false);
                }
            }
            else
            {
                VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer[i].BreakPointSize, OldProtect, &OldProtect);
                return(false);
            }
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL DisableBPX(ULONG_PTR bpxAddress)
{

    int i;
    MEMORY_BASIC_INFORMATION MemInfo;
    ULONG_PTR NumberOfBytesReadWritten = 0;
    DWORD MaximumBreakPoints = 0;
    DWORD OldProtect;

    for(i = 0; i < BreakPointSetCount; i++)
    {
        if(BreakPointBuffer[i].BreakPointAddress == bpxAddress)
        {
            VirtualQueryEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
            OldProtect = MemInfo.Protect;
            VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer[i].BreakPointSize, PAGE_EXECUTE_READWRITE, &OldProtect);
            if(BreakPointBuffer[i].BreakPointActive == UE_BPXACTIVE && (BreakPointBuffer[i].BreakPointType == UE_BREAKPOINT || BreakPointBuffer[i].BreakPointType == UE_SINGLESHOOT))
            {
                if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, &BreakPointBuffer[i].OriginalByte[0], BreakPointBuffer[i].BreakPointSize, &NumberOfBytesReadWritten))
                {
                    BreakPointBuffer[i].BreakPointActive = UE_BPXINACTIVE;
                    VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer[i].BreakPointSize, OldProtect, &OldProtect);
                    return(true);
                }
                else
                {
                    VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer[i].BreakPointSize, OldProtect, &OldProtect);
                    return(false);
                }
            }
            else
            {
                VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer[i].BreakPointSize, OldProtect, &OldProtect);
                return(false);
            }
        }
    }
    return(false);
}
__declspec(dllexport) bool TITCALL SetBPX(ULONG_PTR bpxAddress, DWORD bpxType, LPVOID bpxCallBack)
{

    int i = 0;
    int j = -1;
    void* bpxDataPrt;
    PMEMORY_COMPARE_HANDLER bpxDataCmpPtr;
    MEMORY_BASIC_INFORMATION MemInfo;
    ULONG_PTR NumberOfBytesReadWritten = 0;
    BYTE SelectedBreakPointType;
    DWORD checkBpxType;
    DWORD OldProtect;

    if(bpxCallBack == NULL)
    {
        return(false);
    }
    for(i = 0; i < BreakPointSetCount; i++)
    {
        if(BreakPointBuffer[i].BreakPointAddress == bpxAddress && BreakPointBuffer[i].BreakPointActive == UE_BPXACTIVE && (BreakPointBuffer[i].BreakPointType == UE_SINGLESHOOT || BreakPointBuffer[i].BreakPointType == UE_BREAKPOINT))
        {
            return(false);
        }
        else if(BreakPointBuffer[i].BreakPointAddress == bpxAddress && BreakPointBuffer[i].BreakPointActive == UE_BPXINACTIVE && (BreakPointBuffer[i].BreakPointType == UE_SINGLESHOOT || BreakPointBuffer[i].BreakPointType == UE_BREAKPOINT))
        {
            return(EnableBPX(bpxAddress));
        }
        else if(j == -1 && BreakPointBuffer[i].BreakPointActive == UE_BPXREMOVED)
        {
            j = i;
        }
    }
    if(j == -1)
    {
        BreakPointSetCount++;
    }
    else
    {
        i = j;
    }
    if(i < MAXIMUM_BREAKPOINTS)
    {
        RtlZeroMemory(&BreakPointBuffer[i], sizeof BreakPointDetail);
        if(bpxType < UE_BREAKPOINT_TYPE_INT3)
        {
            if(engineDefaultBreakPointType == UE_BREAKPOINT_INT3)
            {
                SelectedBreakPointType = UE_BREAKPOINT_INT3;
                BreakPointBuffer[i].BreakPointSize = 1;
                bpxDataPrt = &INT3BreakPoint;
            }
            else if(engineDefaultBreakPointType == UE_BREAKPOINT_LONG_INT3)
            {
                SelectedBreakPointType = UE_BREAKPOINT_LONG_INT3;
                BreakPointBuffer[i].BreakPointSize = 2;
                bpxDataPrt = &INT3LongBreakPoint;
            }
            else if(engineDefaultBreakPointType == UE_BREAKPOINT_UD2)
            {
                SelectedBreakPointType = UE_BREAKPOINT_UD2;
                BreakPointBuffer[i].BreakPointSize = 2;
                bpxDataPrt = &UD2BreakPoint;
            }
        }
        else
        {
            checkBpxType = bpxType >> 24;
            checkBpxType = checkBpxType << 24;
            if(checkBpxType == UE_BREAKPOINT_TYPE_INT3)
            {
                SelectedBreakPointType = UE_BREAKPOINT_INT3;
                BreakPointBuffer[i].BreakPointSize = 1;
                bpxDataPrt = &INT3BreakPoint;
            }
            else if(checkBpxType == UE_BREAKPOINT_TYPE_LONG_INT3)
            {
                SelectedBreakPointType = UE_BREAKPOINT_LONG_INT3;
                BreakPointBuffer[i].BreakPointSize = 2;
                bpxDataPrt = &INT3LongBreakPoint;
            }
            else if(checkBpxType == UE_BREAKPOINT_TYPE_UD2)
            {
                SelectedBreakPointType = UE_BREAKPOINT_UD2;
                BreakPointBuffer[i].BreakPointSize = 2;
                bpxDataPrt = &UD2BreakPoint;
            }
        }
        bpxDataCmpPtr = (PMEMORY_COMPARE_HANDLER)bpxDataPrt;
        VirtualQueryEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
        OldProtect = MemInfo.Protect;
        VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer[i].BreakPointSize, PAGE_EXECUTE_READWRITE, &OldProtect);
        if(ReadProcessMemory(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, &BreakPointBuffer[i].OriginalByte[0], BreakPointBuffer[i].BreakPointSize, &NumberOfBytesReadWritten))
        {
            /*if(BreakPointBuffer[i].OriginalByte[0] != bpxDataCmpPtr->Array.bArrayEntry[0])
            {*/
            if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, bpxDataPrt, BreakPointBuffer[i].BreakPointSize, &NumberOfBytesReadWritten))
            {
                BreakPointBuffer[i].AdvancedBreakPointType = (BYTE)SelectedBreakPointType;
                BreakPointBuffer[i].BreakPointActive = UE_BPXACTIVE;
                BreakPointBuffer[i].BreakPointAddress = bpxAddress;
                BreakPointBuffer[i].BreakPointType = (BYTE)bpxType;
                BreakPointBuffer[i].NumberOfExecutions = -1;
                BreakPointBuffer[i].ExecuteCallBack = (ULONG_PTR)bpxCallBack;
                VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer[i].BreakPointSize, OldProtect, &OldProtect);
                return(true);
            }
            else
            {
                VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer[i].BreakPointSize, OldProtect, &OldProtect);
                return(false);
            }
            /*}
            else
            {
                VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer[i].BreakPointSize, OldProtect, &OldProtect);
                return(false);
            }*/
        }
        else
        {
            VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer[i].BreakPointSize, OldProtect, &OldProtect);
            return(false);
        }
    }
    else
    {
        BreakPointSetCount--;
        return(false);
    }
}
__declspec(dllexport) bool TITCALL SetBPXEx(ULONG_PTR bpxAddress, DWORD bpxType, DWORD NumberOfExecution, DWORD CmpRegister, DWORD CmpCondition, ULONG_PTR CmpValue, LPVOID bpxCallBack, LPVOID bpxCompareCallBack, LPVOID bpxRemoveCallBack)
{

    int i = 0;
    int j = -1;
    void* bpxDataPrt;
    PMEMORY_COMPARE_HANDLER bpxDataCmpPtr;
    MEMORY_BASIC_INFORMATION MemInfo;
    ULONG_PTR NumberOfBytesReadWritten = 0;
    BYTE SelectedBreakPointType;
    DWORD checkBpxType;
    DWORD OldProtect;

    if(bpxCallBack == NULL)
    {
        return(false);
    }
    for(i = 0; i < BreakPointSetCount; i++)
    {
        if(BreakPointBuffer[i].BreakPointAddress == bpxAddress && BreakPointBuffer[i].BreakPointActive == UE_BPXACTIVE)
        {
            return(true);
        }
        else if(BreakPointBuffer[i].BreakPointAddress == bpxAddress && BreakPointBuffer[i].BreakPointActive == UE_BPXINACTIVE)
        {
            return(EnableBPX(bpxAddress));
        }
        else if(j == -1 && BreakPointBuffer[i].BreakPointActive == UE_BPXREMOVED)
        {
            j = i;
        }
    }
    if(j == -1)
    {
        BreakPointSetCount++;
    }
    else
    {
        i = j;
    }
    if(i < MAXIMUM_BREAKPOINTS)
    {
        RtlZeroMemory(&BreakPointBuffer[i], sizeof BreakPointDetail);
        if(bpxType < UE_BREAKPOINT_TYPE_INT3)
        {
            if(engineDefaultBreakPointType == UE_BREAKPOINT_INT3)
            {
                SelectedBreakPointType = UE_BREAKPOINT_INT3;
                BreakPointBuffer[i].BreakPointSize = 1;
                bpxDataPrt = &INT3BreakPoint;
            }
            else if(engineDefaultBreakPointType == UE_BREAKPOINT_LONG_INT3)
            {
                SelectedBreakPointType = UE_BREAKPOINT_LONG_INT3;
                BreakPointBuffer[i].BreakPointSize = 2;
                bpxDataPrt = &INT3LongBreakPoint;
            }
            else if(engineDefaultBreakPointType == UE_BREAKPOINT_UD2)
            {
                SelectedBreakPointType = UE_BREAKPOINT_UD2;
                BreakPointBuffer[i].BreakPointSize = 2;
                bpxDataPrt = &UD2BreakPoint;
            }
        }
        else
        {
            checkBpxType = bpxType >> 24;
            checkBpxType = checkBpxType << 24;
            if(checkBpxType == UE_BREAKPOINT_TYPE_INT3)
            {
                SelectedBreakPointType = UE_BREAKPOINT_INT3;
                BreakPointBuffer[i].BreakPointSize = 1;
                bpxDataPrt = &INT3BreakPoint;
            }
            else if(checkBpxType == UE_BREAKPOINT_TYPE_LONG_INT3)
            {
                SelectedBreakPointType = UE_BREAKPOINT_LONG_INT3;
                BreakPointBuffer[i].BreakPointSize = 2;
                bpxDataPrt = &INT3LongBreakPoint;
            }
            else if(checkBpxType == UE_BREAKPOINT_TYPE_UD2)
            {
                SelectedBreakPointType = UE_BREAKPOINT_UD2;
                BreakPointBuffer[i].BreakPointSize = 2;
                bpxDataPrt = &UD2BreakPoint;
            }
        }
        bpxDataCmpPtr = (PMEMORY_COMPARE_HANDLER)bpxDataPrt;
        VirtualQueryEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
        OldProtect = MemInfo.Protect;
        VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer[i].BreakPointSize, PAGE_EXECUTE_READWRITE, &OldProtect);
        if(ReadProcessMemory(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, &BreakPointBuffer[i].OriginalByte[0], BreakPointBuffer[i].BreakPointSize, &NumberOfBytesReadWritten))
        {
            /*if(BreakPointBuffer[i].OriginalByte[0] != bpxDataCmpPtr->Array.bArrayEntry[0])
            {*/
            if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, bpxDataPrt, BreakPointBuffer[i].BreakPointSize, &NumberOfBytesReadWritten))
            {
                BreakPointBuffer[i].AdvancedBreakPointType = (BYTE)SelectedBreakPointType;
                BreakPointBuffer[i].BreakPointActive = UE_BPXACTIVE;
                BreakPointBuffer[i].BreakPointAddress = bpxAddress;
                BreakPointBuffer[i].BreakPointType = (BYTE)bpxType;
                BreakPointBuffer[i].NumberOfExecutions = NumberOfExecution;
                BreakPointBuffer[i].CmpRegister = CmpRegister;
                BreakPointBuffer[i].CmpCondition = (BYTE)CmpCondition;
                BreakPointBuffer[i].CmpValue = CmpValue;
                BreakPointBuffer[i].ExecuteCallBack = (ULONG_PTR)bpxCallBack;
                BreakPointBuffer[i].RemoveCallBack = (ULONG_PTR)bpxRemoveCallBack;
                BreakPointBuffer[i].CompareCallBack = (ULONG_PTR)bpxCompareCallBack;
                VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer[i].BreakPointSize, OldProtect, &OldProtect);
                return(true);
            }
            else
            {
                VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer[i].BreakPointSize, OldProtect, &OldProtect);
                return(false);
            }
            /*}
            else
            {
                VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer[i].BreakPointSize, OldProtect, &OldProtect);
                return(false);
            }*/
        }
        else
        {
            VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer[i].BreakPointSize, OldProtect, &OldProtect);
            return(false);
        }
    }
    else
    {
        BreakPointSetCount--;
        return(false);
    }
}
__declspec(dllexport) bool TITCALL DeleteBPX(ULONG_PTR bpxAddress)
{

    int i;
    typedef void(TITCALL *fCustomBreakPoint)(void* myBreakPointAddress);
    fCustomBreakPoint myCustomBreakPoint;
    MEMORY_BASIC_INFORMATION MemInfo;
    ULONG_PTR NumberOfBytesReadWritten = 0;
    DWORD OldProtect;

    for(i = 0; i < BreakPointSetCount; i++)
    {
        if(BreakPointBuffer[i].BreakPointAddress == bpxAddress)
        {
            if(i - 1 == BreakPointSetCount)
            {
                BreakPointSetCount--;
            }
            break;
        }
    }
    if(BreakPointBuffer[i].BreakPointAddress == bpxAddress)
    {
        VirtualQueryEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
        OldProtect = MemInfo.Protect;
        VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer[i].BreakPointSize, PAGE_EXECUTE_READWRITE, &OldProtect);
        if(BreakPointBuffer[i].BreakPointType == UE_BREAKPOINT || BreakPointBuffer[i].BreakPointType == UE_SINGLESHOOT)
        {
            if(BreakPointBuffer[i].BreakPointActive == UE_BPXACTIVE)
            {
                if(WriteProcessMemory(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, &BreakPointBuffer[i].OriginalByte[0], BreakPointBuffer[i].BreakPointSize, &NumberOfBytesReadWritten))
                {
                    VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer[i].BreakPointSize, OldProtect, &OldProtect);
                    if(BreakPointBuffer[i].RemoveCallBack != NULL)
                    {
                        __try
                        {
                            myCustomBreakPoint = (fCustomBreakPoint)((LPVOID)BreakPointBuffer[i].RemoveCallBack);
                            myCustomBreakPoint((void*)BreakPointBuffer[i].BreakPointAddress);
                            RtlZeroMemory(&BreakPointBuffer[i], sizeof BreakPointDetail);
                        }
                        __except(EXCEPTION_EXECUTE_HANDLER)
                        {
                            RtlZeroMemory(&BreakPointBuffer[i], sizeof BreakPointDetail);
                            return(true);
                        }
                    }
                    else
                    {
                        RtlZeroMemory(&BreakPointBuffer[i], sizeof BreakPointDetail);
                    }
                    return(true);
                }
                else
                {
                    VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer[i].BreakPointSize, OldProtect, &OldProtect);
                    return(false);
                }
            }
            else
            {
                RtlZeroMemory(&BreakPointBuffer[i], sizeof BreakPointDetail);
                return(true);
            }
        }
        else
        {
            VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)bpxAddress, BreakPointBuffer[i].BreakPointSize, OldProtect, &OldProtect);
            return(false);
        }
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL SafeDeleteBPX(ULONG_PTR bpxAddress)
{
    return(DeleteBPX(bpxAddress));
}
__declspec(dllexport) bool TITCALL SetAPIBreakPoint(char* szDLLName, char* szAPIName, DWORD bpxType, DWORD bpxPlace, LPVOID bpxCallBack)
{

    BYTE ReadByte = NULL;
    HMODULE hModule = NULL;
    DWORD ReadMemSize = NULL;
    ULONG_PTR APIAddress = NULL;
    ULONG_PTR tryAPIAddress = NULL;
    ULONG_PTR QueryAPIAddress = NULL;
    int i = MAX_RET_SEARCH_INSTRUCTIONS;
    ULONG_PTR ueNumberOfReadWrite = NULL;
    int currentInstructionLen = NULL;
    bool ModuleLoaded = false;
    void* CmdBuffer = NULL;
    bool RemovedBpx = false;

    if(szDLLName != NULL && szAPIName != NULL)
    {
        hModule = GetModuleHandleA(szDLLName);
        if(hModule == NULL)
        {
            if(engineAlowModuleLoading)
            {
                hModule = LoadLibraryA(szDLLName);
                ModuleLoaded = true;
            }
            else
            {
                ReadMemSize = MAX_RET_SEARCH_INSTRUCTIONS * MAXIMUM_INSTRUCTION_SIZE;
                APIAddress = (ULONG_PTR)EngineGlobalAPIHandler(dbgProcessInformation.hProcess, NULL, NULL, szAPIName, UE_OPTION_IMPORTER_RETURN_APIADDRESS);
                if(APIAddress != NULL)
                {
                    CmdBuffer = VirtualAlloc(NULL, ReadMemSize, MEM_COMMIT, PAGE_READWRITE);
                    while(ReadProcessMemory(dbgProcessInformation.hProcess, (void*)APIAddress, CmdBuffer, ReadMemSize, &ueNumberOfReadWrite) == false && ReadMemSize > NULL)
                    {
                        ReadMemSize = ReadMemSize - (MAXIMUM_INSTRUCTION_SIZE * 10);
                    }
                    if(ReadMemSize == NULL)
                    {
                        VirtualFree(CmdBuffer, NULL, MEM_RELEASE);
                        APIAddress = NULL;
                    }
                    else
                    {
                        tryAPIAddress = (ULONG_PTR)CmdBuffer;
                    }
                }
            }
        }
        if(hModule != NULL || APIAddress != NULL)
        {
            if(hModule != NULL)
            {
                APIAddress = (ULONG_PTR)GetProcAddress(hModule, szAPIName);
            }
            if(bpxPlace == UE_APIEND)
            {
                if(tryAPIAddress == NULL)
                {
                    tryAPIAddress = APIAddress;
                }
                QueryAPIAddress = APIAddress;
                RtlMoveMemory(&ReadByte, (LPVOID)tryAPIAddress, 1);
                while(i > 0 && ReadByte != 0xC3 && ReadByte != 0xC2)
                {
                    if(engineAlowModuleLoading == false && CmdBuffer != NULL)
                    {
                        if(IsBPXEnabled(QueryAPIAddress))
                        {
                            DisableBPX(QueryAPIAddress);
                            ReadProcessMemory(dbgProcessInformation.hProcess, (void*)APIAddress, CmdBuffer, ReadMemSize, &ueNumberOfReadWrite);
                            RemovedBpx = true;
                        }
                    }
                    currentInstructionLen = StaticLengthDisassemble((LPVOID)tryAPIAddress);
                    tryAPIAddress = tryAPIAddress + currentInstructionLen;
                    RtlMoveMemory(&ReadByte, (LPVOID)tryAPIAddress, 1);
                    QueryAPIAddress = QueryAPIAddress + currentInstructionLen;
                    if(!engineAlowModuleLoading)
                    {
                        if(RemovedBpx)
                        {
                            EnableBPX(QueryAPIAddress - currentInstructionLen);
                        }
                    }
                    RemovedBpx = false;
                    i--;
                }
                if(i != NULL)
                {
                    if((engineAlowModuleLoading == true && ModuleLoaded == true) || (engineAlowModuleLoading == true && ModuleLoaded == false))
                    {
                        APIAddress = tryAPIAddress;
                    }
                    else if(!engineAlowModuleLoading)
                    {
                        if(CmdBuffer != NULL)
                        {
                            APIAddress = tryAPIAddress - (ULONG_PTR)CmdBuffer + APIAddress;
                        }
                        else
                        {
                            APIAddress = tryAPIAddress;
                        }
                    }
                }
                else
                {
                    if(ModuleLoaded)
                    {
                        FreeLibrary(hModule);
                    }
                    if(CmdBuffer != NULL)
                    {
                        VirtualFree(CmdBuffer, NULL, MEM_RELEASE);
                    }
                    return(false);
                }
            }
            if(engineAlowModuleLoading)
            {
                APIAddress = (ULONG_PTR)EngineGlobalAPIHandler(dbgProcessInformation.hProcess, NULL, APIAddress, NULL, UE_OPTION_IMPORTER_REALIGN_APIADDRESS);
                if(ModuleLoaded)
                {
                    FreeLibrary(hModule);
                }
            }
            else
            {
                if(CmdBuffer != NULL)
                {
                    VirtualFree(CmdBuffer, NULL, MEM_RELEASE);
                }
            }
            return(SetBPX(APIAddress, bpxType, bpxCallBack));
        }
        else
        {
            if(engineAlowModuleLoading)
            {
                if(ModuleLoaded)
                {
                    FreeLibrary(hModule);
                }
            }
            else
            {
                if(CmdBuffer != NULL)
                {
                    VirtualFree(CmdBuffer, NULL, MEM_RELEASE);
                }
            }
            return(false);
        }
    }
    else
    {
        return(false);
    }
    return(false);
}
__declspec(dllexport) bool TITCALL DeleteAPIBreakPoint(char* szDLLName, char* szAPIName, DWORD bpxPlace)
{

    BYTE ReadByte = NULL;
    HMODULE hModule = NULL;
    DWORD ReadMemSize = NULL;
    ULONG_PTR APIAddress = NULL;
    ULONG_PTR tryAPIAddress = NULL;
    ULONG_PTR QueryAPIAddress = NULL;
    int i = MAX_RET_SEARCH_INSTRUCTIONS;
    ULONG_PTR ueNumberOfReadWrite = NULL;
    int currentInstructionLen = NULL;
    bool ModuleLoaded = false;
    void* CmdBuffer = NULL;
    bool RemovedBpx = false;

    if(szDLLName != NULL && szAPIName != NULL)
    {
        hModule = GetModuleHandleA(szDLLName);
        if(hModule == NULL)
        {
            if(engineAlowModuleLoading)
            {
                hModule = LoadLibraryA(szDLLName);
                ModuleLoaded = true;
            }
            else
            {
                ReadMemSize = MAX_RET_SEARCH_INSTRUCTIONS * MAXIMUM_INSTRUCTION_SIZE;
                APIAddress = (ULONG_PTR)EngineGlobalAPIHandler(dbgProcessInformation.hProcess, NULL, NULL, szAPIName, UE_OPTION_IMPORTER_RETURN_APIADDRESS);
                if(APIAddress != NULL)
                {
                    CmdBuffer = VirtualAlloc(NULL, ReadMemSize, MEM_COMMIT, PAGE_READWRITE);
                    while(ReadProcessMemory(dbgProcessInformation.hProcess, (void*)APIAddress, CmdBuffer, ReadMemSize, &ueNumberOfReadWrite) == false && ReadMemSize > NULL)
                    {
                        ReadMemSize = ReadMemSize - (MAXIMUM_INSTRUCTION_SIZE * 10);
                    }
                    if(ReadMemSize == NULL)
                    {
                        VirtualFree(CmdBuffer, NULL, MEM_RELEASE);
                        APIAddress = NULL;
                    }
                    else
                    {
                        tryAPIAddress = (ULONG_PTR)CmdBuffer;
                    }
                }
            }
        }
        if(hModule != NULL || APIAddress != NULL)
        {
            if(hModule != NULL)
            {
                APIAddress = (ULONG_PTR)GetProcAddress(hModule, szAPIName);
            }
            if(bpxPlace == UE_APIEND)
            {
                if(tryAPIAddress == NULL)
                {
                    tryAPIAddress = APIAddress;
                }
                QueryAPIAddress = APIAddress;
                RtlMoveMemory(&ReadByte, (LPVOID)tryAPIAddress, 1);
                while(i > 0 && ReadByte != 0xC3 && ReadByte != 0xC2)
                {
                    if(engineAlowModuleLoading == false && CmdBuffer != NULL)
                    {
                        if(IsBPXEnabled(QueryAPIAddress))
                        {
                            DisableBPX(QueryAPIAddress);
                            ReadProcessMemory(dbgProcessInformation.hProcess, (void*)APIAddress, CmdBuffer, ReadMemSize, &ueNumberOfReadWrite);
                            RemovedBpx = true;
                        }
                    }
                    currentInstructionLen = StaticLengthDisassemble((LPVOID)tryAPIAddress);
                    tryAPIAddress = tryAPIAddress + currentInstructionLen;
                    RtlMoveMemory(&ReadByte, (LPVOID)tryAPIAddress, 1);
                    QueryAPIAddress = QueryAPIAddress + currentInstructionLen;
                    if(!engineAlowModuleLoading)
                    {
                        if(RemovedBpx)
                        {
                            EnableBPX(QueryAPIAddress - currentInstructionLen);
                        }
                    }
                    RemovedBpx = false;
                    i--;
                }
                if(i != NULL)
                {
                    if((engineAlowModuleLoading == true && ModuleLoaded == true) || (engineAlowModuleLoading == true && ModuleLoaded == false))
                    {
                        APIAddress = tryAPIAddress;
                    }
                    else if(!engineAlowModuleLoading)
                    {
                        if(CmdBuffer != NULL)
                        {
                            APIAddress = tryAPIAddress - (ULONG_PTR)CmdBuffer + APIAddress;
                        }
                        else
                        {
                            APIAddress = tryAPIAddress;
                        }
                    }
                }
                else
                {
                    if(ModuleLoaded)
                    {
                        FreeLibrary(hModule);
                    }
                    if(CmdBuffer != NULL)
                    {
                        VirtualFree(CmdBuffer, NULL, MEM_RELEASE);
                    }
                    return(false);
                }
            }
            if(engineAlowModuleLoading)
            {
                APIAddress = (ULONG_PTR)EngineGlobalAPIHandler(dbgProcessInformation.hProcess, NULL, APIAddress, NULL, UE_OPTION_IMPORTER_REALIGN_APIADDRESS);
                if(ModuleLoaded)
                {
                    FreeLibrary(hModule);
                }
            }
            else
            {
                if(CmdBuffer != NULL)
                {
                    VirtualFree(CmdBuffer, NULL, MEM_RELEASE);
                }
            }
            return(DeleteBPX(APIAddress));
        }
        else
        {
            if(engineAlowModuleLoading)
            {
                if(ModuleLoaded)
                {
                    FreeLibrary(hModule);
                }
            }
            else
            {
                if(CmdBuffer != NULL)
                {
                    VirtualFree(CmdBuffer, NULL, MEM_RELEASE);
                }
            }
            return(false);
        }
    }
    else
    {
        return(false);
    }
    return(false);
}
__declspec(dllexport) bool TITCALL SafeDeleteAPIBreakPoint(char* szDLLName, char* szAPIName, DWORD bpxPlace)
{
    return(DeleteAPIBreakPoint(szDLLName, szAPIName, bpxPlace));
}
__declspec(dllexport) bool TITCALL SetMemoryBPX(ULONG_PTR MemoryStart, SIZE_T SizeOfMemory, LPVOID bpxCallBack)
{
    int i = 0;
    int j = -1;
    MEMORY_BASIC_INFORMATION MemInfo;
    ULONG_PTR NumberOfBytesReadWritten = 0;
    DWORD NewProtect = 0;
    DWORD OldProtect = 0;

    for(i = 0; i < BreakPointSetCount; i++)
    {
        if(BreakPointBuffer[i].BreakPointAddress == MemoryStart)
        {
            if(BreakPointBuffer[i].BreakPointActive == UE_BPXACTIVE)
            {
                RemoveMemoryBPX(BreakPointBuffer[i].BreakPointAddress, BreakPointBuffer[i].BreakPointSize);
            }
            j = i;
            break;
        }
        else if(j == -1 && BreakPointBuffer[i].BreakPointActive == UE_BPXREMOVED)
        {
            j = i;
        }
    }
    if(BreakPointBuffer[i].BreakPointAddress != MemoryStart)
    {
        if(j != -1)
        {
            i = j;
        }
        else
        {
            BreakPointSetCount++;
        }
    }
    if(i < MAXIMUM_BREAKPOINTS)
    {
        RtlZeroMemory(&BreakPointBuffer[i], sizeof BreakPointDetail);
        VirtualQueryEx(dbgProcessInformation.hProcess, (LPVOID)MemoryStart, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
        OldProtect = MemInfo.Protect;
        if(!(OldProtect & PAGE_GUARD))
        {
            NewProtect = OldProtect ^ PAGE_GUARD;
            VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)MemoryStart, SizeOfMemory, NewProtect, &OldProtect);
            BreakPointBuffer[i].BreakPointActive = UE_BPXACTIVE;
            BreakPointBuffer[i].BreakPointAddress = MemoryStart;
            BreakPointBuffer[i].BreakPointType = UE_MEMORY;
            BreakPointBuffer[i].BreakPointSize = SizeOfMemory;
            BreakPointBuffer[i].NumberOfExecutions = -1;
            BreakPointBuffer[i].ExecuteCallBack = (ULONG_PTR)bpxCallBack;
        }
        return(true);
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL SetMemoryBPXEx(ULONG_PTR MemoryStart, SIZE_T SizeOfMemory, DWORD BreakPointType, bool RestoreOnHit, LPVOID bpxCallBack)
{

    int i = 0;
    int j = -1;
    MEMORY_BASIC_INFORMATION MemInfo;
    ULONG_PTR NumberOfBytesReadWritten = 0;
    DWORD NewProtect = 0;
    DWORD OldProtect = 0;

    for(i = 0; i < BreakPointSetCount; i++)
    {
        if(BreakPointBuffer[i].BreakPointAddress == MemoryStart)
        {
            if(BreakPointBuffer[i].BreakPointActive == UE_BPXACTIVE)
            {
                RemoveMemoryBPX(BreakPointBuffer[i].BreakPointAddress, BreakPointBuffer[i].BreakPointSize);
            }
            j = i;
            break;
        }
        else if(j == -1 && BreakPointBuffer[i].BreakPointActive == UE_BPXREMOVED)
        {
            j = i;
        }
    }
    if(BreakPointBuffer[i].BreakPointAddress != MemoryStart)
    {
        if(j != -1)
        {
            i = j;
        }
        else
        {
            BreakPointSetCount++;
        }
    }
    if(i < MAXIMUM_BREAKPOINTS)
    {
        RtlZeroMemory(&BreakPointBuffer[i], sizeof BreakPointDetail);
        VirtualQueryEx(dbgProcessInformation.hProcess, (LPVOID)MemoryStart, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
        OldProtect = MemInfo.Protect;
        if(!(OldProtect & PAGE_GUARD))
        {
            NewProtect = OldProtect ^ PAGE_GUARD;
            VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)MemoryStart, SizeOfMemory, NewProtect, &OldProtect);
            BreakPointBuffer[i].BreakPointActive = UE_BPXACTIVE;
            BreakPointBuffer[i].BreakPointAddress = MemoryStart;
            BreakPointBuffer[i].BreakPointType = BreakPointType;
            BreakPointBuffer[i].BreakPointSize = SizeOfMemory;
            BreakPointBuffer[i].NumberOfExecutions = -1;
            BreakPointBuffer[i].MemoryBpxRestoreOnHit = (BYTE)RestoreOnHit;
            BreakPointBuffer[i].ExecuteCallBack = (ULONG_PTR)bpxCallBack;
        }
        return(true);
    }
    else
    {
        return(false);
    }
}
__declspec(dllexport) bool TITCALL RemoveMemoryBPX(ULONG_PTR MemoryStart, SIZE_T SizeOfMemory)
{

    int i = 0;
    MEMORY_BASIC_INFORMATION MemInfo;
    ULONG_PTR NumberOfBytesReadWritten = 0;
    DWORD NewProtect = 0;
    DWORD OldProtect = 0;

    for(i = 0; i < BreakPointSetCount; i++)
    {
        if(BreakPointBuffer[i].BreakPointAddress == MemoryStart &&
                (BreakPointBuffer[i].BreakPointType == UE_MEMORY ||
                 BreakPointBuffer[i].BreakPointType == UE_MEMORY_READ ||
                 BreakPointBuffer[i].BreakPointType == UE_MEMORY_WRITE ||
                 BreakPointBuffer[i].BreakPointType == UE_MEMORY_EXECUTE)
          )
        {
            if(i - 1 == BreakPointSetCount)
            {
                BreakPointSetCount--;
            }
            break;
        }
    }
    if(BreakPointBuffer[i].BreakPointAddress == MemoryStart)
    {
        VirtualQueryEx(dbgProcessInformation.hProcess, (LPVOID)MemoryStart, &MemInfo, sizeof MEMORY_BASIC_INFORMATION);
        OldProtect = MemInfo.Protect;
        if(OldProtect & PAGE_GUARD)
        {
            NewProtect = OldProtect ^ PAGE_GUARD;
        }
        else
        {
            NewProtect = OldProtect;
        }
        if(SizeOfMemory != NULL)
        {
            VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)MemoryStart, SizeOfMemory, NewProtect, &OldProtect);
        }
        else
        {
            VirtualProtectEx(dbgProcessInformation.hProcess, (LPVOID)MemoryStart, BreakPointBuffer[i].BreakPointSize, NewProtect, &OldProtect);
        }
        RtlZeroMemory(&BreakPointBuffer[i], sizeof BreakPointDetail);
        return(true);
    }
    else
    {
        return(false);
    }
}

__declspec(dllexport) bool TITCALL GetUnusedHardwareBreakPointRegister(LPDWORD RegisterIndex)
{
    return(EngineIsThereFreeHardwareBreakSlot(RegisterIndex));
}

__declspec(dllexport) bool TITCALL SetHardwareBreakPoint(ULONG_PTR bpxAddress, DWORD IndexOfRegister, DWORD bpxType, DWORD bpxSize, LPVOID bpxCallBack)
{
    HWBP_SIZE hwbpSize;
    HWBP_MODE hwbpMode;
    HWBP_TYPE hwbpType;
    int hwbpIndex=-1;
    DR7 dr7;

    switch(bpxSize)
    {
    case UE_HARDWARE_SIZE_1:
        hwbpSize=SIZE_1;
        break;
    case UE_HARDWARE_SIZE_2:
        hwbpSize=SIZE_2;
        if((bpxAddress%2)!=0)
            return false;
        break;
    case UE_HARDWARE_SIZE_4:
        hwbpSize=SIZE_4;
        if((bpxAddress%4)!=0)
            return false;
        break;
    case UE_HARDWARE_SIZE_8:
        hwbpSize=SIZE_8;
        if((bpxAddress%8)!=0)
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
        hwbpIndex=0;
        break;
    case UE_DR1:
        hwbpIndex=1;
        break;
    case UE_DR2:
        hwbpIndex=2;
        break;
    case UE_DR3:
        hwbpIndex=3;
        break;
    default:
        return false;
    }

    uintdr7((ULONG_PTR)GetContextData(UE_DR7), &dr7);

    DebugRegister[hwbpIndex].DrxExecution=false;

    switch(bpxType)
    {
    case UE_HARDWARE_EXECUTE:
        hwbpSize=SIZE_1;
        hwbpType=TYPE_EXECUTE;
        DebugRegister[hwbpIndex].DrxExecution=true;
        break;
    case UE_HARDWARE_WRITE:
        hwbpType=TYPE_WRITE;
        break;
    case UE_HARDWARE_READWRITE:
        hwbpType=TYPE_READWRITE;
        break;
    default:
        return false;
    }

    hwbpMode=MODE_LOCAL;

    dr7.HWBP_MODE[hwbpIndex]=hwbpMode;
    dr7.HWBP_SIZE[hwbpIndex]=hwbpSize;
    dr7.HWBP_TYPE[hwbpIndex]=hwbpType;

    SetContextData(UE_DR7, dr7uint(&dr7)); //NOTE: MUST SET THIS FIRST FOR X64!
    SetContextData(IndexOfRegister, (ULONG_PTR)bpxAddress);

    DebugRegister[hwbpIndex].DrxBreakPointType=bpxType;
    DebugRegister[hwbpIndex].DrxBreakPointSize=bpxSize;
    DebugRegister[hwbpIndex].DrxEnabled=true;
    DebugRegister[hwbpIndex].DrxBreakAddress=(ULONG_PTR)bpxAddress;
    DebugRegister[hwbpIndex].DrxCallBack=(ULONG_PTR)bpxCallBack;

    return true;
}

__declspec(dllexport) bool TITCALL DeleteHardwareBreakPoint(DWORD IndexOfRegister)
{

    ULONG_PTR HardwareBPX = NULL;
    ULONG_PTR bpxAddress = NULL;

    if(IndexOfRegister == UE_DR0)
    {
        HardwareBPX = (ULONG_PTR)GetContextData(UE_DR7);
        HardwareBPX = HardwareBPX &~ (1 << 0);
        HardwareBPX = HardwareBPX &~ (1 << 1);
        SetContextData(UE_DR0, (ULONG_PTR)bpxAddress);
        SetContextData(UE_DR7, HardwareBPX);
        DebugRegister[0].DrxEnabled = false;
        DebugRegister[0].DrxBreakAddress = NULL;
        DebugRegister[0].DrxCallBack = NULL;
        return(true);
    }
    else if(IndexOfRegister == UE_DR1)
    {
        HardwareBPX = (ULONG_PTR)GetContextData(UE_DR7);
        HardwareBPX = HardwareBPX &~ (1 << 2);
        HardwareBPX = HardwareBPX &~ (1 << 3);
        SetContextData(UE_DR1, (ULONG_PTR)bpxAddress);
        SetContextData(UE_DR7, HardwareBPX);
        DebugRegister[1].DrxEnabled = false;
        DebugRegister[1].DrxBreakAddress = NULL;
        DebugRegister[1].DrxCallBack = NULL;
        return(true);
    }
    else if(IndexOfRegister == UE_DR2)
    {
        HardwareBPX = (ULONG_PTR)GetContextData(UE_DR7);
        HardwareBPX = HardwareBPX &~ (1 << 4);
        HardwareBPX = HardwareBPX &~ (1 << 5);
        SetContextData(UE_DR2, (ULONG_PTR)bpxAddress);
        SetContextData(UE_DR7, HardwareBPX);
        DebugRegister[2].DrxEnabled = false;
        DebugRegister[2].DrxBreakAddress = NULL;
        DebugRegister[2].DrxCallBack = NULL;
        return(true);
    }
    else if(IndexOfRegister == UE_DR3)
    {
        HardwareBPX = (ULONG_PTR)GetContextData(UE_DR7);
        HardwareBPX = HardwareBPX &~ (1 << 6);
        HardwareBPX = HardwareBPX &~ (1 << 7);
        SetContextData(UE_DR3, (ULONG_PTR)bpxAddress);
        SetContextData(UE_DR7, HardwareBPX);
        DebugRegister[3].DrxEnabled = false;
        DebugRegister[3].DrxBreakAddress = NULL;
        DebugRegister[3].DrxCallBack = NULL;
        return(true);
    }
    else
    {
        return(false);
    }
    return(false);
}

__declspec(dllexport) bool TITCALL SetHardwareBreakPointEx(HANDLE hActiveThread, ULONG_PTR bpxAddress, DWORD IndexOfRegister, DWORD bpxType, DWORD bpxSize, LPVOID bpxCallBack, LPDWORD IndexOfSelectedRegister)
{
    HWBP_SIZE hwbpSize;
    HWBP_MODE hwbpMode;
    HWBP_TYPE hwbpType;
    int hwbpIndex=-1;
    DR7 dr7;

    switch(bpxSize)
    {
    case UE_HARDWARE_SIZE_1:
        hwbpSize=SIZE_1;
        break;
    case UE_HARDWARE_SIZE_2:
        hwbpSize=SIZE_2;
        if((bpxAddress%2)!=0)
            return false;
        break;
    case UE_HARDWARE_SIZE_4:
        hwbpSize=SIZE_4;
        if((bpxAddress%4)!=0)
            return false;
        break;
    case UE_HARDWARE_SIZE_8:
        hwbpSize=SIZE_8;
        if((bpxAddress%8)!=0)
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
        *IndexOfSelectedRegister=IndexOfRegister;

    switch(IndexOfRegister)
    {
    case UE_DR0:
        hwbpIndex=0;
        break;
    case UE_DR1:
        hwbpIndex=1;
        break;
    case UE_DR2:
        hwbpIndex=2;
        break;
    case UE_DR3:
        hwbpIndex=3;
        break;
    default:
        return false;
    }

    uintdr7((ULONG_PTR)GetContextDataEx(hActiveThread, UE_DR7), &dr7);

    DebugRegister[hwbpIndex].DrxExecution=false;

    switch(bpxType)
    {
    case UE_HARDWARE_EXECUTE:
        hwbpSize=SIZE_1;
        hwbpType=TYPE_EXECUTE;
        DebugRegister[hwbpIndex].DrxExecution=true;
        break;
    case UE_HARDWARE_WRITE:
        hwbpType=TYPE_WRITE;
        break;
    case UE_HARDWARE_READWRITE:
        hwbpType=TYPE_READWRITE;
        break;
    default:
        return false;
    }

    hwbpMode=MODE_LOCAL;

    dr7.HWBP_MODE[hwbpIndex]=hwbpMode;
    dr7.HWBP_SIZE[hwbpIndex]=hwbpSize;
    dr7.HWBP_TYPE[hwbpIndex]=hwbpType;

    SetContextDataEx(hActiveThread, UE_DR7, dr7uint(&dr7));
    SetContextDataEx(hActiveThread, IndexOfRegister, (ULONG_PTR)bpxAddress);

    DebugRegister[hwbpIndex].DrxBreakPointType=bpxType;
    DebugRegister[hwbpIndex].DrxBreakPointSize=bpxSize;
    DebugRegister[hwbpIndex].DrxEnabled=true;
    DebugRegister[hwbpIndex].DrxBreakAddress=(ULONG_PTR)bpxAddress;
    DebugRegister[hwbpIndex].DrxCallBack=(ULONG_PTR)bpxCallBack;

    return true;
}

__declspec(dllexport) bool TITCALL RemoveAllBreakPoints(DWORD RemoveOption)
{

    int i = 0;
    int CurrentBreakPointSetCount = -1;

    if(RemoveOption == UE_OPTION_REMOVEALL)
    {
        for(i = BreakPointSetCount - 1; i >= 0; i--)
        {
            if(BreakPointBuffer[i].BreakPointType == UE_BREAKPOINT)
            {
                DeleteBPX((ULONG_PTR)BreakPointBuffer[i].BreakPointAddress);
            }
            else if(BreakPointBuffer[i].BreakPointType >= UE_MEMORY && BreakPointBuffer[i].BreakPointType <= UE_MEMORY_EXECUTE)
            {
                RemoveMemoryBPX((ULONG_PTR)BreakPointBuffer[i].BreakPointAddress, BreakPointBuffer[i].BreakPointSize);
            }
            else if(CurrentBreakPointSetCount == -1 && BreakPointBuffer[i].BreakPointActive != UE_BPXREMOVED)
            {
                CurrentBreakPointSetCount = BreakPointSetCount;
            }
            RtlZeroMemory(&BreakPointBuffer[i], sizeof BreakPointDetail);
        }
        DeleteHardwareBreakPoint(UE_DR0);
        DeleteHardwareBreakPoint(UE_DR1);
        DeleteHardwareBreakPoint(UE_DR2);
        DeleteHardwareBreakPoint(UE_DR3);
        BreakPointSetCount = 0;
        return(true);
    }
    else if(RemoveOption == UE_OPTION_DISABLEALL)
    {
        for(i = BreakPointSetCount - 1; i >= 0; i--)
        {
            if(BreakPointBuffer[i].BreakPointType == UE_BREAKPOINT && BreakPointBuffer[i].BreakPointActive == UE_BPXACTIVE)
            {
                DisableBPX((ULONG_PTR)BreakPointBuffer[i].BreakPointAddress);
            }
            else if(BreakPointBuffer[i].BreakPointType >= UE_MEMORY && BreakPointBuffer[i].BreakPointType <= UE_MEMORY_EXECUTE)
            {
                RemoveMemoryBPX((ULONG_PTR)BreakPointBuffer[i].BreakPointAddress, BreakPointBuffer[i].BreakPointSize);
                RtlZeroMemory(&BreakPointBuffer[i], sizeof BreakPointDetail);
            }
        }
        return(true);
    }
    else if(RemoveOption == UE_OPTION_REMOVEALLDISABLED)
    {
        for(i = BreakPointSetCount - 1; i >= 0; i--)
        {
            if(BreakPointBuffer[i].BreakPointType == UE_BREAKPOINT && BreakPointBuffer[i].BreakPointActive == UE_BPXINACTIVE)
            {
                DeleteBPX((ULONG_PTR)BreakPointBuffer[i].BreakPointAddress);
            }
            else if(CurrentBreakPointSetCount == -1 && BreakPointBuffer[i].BreakPointActive != UE_BPXREMOVED)
            {
                CurrentBreakPointSetCount = BreakPointSetCount;
            }
        }
        if(CurrentBreakPointSetCount == -1)
        {
            BreakPointSetCount = 0;
        }
        else
        {
            BreakPointSetCount = CurrentBreakPointSetCount;
        }
        return(true);
    }
    else if(RemoveOption == UE_OPTION_REMOVEALLENABLED)
    {
        for(i = BreakPointSetCount - 1; i >= 0; i--)
        {
            if(BreakPointBuffer[i].BreakPointType == UE_BREAKPOINT && BreakPointBuffer[i].BreakPointActive == UE_BPXACTIVE)
            {
                DeleteBPX((ULONG_PTR)BreakPointBuffer[i].BreakPointAddress);
            }
            else if(CurrentBreakPointSetCount == -1 && BreakPointBuffer[i].BreakPointActive != UE_BPXREMOVED)
            {
                CurrentBreakPointSetCount = BreakPointSetCount;
            }
        }
        if(CurrentBreakPointSetCount == -1)
        {
            BreakPointSetCount = 0;
        }
        else
        {
            BreakPointSetCount = CurrentBreakPointSetCount;
        }
        return(true);
    }
    return(false);
}