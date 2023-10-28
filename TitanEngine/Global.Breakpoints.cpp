#include "stdafx.h"
#include "definitions.h"
#include "Global.Breakpoints.h"

std::vector<BreakPointDetail> BreakPointBuffer;
std::unordered_map<ULONG_PTR, MemoryBreakpointPageDetail> MemoryBreakpointPages;

ULONG_PTR dr7uint(DR7* dr7)
{
    ULONG_PTR ret = 0;
    if(BITGET(dr7->HWBP_MODE[0], 0))
        BITSET(ret, 0);
    if(BITGET(dr7->HWBP_MODE[0], 1))
        BITSET(ret, 1);
    if(BITGET(dr7->HWBP_MODE[1], 0))
        BITSET(ret, 2);
    if(BITGET(dr7->HWBP_MODE[1], 1))
        BITSET(ret, 3);
    if(BITGET(dr7->HWBP_MODE[2], 0))
        BITSET(ret, 4);
    if(BITGET(dr7->HWBP_MODE[2], 1))
        BITSET(ret, 5);
    if(BITGET(dr7->HWBP_MODE[3], 0))
        BITSET(ret, 6);
    if(BITGET(dr7->HWBP_MODE[3], 1))
        BITSET(ret, 7);
    if(BITGET(dr7->HWBP_TYPE[0], 0))
        BITSET(ret, 16);
    if(BITGET(dr7->HWBP_TYPE[0], 1))
        BITSET(ret, 17);
    if(BITGET(dr7->HWBP_SIZE[0], 0))
        BITSET(ret, 18);
    if(BITGET(dr7->HWBP_SIZE[0], 1))
        BITSET(ret, 19);
    if(BITGET(dr7->HWBP_TYPE[1], 0))
        BITSET(ret, 20);
    if(BITGET(dr7->HWBP_TYPE[1], 1))
        BITSET(ret, 21);
    if(BITGET(dr7->HWBP_SIZE[1], 0))
        BITSET(ret, 22);
    if(BITGET(dr7->HWBP_SIZE[1], 1))
        BITSET(ret, 23);
    if(BITGET(dr7->HWBP_TYPE[2], 0))
        BITSET(ret, 24);
    if(BITGET(dr7->HWBP_TYPE[2], 1))
        BITSET(ret, 25);
    if(BITGET(dr7->HWBP_SIZE[2], 0))
        BITSET(ret, 26);
    if(BITGET(dr7->HWBP_SIZE[2], 1))
        BITSET(ret, 27);
    if(BITGET(dr7->HWBP_TYPE[3], 0))
        BITSET(ret, 28);
    if(BITGET(dr7->HWBP_TYPE[3], 1))
        BITSET(ret, 29);
    if(BITGET(dr7->HWBP_SIZE[3], 0))
        BITSET(ret, 30);
    if(BITGET(dr7->HWBP_SIZE[3], 1))
        BITSET(ret, 31);
    return ret;
}

void uintdr7(ULONG_PTR dr7, DR7* ret)
{
    memset(ret, 0, sizeof(DR7));
    if(BITGET(dr7, 0))
        BITSET(ret->HWBP_MODE[0], 0);
    if(BITGET(dr7, 1))
        BITSET(ret->HWBP_MODE[0], 1);
    if(BITGET(dr7, 2))
        BITSET(ret->HWBP_MODE[1], 0);
    if(BITGET(dr7, 3))
        BITSET(ret->HWBP_MODE[1], 1);
    if(BITGET(dr7, 4))
        BITSET(ret->HWBP_MODE[2], 0);
    if(BITGET(dr7, 5))
        BITSET(ret->HWBP_MODE[2], 1);
    if(BITGET(dr7, 6))
        BITSET(ret->HWBP_MODE[3], 0);
    if(BITGET(dr7, 7))
        BITSET(ret->HWBP_MODE[3], 1);
    if(BITGET(dr7, 16))
        BITSET(ret->HWBP_TYPE[0], 0);
    if(BITGET(dr7, 17))
        BITSET(ret->HWBP_TYPE[0], 1);
    if(BITGET(dr7, 18))
        BITSET(ret->HWBP_SIZE[0], 0);
    if(BITGET(dr7, 19))
        BITSET(ret->HWBP_SIZE[0], 1);
    if(BITGET(dr7, 20))
        BITSET(ret->HWBP_TYPE[1], 0);
    if(BITGET(dr7, 21))
        BITSET(ret->HWBP_TYPE[1], 1);
    if(BITGET(dr7, 22))
        BITSET(ret->HWBP_SIZE[1], 0);
    if(BITGET(dr7, 23))
        BITSET(ret->HWBP_SIZE[1], 1);
    if(BITGET(dr7, 24))
        BITSET(ret->HWBP_TYPE[2], 0);
    if(BITGET(dr7, 25))
        BITSET(ret->HWBP_TYPE[2], 1);
    if(BITGET(dr7, 26))
        BITSET(ret->HWBP_SIZE[2], 0);
    if(BITGET(dr7, 27))
        BITSET(ret->HWBP_SIZE[2], 1);
    if(BITGET(dr7, 28))
        BITSET(ret->HWBP_TYPE[3], 0);
    if(BITGET(dr7, 29))
        BITSET(ret->HWBP_TYPE[3], 1);
    if(BITGET(dr7, 30))
        BITSET(ret->HWBP_SIZE[3], 0);
    if(BITGET(dr7, 31))
        BITSET(ret->HWBP_SIZE[3], 1);
}

void BreakPointPostReadFilter(ULONG_PTR lpBaseAddress, unsigned char* lpBuffer, SIZE_T nSize)
{
    CriticalSectionLocker lock(LockBreakPointBuffer);
    ULONG_PTR start = lpBaseAddress;
    ULONG_PTR end = start + nSize;
    int bpcount = (int)BreakPointBuffer.size();
    for(int i = 0; i < bpcount; i++)
    {
        BreakPointDetail* curBp = &BreakPointBuffer.at(i);
        //check if the breakpoint is one we should be concerned about
        if(curBp->BreakPointActive != UE_BPXACTIVE || (curBp->BreakPointType != UE_BREAKPOINT && curBp->BreakPointType != UE_SINGLESHOOT))
            continue;
        ULONG_PTR cur_addr = curBp->BreakPointAddress;
        for(SIZE_T j = 0; j < curBp->BreakPointSize; j++)
        {
            if(cur_addr + j >= start && cur_addr + j < end) //breakpoint is in range
            {
                ULONG_PTR index = cur_addr + j - start; //calculate where to write in the buffer
                memcpy(lpBuffer + index, &curBp->OriginalByte[j], sizeof(char));
            }
        }
    }
}

void BreakPointPreWriteFilter(ULONG_PTR lpBaseAddress, SIZE_T nSize)
{
    ULONG_PTR start = lpBaseAddress;
    ULONG_PTR end = start + nSize;
    int bpcount = (int)BreakPointBuffer.size();
    for(int i = 0; i < bpcount; i++)
    {
        BreakPointDetail* curBp = &BreakPointBuffer.at(i);
        //check if the breakpoint is one we should be concerned about
        if(curBp->BreakPointActive != UE_BPXACTIVE || (curBp->BreakPointType != UE_BREAKPOINT && curBp->BreakPointType != UE_SINGLESHOOT))
            continue;
        ULONG_PTR cur_addr = curBp->BreakPointAddress;
        for(SIZE_T j = 0; j < curBp->BreakPointSize; j++)
        {
            if(cur_addr + j >= start && cur_addr + j < end) //breakpoint byte is in range
            {
                DisableBPX(cur_addr);
                curBp->BreakPointActive = UE_BPXACTIVE; //little hack
                break;
            }
        }
    }
}

void BreakPointPostWriteFilter(ULONG_PTR lpBaseAddress, SIZE_T nSize)
{
    ULONG_PTR start = lpBaseAddress;
    ULONG_PTR end = start + nSize;
    int bpcount = (int)BreakPointBuffer.size();
    for(int i = 0; i < bpcount; i++)
    {
        BreakPointDetail* curBp = &BreakPointBuffer.at(i);
        //check if the breakpoint is one we should be concerned about
        if(curBp->BreakPointActive != UE_BPXACTIVE || (curBp->BreakPointType != UE_BREAKPOINT && curBp->BreakPointType != UE_SINGLESHOOT))
            continue;
        ULONG_PTR cur_addr = curBp->BreakPointAddress;
        for(SIZE_T j = 0; j < curBp->BreakPointSize; j++)
        {
            if(cur_addr + j >= start && cur_addr + j < end) //breakpoint byte is in range
            {
                curBp->BreakPointActive = UE_BPXINACTIVE; //little hack
                EnableBPX(cur_addr); //needs a cleaner solution
                break;
            }
        }
    }
}

bool IsDepEnabled(bool* outPermanent)
{
    bool isEnabled = false;
    bool isPermanent = false;

#ifndef _WIN64
    ULONG depFlags = 0;
    NTSTATUS status = NtQueryInformationProcess(dbgProcessInformation.hProcess, ProcessExecuteFlags, &depFlags, sizeof(depFlags), nullptr);
    if(status == STATUS_SUCCESS)
    {
        isEnabled = (depFlags & 0x1) != 0; // 0x1 is MEM_EXECUTE_OPTION_DISABLE
        isPermanent = (depFlags & 0x8) != 0; // 0x8 is MEM_EXECUTE_OPTION_PERMANENT
    }
#else
    isEnabled = true;
    isPermanent = true;
#endif //_WIN64

    if(outPermanent != nullptr)
        *outPermanent = isPermanent;

    return isEnabled;
}

DWORD GetPageProtectionForMemoryBreakpoint(const MemoryBreakpointPageDetail & page)
{
    // Memory Protection Constants: https://msdn.microsoft.com/en-us/library/windows/desktop/aa366786(v=vs.85).aspx

    // If DEP is disabled or enabled but not permanent (i.e. may be disabled unpredictably in the future),
    //  we cannot rely on "PAGE_EXECUTE_*" protection options for BPs on execution
    //  and should use PAGE_GUARD (or PAGE_NOACCESS) instead, a much slower approach:
    bool isDepPermanent = false;
    bool isDepPermanentlyEnabled = IsDepEnabled(&isDepPermanent) && isDepPermanent;

    // for ACCESS and READ breakpoints, apply the "lowest" protection: GUARD_PAGE or PAGE_NOACCESS
    if(page.accessBps > 0 || page.readBps > 0 || (page.executeBps > 0 && !isDepPermanentlyEnabled))
    {
        // GUARD_PAGE is incompatible with PAGE_NOACCESS
        if((page.origProtect & 0xFF) == PAGE_NOACCESS || engineMembpAlt)
            return (page.origProtect & ~0x7FF) | PAGE_NOACCESS;
        else
            // erase PAGE_NOCACHE and PAGE_WRITECOMBINE (cannot be used with the PAGE_GUARD)
            return (page.origProtect & ~0x700) | PAGE_GUARD;
    }

    int newProtect = page.origProtect & ~PAGE_GUARD; // erase guard page, just in case
    if(page.executeBps > 0 && isDepPermanentlyEnabled)
    {
        // Remove execute access e.g. PAGE_EXECUTE_READWRITE => PAGE_READWRITE
        DWORD dwBase = newProtect & 0xFF;
        DWORD dwHigh = newProtect & 0xFFFFFF00;
        switch(dwBase)
        {
        case PAGE_EXECUTE:
            newProtect = dwHigh | PAGE_READONLY;
            break;
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            newProtect = dwHigh | (dwBase >> 4);
            break;
        }
    }

    if(page.writeBps > 0)
    {
        // Remove write access e.g. PAGE_EXECUTE_READWRITE => PAGE_EXECUTE
        DWORD dwBase = newProtect & 0xFF;
        switch(dwBase)
        {
        case PAGE_READWRITE:
        case PAGE_EXECUTE_READWRITE:
            newProtect = (newProtect & 0xFFFFFF00) | (dwBase >> 1);
            break;
        }
    }

    return newProtect;
}

bool IsMemoryAccessAllowed(DWORD memProtect, ULONG_PTR accessType /*0 (READ), 1 (WRITE), or 8 (EXECUTE)*/)
{
    const bool isRead = accessType == 0;
    const bool isWrite = accessType == 1;
    const bool isExecute = accessType == 8;

    switch(memProtect & 0xFF)
    {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
        return isRead || isExecute;
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    case PAGE_READONLY:
        return isRead || (isExecute && !IsDepEnabled());
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
        return isRead || isWrite || (isExecute && !IsDepEnabled());
    default:
    case PAGE_NOACCESS:
        return false;
    }
}
