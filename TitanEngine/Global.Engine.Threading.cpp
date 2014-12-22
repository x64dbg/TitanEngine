#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.Threading.h"

static CRITICAL_SECTION locks[LockLast] = {};
static bool bInitDone = false;

static void CriticalSectionInitializeLocks()
{
    if(bInitDone)
        return;
    for(int i = 0; i < LockLast; i++)
        InitializeCriticalSection(&locks[i]);
    bInitDone = true;
}

void CriticalSectionDeleteLocks()
{
    if(!bInitDone)
        return;
    for(int i = 0; i < LockLast; i++)
    {
        EnterCriticalSection(&locks[i]);
        DeleteCriticalSection(&locks[i]);
    }
    bInitDone = false;
}

CriticalSectionLocker::CriticalSectionLocker(CriticalSectionLock lock)
{
    CriticalSectionInitializeLocks(); //initialize critical sections
    gLock = lock;

    EnterCriticalSection(&locks[gLock]);
    Locked = true;
}

CriticalSectionLocker::~CriticalSectionLocker()
{
    if(Locked)
        LeaveCriticalSection(&locks[gLock]);
}

void CriticalSectionLocker::unlock()
{
    Locked = false;
    LeaveCriticalSection(&locks[gLock]);
}

void CriticalSectionLocker::relock()
{
    EnterCriticalSection(&locks[gLock]);
    Locked = true;
}