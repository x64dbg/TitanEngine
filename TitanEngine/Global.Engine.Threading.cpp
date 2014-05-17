#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.Threading.h"

static CRITICAL_SECTION locks[LockLast];

void CriticalSectionInitializeLocks()
{
    for(int i=0; i<LockLast; i++)
        InitializeCriticalSection(&locks[i]);
}

void CriticalSectionDeleteLocks()
{
    for(int i=0; i<LockLast; i++)
        DeleteCriticalSection(&locks[i]);
}

CriticalSectionLocker::CriticalSectionLocker(CriticalSectionLock lock)
{
    gCriticalSection=&locks[lock];
    EnterCriticalSection(gCriticalSection);
}

CriticalSectionLocker::~CriticalSectionLocker()
{
    LeaveCriticalSection(gCriticalSection);
}

void CriticalSectionLocker::unlock()
{
    LeaveCriticalSection(gCriticalSection);
}

void CriticalSectionLocker::relock()
{
    EnterCriticalSection(gCriticalSection);
}