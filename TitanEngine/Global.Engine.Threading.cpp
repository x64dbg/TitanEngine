#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.Threading.h"

CRITICAL_SECTION CriticalSectionLocker::locks[LockLast] = {};
bool CriticalSectionLocker::bInitDone = false;

void CriticalSectionLocker::Initialize()
{
    if(bInitDone)
        return;
    for(int i = 0; i < LockLast; i++)
        InitializeCriticalSection(&locks[i]);
    bInitDone = true;
}

void CriticalSectionLocker::Deinitialize()
{
    if(!bInitDone)
        return;
    for(int i = 0; i < LockLast; i++)
    {
        EnterCriticalSection(&locks[i]); //obtain ownership
        DeleteCriticalSection(&locks[i]);
    }
    bInitDone = false;
}

CriticalSectionLocker::CriticalSectionLocker(CriticalSectionLock lock)
{
    Initialize(); //initialize critical sections
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