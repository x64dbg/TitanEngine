#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.Threading.h"

MutexLocker::MutexLocker(const char* name)
{
    gMutex=CreateMutexA(0, false, name);
    bUnlocked=false;
    WaitForSingleObject(gMutex, INFINITE);
}

MutexLocker::~MutexLocker()
{
    if(!bUnlocked)
        ReleaseMutex(gMutex);
}

void MutexLocker::relock()
{
    if(bUnlocked)
    {
        bUnlocked=false;
        WaitForSingleObject(gMutex, INFINITE);
    }
}

void MutexLocker::unlock()
{
    ReleaseMutex(gMutex);
    bUnlocked=true;
}