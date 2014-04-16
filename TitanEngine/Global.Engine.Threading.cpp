#include "stdafx.h"
#include "definitions.h"
#include "Global.Engine.Threading.h"

MutexLocker::MutexLocker(const char* name)
{
    int len=strlen(name);
    DynBuf newNameBuf(len+20);
    char* newName = (char*)newNameBuf.GetPtr();
    sprintf(newName, "%s%X", name, GetCurrentProcessId());
    gMutex=CreateMutexA(0, false, newName);
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