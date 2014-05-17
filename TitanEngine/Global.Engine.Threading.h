#ifndef _GLOBAL_ENGINE_THREADING_H
#define _GLOBAL_ENGINE_THREADING_H

enum CriticalSectionLock
{
    LockBreakPointBuffer,
    LockLast
};

void CriticalSectionInitializeLocks();
void CriticalSectionDeleteLocks();

class CriticalSectionLocker
{
public:
    CriticalSectionLocker(CriticalSectionLock lock);
    ~CriticalSectionLocker();
    void unlock();
    void relock();
    
private:
    LPCRITICAL_SECTION gCriticalSection;
};

#endif //_GLOBAL_ENGINE_THREADING_H