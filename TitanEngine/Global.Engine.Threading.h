#ifndef _GLOBAL_ENGINE_THREADING_H
#define _GLOBAL_ENGINE_THREADING_H

class MutexLocker
{
public:
    MutexLocker(const char* name);
    ~MutexLocker();
    void relock();
    void unlock();
private:
    HANDLE gMutex;
    bool bUnlocked;
};

#endif //_GLOBAL_ENGINE_THREADING_H