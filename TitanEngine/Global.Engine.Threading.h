#ifndef _GLOBAL_ENGINE_THREADING_H
#define _GLOBAL_ENGINE_THREADING_H

#define GetSTInTOPStackFromStatusWord(StatusWord) ((StatusWord & 0x3800) >> 11)
#define Getx87r0PositionInRegisterArea(STInTopStack) ((8 - STInTopStack) % 8)
#define Calculatex87registerPositionInRegisterArea(x87r0_position, index) (((x87r0_position + index) % 8))
#define GetRegisterAreaOf87register(register_area, x87r0_position, index) (((char *) register_area) + 10 * Calculatex87registerPositionInRegisterArea(x87r0_position, i) )
#define GetSTValueFromIndex(x87r0_position, index) ((x87r0_position + index) % 8)

enum CriticalSectionLock
{
    LockBreakPointBuffer,
    LockLast
};

void CriticalSectionDeleteLocks();

class CriticalSectionLocker
{
public:
    CriticalSectionLocker(CriticalSectionLock lock);
    ~CriticalSectionLocker();
    void unlock();
    void relock();

private:
    CriticalSectionLock gLock;
};

#endif //_GLOBAL_ENGINE_THREADING_H