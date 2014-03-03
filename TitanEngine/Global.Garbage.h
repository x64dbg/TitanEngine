#ifndef _GLOBAL_GARBAGE_H
#define _GLOBAL_GARBAGE_H

extern wchar_t engineSzEngineGarbageFolder[MAX_PATH];

// Global.Garbage.functions:
bool CreateGarbageItem(void* outGargabeItem, int MaxGargabeStringSize);
bool RemoveGarbageItem(wchar_t* szGarbageItem, bool RemoveFolder);
bool FillGarbageItem(wchar_t* szGarbageItem, wchar_t* szFileName, void* outGargabeItem, int MaxGargabeStringSize);
void EmptyGarbage();

#endif //_GLOBAL_GARBAGE_H