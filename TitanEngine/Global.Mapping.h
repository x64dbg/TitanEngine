#ifndef _GLOBAL_MAPPING_H
#define _GLOBAL_MAPPING_H

bool MapFileEx(const char* szFileName, DWORD ReadOrWrite, LPHANDLE FileHandle, LPDWORD FileSize, LPHANDLE FileMap, LPVOID FileMapVA, DWORD SizeModifier);
bool MapFileExW(const wchar_t* szFileName, DWORD ReadOrWrite, LPHANDLE FileHandle, LPDWORD FileSize, LPHANDLE FileMap, LPVOID FileMapVA, DWORD SizeModifier);
void UnMapFileEx(HANDLE FileHandle, DWORD FileSize, HANDLE FileMap, ULONG_PTR FileMapVA);

#endif //_GLOBAL_MAPPING_H