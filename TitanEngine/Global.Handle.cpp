#include "stdafx.h"
#include "definitions.h"
#include "Global.Handle.h"

// Global.Handle.functions:
bool EngineCloseHandle(HANDLE myHandle)
{
    DWORD HandleFlags;
    if(GetHandleInformation(myHandle, &HandleFlags) && (HandleFlags & HANDLE_FLAG_PROTECT_FROM_CLOSE) != HANDLE_FLAG_PROTECT_FROM_CLOSE)
        return !!CloseHandle(myHandle);
    return false;
}