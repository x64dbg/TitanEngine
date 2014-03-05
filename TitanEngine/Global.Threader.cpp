#include "stdafx.h"
#include "definitions.h"
#include "Global.Threader.h"

std::vector<THREAD_ITEM_DATA> hListThread;

void ClearThreadList()
{
    std::vector<THREAD_ITEM_DATA>().swap(hListThread);
}
