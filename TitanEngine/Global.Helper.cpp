#include "stdafx.h"
#include "Global.Helper.h"



bool IsStrEqual(const char* const a, const char* const b, bool considercase/*=true*/)
{
    const int stringlen = (int)std::strlen(a);
    if(stringlen != std::strlen(b))
        return false; //cheap

    if(considercase)
    {
        //plain old strcmp
        return std::strcmp(a, b) == 0;
    }
    else
    {
        for(int i = 0; i < stringlen; i++)
        {
            if(tolower(a[i]) != tolower(b[i]))
                return false;
        }

        return true;
    }
}

void* MemAlloc(size_t sz)
{
    void* r = malloc(sz);
    if(r)
        memset(r, 0, sz);
    return r;
}

void MemFree(void* mem)
{
    free(mem);
}
