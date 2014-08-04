#ifndef Helper_h__
#define Helper_h__

#include <string>
#include <vector>

/*
Compares two strings
a : string 1
b : string 2
considercase : casesensitivity
*/
bool IsStrEqual(const char* const a, const char* const b, bool considercase = true);

/*
A basic dynamic buffer, exception free.
*/
class DynBuf
{
public:
    DynBuf(size_t sz = 0)
    {
        Allocate(sz);
    }
    typedef std::vector<char> DynBufVec;

    void* Allocate(size_t sz)
    {
        void* r = NULL;
        try
        {
            if(Size() < sz)
                mem.resize(sz);
            if(Size())
                r = GetPtr();
            if(r && sz)
                memset(r, 0, sz);
        }
        catch(...)
        {
        }

        return r;
    }
    void* GetPtr()
    {
        if(Size())
            return &mem.front(); //in c++11: .data()
        return NULL;
    }
    void Free()
    {
        mem.clear();
    }
    DynBufVec & GetVector()
    {
        return mem;
    }
    const DynBufVec & GetVector() const
    {
        return mem;
    }
    size_t Size() const
    {
        return mem.size();
    }


protected:
    char & operator[](std::size_t idx)
    {
        return mem[idx];
    };
    const char & operator[](std::size_t idx) const
    {
        return mem[idx];
    };

    DynBufVec mem;
};


//Unused malloc/free wrappers

/*
malloc wrapper
*/
void* MemAlloc(size_t sz);

/*
free wrapper
*/
void MemFree(void* mem);



#endif // Helper_h__

