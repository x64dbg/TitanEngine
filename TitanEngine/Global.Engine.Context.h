#ifndef _GLOBAL_ENGINE_CONTEXT_H
#define _GLOBAL_ENGINE_CONTEXT_H

#undef CONTEXT_XSTATE

#if defined(_M_X64)
#define CONTEXT_XSTATE                      (0x00100040)
#else
#define CONTEXT_XSTATE                      (0x00010040)
#endif

#define XSTATE_AVX                          (XSTATE_GSSE)
#define XSTATE_MASK_AVX                     (XSTATE_MASK_GSSE)

typedef DWORD64(WINAPI* PGETENABLEDXSTATEFEATURES)();
typedef BOOL (WINAPI* PINITIALIZECONTEXT)(PVOID Buffer, DWORD ContextFlags, PCONTEXT* Context, PDWORD ContextLength);
typedef BOOL (WINAPI* PGETXSTATEFEATURESMASK)(PCONTEXT Context, PDWORD64 FeatureMask);
typedef PVOID(WINAPI* LOCATEXSTATEFEATURE)(PCONTEXT Context, DWORD FeatureId, PDWORD Length);
typedef BOOL (WINAPI* SETXSTATEFEATURESMASK)(PCONTEXT Context, DWORD64 FeatureMask);

extern PGETENABLEDXSTATEFEATURES _GetEnabledXStateFeatures;
extern PINITIALIZECONTEXT _InitializeContext;
extern PGETXSTATEFEATURESMASK _GetXStateFeaturesMask;
extern LOCATEXSTATEFEATURE _LocateXStateFeature;
extern SETXSTATEFEATURESMASK _SetXStateFeaturesMask;

enum class EngineContextMode
{
    X86,
    X64,
};

// Determine the mode in which a thread is currently executing. A WoW64 thread
// can switch between 32-bit and 64-bit code, so this deliberately uses CS from
// the live thread context instead of the process image architecture.
EngineContextMode EngineGetThreadContextMode(HANDLE hThread);
EngineContextMode EngineGetCurrentContextMode();
SIZE_T EngineGetContextPointerSize(EngineContextMode mode);

// Thread context cache. While a debug event is being handled, every thread of the debuggee is
// frozen by the kernel until ContinueDebugEvent, so a context only changes when the debugger
// writes it. Begin/End bracket the handling of one event; any write invalidates the thread.
enum EngineContextCacheKind
{
    ContextCacheFull = 0, // CONTEXT (all flags but XSTATE)
    ContextCacheAvx = 1, // YmmRegisters of TITAN_ENGINE_CONTEXT_t
    ContextCacheAvx512 = 2, // TITAN_ENGINE_CONTEXT_AVX512_t
};

// ContextFlags of the ContextCacheFull entries
const DWORD EngineContextCacheFlags = CONTEXT_ALL | CONTEXT_FLOATING_POINT | CONTEXT_EXTENDED_REGISTERS;

void EngineContextCacheBegin();
void EngineContextCacheEnd();
bool EngineContextCacheActive();
void EngineContextCacheInvalidate(HANDLE hThread);
// On a miss, generation receives the value to pass to EngineContextCacheStore
bool EngineContextCacheLoad(HANDLE hThread, EngineContextCacheKind kind, void* data, size_t size, uint64_t & generation);
void EngineContextCacheStore(HANDLE hThread, EngineContextCacheKind kind, const void* data, size_t size, uint64_t generation);

// Handle of the thread of the current debug event for the duration of one engine call: the
// engine's own handle (from the CREATE_THREAD/CREATE_PROCESS event) while the debug loop thread
// handles the event, otherwise a newly opened handle that is closed on destruction
class EngineEventThread
{
public:
    explicit EngineEventThread(DWORD dwDesiredAccess);
    ~EngineEventThread();
    EngineEventThread(const EngineEventThread &) = delete;
    EngineEventThread & operator=(const EngineEventThread &) = delete;
    HANDLE get() const
    {
        return mHandle;
    }

private:
    HANDLE mHandle = NULL;
    bool mOwned = false;
};

bool _SetFullContextDataEx(HANDLE hActiveThread, TITAN_ENGINE_CONTEXT_t* titcontext, bool AVX_PRIORITY);
bool _GetFullContextDataEx(HANDLE hActiveThread, TITAN_ENGINE_CONTEXT_t* titcontext, bool avx);
bool InitXState(void);

#endif //_GLOBAL_ENGINE_CONTEXT_H