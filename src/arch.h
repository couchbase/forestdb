#ifndef _JSAHN_ARCH_H
#define _JSAHN_ARCH_H


#ifdef __APPLE__
    #define INLINE extern inline

    #define _F64 "lld"
    #define _FSEC "ld"
    #define _FUSEC "d"

    #define _ARCH_O_DIRECT (0x0)

    #ifndef spin_t
    // spinlock
    #include <libkern/OSAtomic.h>
    #define spin_t OSSpinLock
    #define spin_lock(arg) OSSpinLockLock(arg)
    #define spin_unlock(arg) OSSpinLockUnlock(arg)
    #define SPIN_INITIALIZER 0
    #endif
    
#elif __linux
    #define INLINE __inline

    #define _F64 "ld"
    #define _FSEC "ld"
    #define _FUSEC "ld"

    #define _ARCH_O_DIRECT (O_DIRECT)

    #ifndef spin_t
    // spinlock
    #include <pthread.h>
    #define spin_t pthread_spinlock_t
    #define spin_lock(arg) pthread_spin_lock(arg)
    #define spin_unlock(arg) pthread_spin_unlock(arg)
    #define SPIN_INITIALIZER 1
    #endif
    
#else
    #define INLINE make_error
#endif


#endif
