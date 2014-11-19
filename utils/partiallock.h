/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Generic Partial Lock
 * see https://github.com/greensky00/partiallock
 */

#ifndef _JSAHN_PARITIAL_LOCK_H
#define _JSAHN_PARITIAL_LOCK_H

#include <stdint.h>
#include <stddef.h>

#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t plock_range_t;
typedef struct plock_node plock_entry_t; // opaque reference

struct plock_ops {
    void (*init_user)(void *lock);
    void (*lock_user)(void *lock);
    void (*unlock_user)(void *lock);
    void (*destroy_user)(void *lock);
    void (*init_internal)(void *lock);
    void (*lock_internal)(void *lock);
    void (*unlock_internal)(void *lock);
    void (*destroy_internal)(void *lock);
    int (*is_overlapped)(void *start1, void *len1, void *start2, void *len2, void *aux);
};

struct plock_config {
    struct plock_ops *ops;
    size_t sizeof_lock_user;
    size_t sizeof_lock_internal;
    size_t sizeof_range;
    void *aux;
};

struct plock {
    struct list active; // list of active locks
    struct list inactive; // list of inactive (freed) locks
    struct plock_ops *ops;
    size_t sizeof_lock_user;
    size_t sizeof_lock_internal;
    size_t sizeof_range;
    void *lock;
    void *aux;
};

#define PLOCK_RESULT_SUCCESS (0)
#define PLOCK_RESULT_INVALID_ARGS (-1)
#define PLOCK_RESULT_ALLOC_FAIL (-2)

int plock_init(struct plock *plock, struct plock_config *config);
plock_entry_t *plock_lock(struct plock *plock, void *start, void *len);
int plock_unlock(struct plock *plock, plock_entry_t *plock_entry);
int plock_destroy(struct plock *plock);

#ifdef __cplusplus
}
#endif

#endif

