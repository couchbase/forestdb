/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Generic Partial Lock
 * see https://github.com/greensky00/partiallock
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "partiallock.h"

struct plock_node {
    void *lock;
    void *start;
    void *len;
    volatile uint32_t wcount; // waiting count
    struct list_elem le;
};

int plock_init(struct plock *plock, struct plock_config *config)
{
    if (!plock || !config) {
        return PLOCK_RESULT_INVALID_ARGS;
    }

    plock->ops = (struct plock_ops *)malloc(sizeof(struct plock_ops));
    if (!plock->ops) {
        return PLOCK_RESULT_ALLOC_FAIL;
    }
    *plock->ops = *(config->ops);

    // allocate and init lock
    plock->sizeof_lock_user = config->sizeof_lock_user;
    plock->sizeof_lock_internal = config->sizeof_lock_internal;
    plock->sizeof_range = config->sizeof_range;
    plock->aux = config->aux;
    plock->lock = (void *)malloc(plock->sizeof_lock_internal);
    plock->ops->init_internal(plock->lock);

    // init list and tree
    list_init(&plock->active);
    list_init(&plock->inactive);

    return PLOCK_RESULT_SUCCESS;
}

plock_entry_t *plock_lock(struct plock *plock, void *start, void *len)
{
    struct list_elem *le = NULL;
    struct plock_node *node = NULL;

    if (!plock || !start || !len) {
        return NULL;
    }

    // grab plock's lock
    plock->ops->lock_internal(plock->lock);

    // find existing overlapped lock
    le = list_begin(&plock->active);
    while (le) {
        node = _get_entry(le, struct plock_node, le);
        if (plock->ops->is_overlapped(node->start, node->len,
                                      start, len, plock->aux)) {
            // overlapped
            // increase waiting count
            node->wcount++;
            // release plock's lock
            plock->ops->unlock_internal(plock->lock);

            // grab node's lock
            plock->ops->lock_user(node->lock);
            // got control .. that means the owner released the lock
            // grab plock's lock
            plock->ops->lock_internal(plock->lock);
            // decrease waiting count
            le = list_next(&node->le);
            node->wcount--;
            if (node->wcount == 0) {
                // no other thread refers this node
                // move from active to inactive
                list_remove(&plock->active, &node->le);
                list_push_front(&plock->inactive, &node->le);
            }
            // release node's lock
            plock->ops->unlock_user(node->lock);
        } else {
            le = list_next(le);
        }
    }

    // get a free lock
    le = list_pop_front(&plock->inactive);
    if (le == NULL) {
        // no free lock .. create one
        node = (struct plock_node *)malloc(sizeof(struct plock_node));
        if (!node) {
            plock->ops->unlock_internal(plock->lock);
            return NULL;
        }
        node->lock = (void *)malloc(plock->sizeof_lock_user);
        plock->ops->init_user(node->lock);
        node->start = (void *)malloc(plock->sizeof_range);
        node->len = (void *)malloc(plock->sizeof_range);
        if (!node->lock || !node->start || !node->len) {
            free(node);
            plock->ops->unlock_internal(plock->lock);
            return NULL;
        }
    } else {
        node = _get_entry(le, struct plock_node ,le);
    }
    node->wcount = 0;

    // copy start & len value
    memcpy(node->start, start, plock->sizeof_range);
    memcpy(node->len, len, plock->sizeof_range);
    // insert into active list
    list_push_back(&plock->active, &node->le);

    // grab node's lock & release plock's lock
    plock->ops->lock_user(node->lock);
    plock->ops->unlock_internal(plock->lock);

    return node;
}

int plock_unlock(struct plock *plock, plock_entry_t *plock_entry)
{
    struct plock_node *node = plock_entry;

    if (!plock || !plock_entry) {
        return PLOCK_RESULT_INVALID_ARGS;
    }

    // grab plock's lock
    plock->ops->lock_internal(plock->lock);

    if (node->wcount == 0) {
        // no other thread refers this node
        // move from active to inactive
        list_remove(&plock->active, &node->le);
        list_push_front(&plock->inactive, &node->le);
    }
    plock->ops->unlock_user(node->lock);

    // release plock's lock
    plock->ops->unlock_internal(plock->lock);

    return PLOCK_RESULT_SUCCESS;
}

int plock_destroy(struct plock *plock)
{
    struct list_elem *le;
    struct plock_node *node;

    if (!plock) {
        return PLOCK_RESULT_INVALID_ARGS;
    }

    plock->ops->destroy_internal(plock->lock);

    // free all active locks
    le = list_begin(&plock->active);
    while(le) {
        node = _get_entry(le, struct plock_node, le);
        le = list_next(le);

        // unlock and destroy
        plock->ops->unlock_user(node->lock);
        plock->ops->destroy_user(node->lock);
        free(node->start);
        free(node->len);
        free(node->lock);
        free(node);
    }

    // free all inactive locks
    le = list_begin(&plock->inactive);
    while(le) {
        node = _get_entry(le, struct plock_node, le);
        le = list_next(le);

        // destroy
        plock->ops->destroy_user(node->lock);
        free(node->start);
        free(node->len);
        free(node->lock);
        free(node);
    }

    // free plock
    free(plock->lock);
    free(plock->ops);

    return PLOCK_RESULT_SUCCESS;
}

