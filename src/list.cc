/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Doubly Linked List
 * (C) 2013  Jung-Sang Ahn <jungsang.ahn@gmail.com>
 */

#include <stdio.h>
#include "list.h"

#ifdef _LIST_LOCK
    #define IFDEF_LOCK(...) __VA_ARGS__
#else
    #define IFDEF_LOCK(...)
#endif


#ifdef LIST_LOCK
void list_init(struct list *list)
{
    list->head = NULL;
    list->tail = NULL;
    IFDEF_LOCK( spin_init(&list->lock); );
}
#endif

void list_push_front(struct list *list, struct list_elem *e)
{
    IFDEF_LOCK( spin_lock(&list->lock); );
    if (list->head == NULL) {
        list->head = e;
        list->tail = e;
        e->next = e->prev = NULL;
    }else{
        list->head->prev = e;
        e->prev = NULL;
        e->next = list->head;
        list->head = e;
    }
    IFDEF_LOCK( spin_unlock(&list->lock); );
}

void list_push_back(struct list *list, struct list_elem *e)
{
    IFDEF_LOCK( spin_lock(&list->lock); );
    if (list->tail == NULL) {
        list->head = e;
        list->tail = e;
        e->next = e->prev = NULL;
    }else{
        list->tail->next = e;
        e->prev = list->tail;
        e->next = NULL;
        list->tail = e;
    }
    IFDEF_LOCK( spin_unlock(&list->lock); );
}

// insert E just before BEFORE
void list_insert_before(struct list *list, struct list_elem *before, struct list_elem *e)
{
    IFDEF_LOCK( spin_lock(&list->lock); );
    e->prev = before->prev;
    e->next = before;
    if (before->prev) before->prev->next = e;
    else list->head = e;
    before->prev = e;
    IFDEF_LOCK( spin_unlock(&list->lock); );
}

// insert E just after AFTER
// LCOV_EXCL_START
void list_insert_after(struct list *list, struct list_elem *after, struct list_elem *e)
{
    IFDEF_LOCK( spin_lock(&list->lock); );
    e->next = after->next;
    e->prev = after;
    if (after->next) after->next->prev = e;
    else list->tail = e;
    after->next = e;
    IFDEF_LOCK( spin_unlock(&list->lock); );
}
// LCOV_EXCL_STOP

struct list_elem *list_remove(struct list *list, struct list_elem *e)
{
    IFDEF_LOCK( spin_lock(&list->lock); );
    if (e) {
        // if not NULL
        if (e->next) e->next->prev = e->prev;
        if (e->prev) e->prev->next = e->next;

        if (list->head == e) list->head = e->next;
        if (list->tail == e) list->tail = e->prev;

        struct list_elem *next = e->next;

        IFDEF_LOCK( spin_unlock(&list->lock); );
        return next;
    }
    // NULL .. do nothing
    IFDEF_LOCK( spin_unlock(&list->lock); );
    return NULL;
}

struct list_elem *list_remove_reverse(struct list *list, struct list_elem *e)
{
    IFDEF_LOCK( spin_lock(&list->lock); );
    if (e) {
        // if not NULL
        if (e->next) e->next->prev = e->prev;
        if (e->prev) e->prev->next = e->next;

        if (list->head == e) list->head = e->next;
        if (list->tail == e) list->tail = e->prev;

        IFDEF_LOCK( spin_unlock(&list->lock); );
        return e->prev;
    }
    // NULL .. do nothing
    IFDEF_LOCK( spin_unlock(&list->lock); );
    return NULL;
}

struct list_elem *list_pop_front(struct list *list)
{
    IFDEF_LOCK( spin_lock(&list->lock); );
    struct list_elem *e = list->head;
    if (e) {
        // if not NULL
        if (e->next) e->next->prev = e->prev;
        if (e->prev) e->prev->next = e->next;

        if (list->head == e) list->head = e->next;
        if (list->tail == e) list->tail = e->prev;

        IFDEF_LOCK( spin_unlock(&list->lock); );
        return e;
    }
    // NULL .. do nothing
    IFDEF_LOCK( spin_unlock(&list->lock); );
    return NULL;
}

struct list_elem *list_pop_back(struct list *list)
{
    IFDEF_LOCK( spin_lock(&list->lock); );
    struct list_elem *e = list->tail;
    if (e) {
        // if not NULL
        if (e->next) e->next->prev = e->prev;
        if (e->prev) e->prev->next = e->next;

        if (list->head == e) list->head = e->next;
        if (list->tail == e) list->tail = e->prev;

        IFDEF_LOCK( spin_unlock(&list->lock); );
        return e;
    }
    // NULL .. do nothing
    IFDEF_LOCK( spin_unlock(&list->lock); );
    return NULL;
}

#ifdef LIST_LOCK
struct list_elem *list_begin(struct list *list)
{
    IFDEF_LOCK( spin_lock(&list->lock); );
    struct list_elem *e = list->head;
    IFDEF_LOCK( spin_unlock(&list->lock); );
    return e;
}

struct list_elem *list_end(struct list *list)
{
    IFDEF_LOCK( spin_lock(&list->lock); );
    struct list_elem *e = list->tail;
    IFDEF_LOCK( spin_unlock(&list->lock); );
    return e;
}
#endif
