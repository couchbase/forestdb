/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2010 Couchbase, Inc
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include <stdio.h>
#include <assert.h>
#include "list.h"

#ifdef _LIST_LOCK
    #define IFDEF_LOCK(command...) command
#else
    #define IFDEF_LOCK(command...)
#endif


void list_init(struct list *list)
{
    list->head = NULL;
    list->tail = NULL;
    IFDEF_LOCK( list->lock = SPIN_INITIALIZER; );
}

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

struct list_elem *list_next(struct list_elem *e)
{
    return e->next;
}

struct list_elem *list_prev(struct list_elem *e)
{
    return e->prev;
}

