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

#ifndef _JSAHN_LIST_H
#define _JSAHN_LIST_H

#include <stdint.h>
#include <stddef.h>

//#define _LIST_LOCK
#ifdef _LIST_LOCK
    #include "arch.h"
#endif

struct list_elem {
    struct list_elem *prev;
    struct list_elem *next;
};

struct list {
    struct list_elem *head;
    struct list_elem *tail;
#ifdef _LIST_LOCK
    spin_t lock;
#endif
};

#ifndef _get_entry
#define _get_entry(ELEM, STRUCT, MEMBER) \
    ((STRUCT *) ((uint8_t *) (ELEM) - offsetof (STRUCT, MEMBER)))
#endif

void list_init(struct list *list);

void list_push_front(struct list *list, struct list_elem *e);
void list_push_back(struct list *list, struct list_elem *e);
void list_insert_before(struct list *list, struct list_elem *before, struct list_elem *e);
void list_insert_after(struct list *list, struct list_elem *after, struct list_elem *e);

struct list_elem *list_remove(struct list *list, struct list_elem *e);
struct list_elem *list_remove_reverse(struct list *list, struct list_elem *e);

struct list_elem *list_pop_front(struct list *list);
struct list_elem *list_pop_back(struct list *list);

struct list_elem *list_begin(struct list *list);
struct list_elem *list_end(struct list *list);
struct list_elem *list_next(struct list_elem *e);
struct list_elem *list_prev(struct list_elem *e);


#endif

