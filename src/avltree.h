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

#ifndef _JSAHN_AVL_TREE_H
#define _JSAHN_AVL_TREE_H

#include "stddef.h"
#include "stdint.h"

struct avl_node {
    struct avl_node *parent, *left, *right;

#ifdef _AVL_SEPARATE_PARENT_BF
    int bf;
#endif
#ifdef _AVL_NEXT_POINTER
    struct avl_node *prev, *next;
#endif
};

struct avl_tree{
    struct avl_node *root;
    void *aux;
};

#ifndef _get_entry
#define _get_entry(ELEM, STRUCT, MEMBER)                              \
        ((STRUCT *) ((uint8_t *) (ELEM) - offsetof (STRUCT, MEMBER)))
#endif

#define avl_parent(node) \
        ((struct avl_node *)((unsigned long)(node)->parent & ~0x3))

#ifdef _AVL_SEPARATE_PARENT_BF
    #define avl_bf(node) ((node)->bf)
#else
    #define avl_bf(node) (((int)((unsigned long)(node)->parent & 0x3)) - 1)
#endif

// *a < *b : return neg
// *a == *b : return 0
// *a > *b : return pos
typedef int avl_cmp_func (struct avl_node *a, struct avl_node *b, void *aux);

void avl_init(struct avl_tree *tree, void *aux);
struct avl_node* avl_insert(struct avl_tree *tree,
                            struct avl_node *node,
                            avl_cmp_func *func);
struct avl_node* avl_search(struct avl_tree *tree,
                            struct avl_node *node,
                            avl_cmp_func *func);
struct avl_node* avl_search_greater(struct avl_tree *tree,
                            struct avl_node *node,
                            avl_cmp_func *func);
void avl_remove(struct avl_tree *tree,
                struct avl_node *node);
struct avl_node* avl_first(struct avl_tree *tree);
struct avl_node* avl_last(struct avl_tree *tree);
struct avl_node* avl_next(struct avl_node *node);
struct avl_node* avl_prev(struct avl_node *node);

#endif
