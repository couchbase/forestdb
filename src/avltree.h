/*
Copyright (C) 2014 Jung-Sang Ahn <jungsang.ahn@gmail.com>
All rights reserved.

Last modification: Mar 5, 2014

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
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
