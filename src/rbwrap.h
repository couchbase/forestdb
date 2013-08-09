/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#ifndef _RBTREE_WRAP
#define _RBTREE_WRAP

#ifdef _KERNEL_MODE
    #include <linux/rbtree.h>
    #include <linux/types.h>
#else
    #include "rbtree.h"
    #include <stdbool.h>
    #include <stdint.h>
#endif

#ifndef _get_entry
#define _get_entry(ELEM, STRUCT, MEMBER)                              \
        ((STRUCT *) ((uint8_t *) (ELEM) - offsetof (STRUCT, MEMBER)))
#endif


// *a < *b : return neg
// *a == *b : return 0
// *a > *b : return pos
typedef int rbwrap_cmp_func (struct rb_node *a, struct rb_node *b, void *aux);

void rbwrap_init(struct rb_root *root, void *aux);
struct rb_node * rbwrap_insert(struct rb_root *root, struct rb_node *node, rbwrap_cmp_func *func);
struct rb_node * rbwrap_search(struct rb_root *root, struct rb_node *node, rbwrap_cmp_func *func);

#endif
