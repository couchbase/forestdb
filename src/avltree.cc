/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * AVL Tree
 * (C) 2014  Jung-Sang Ahn <jungsang.ahn@gmail.com>
 * see https://github.com/greensky00/avltree
 */

#ifndef INLINE
    #ifdef __APPLE__
        #define INLINE extern inline
    #elif __linux__
        #define INLINE __inline
    #else
        #define INLINE
    #endif
#endif

#include "avltree.h"

#define max(a,b)    (((a) > (b)) ? (a) : (b))

INLINE int _abs(int n) {
    int mask = n >> ((sizeof(int)*8) -1);
    return (mask + n)^mask;
}

INLINE void avl_set_parent(struct avl_node *node, struct avl_node *parent)
{
    node->parent = (struct avl_node *)(
        (uint64_t)parent | ((uint64_t)node->parent & 0x3));
}

#ifdef __AVL_DEBUG
#include <stdio.h>
#include <assert.h>
#include "avltree_debug.h"
#else
#define __AVL_DEBUG_BF_CHECK(bf)
#define __AVL_DEBUG_LL(p, c, pb, cb)
#define __AVL_DEBUG_RR(p, c, pb, cb)
#define __AVL_DEBUG_BAL_BEGIN(node, bf, height_diff)
#define __AVL_DEBUG_BAL_END(node)
#define __AVL_DEBUG_INSERT(node)
#define __AVL_DEBUG_REMOVE(node)
#define __AVL_DEBUG_DISPLAY(tree)
#endif

INLINE void avl_set_bf(struct avl_node *node, int bf)
{
    __AVL_DEBUG_BF_CHECK(bf);

#ifdef _AVL_SEPARATE_PARENT_BF
    node->bf = bf;
#else
    node->parent = (struct avl_node *)(
        (uint64_t)avl_parent(node) | (uint64_t)(bf+1));
#endif
}

INLINE struct avl_node* _rotate_LL(struct avl_node *parent,
                                   int parent_bf,
                                   int *child_bf,
                                   int *height_delta)
// MUST ensure that parent_bf <= 0
{
    int p_right, c_left, c_right;
    struct avl_node *child = parent->left;

    __AVL_DEBUG_LL(parent, child, parent_bf, *child_bf);

    c_left = (child->left)?(1):(0);
    c_right = (child->right)?(1):(0);
    if (*child_bf < 0) {
        // child->left > child->right
        c_left = c_right - (*child_bf);
        p_right = c_left + 1 + parent_bf;
        if (height_delta)
            *height_delta = max(c_left, max(c_right, p_right)+1) - (c_left + 1);

    } else {
        // child->left <= child->right
        c_right = c_left + (*child_bf);
        p_right = c_right + 1 + parent_bf;
        if (height_delta)
            *height_delta = max(c_left, max(c_right, p_right)+1) - (c_right + 1);
    }
    *child_bf = (max(c_right, p_right) + 1) - c_left;
    avl_set_bf(parent, p_right - c_right);

    parent->left = child->right;
    if (child->right)
        avl_set_parent(child->right, parent);
    child->right = parent;
    avl_set_parent(child, avl_parent(parent));
    avl_set_parent(parent, child);

    return child;
}

INLINE struct avl_node* _rotate_RR(struct avl_node *parent,
                                   int parent_bf,
                                   int *child_bf,
                                   int *height_delta)
// MUST ensure that parent_bf >= 0
{
    int p_left, c_left, c_right;
    struct avl_node *child = parent->right;

    __AVL_DEBUG_RR(parent, child, parent_bf, *child_bf);

    c_left = (child->left)?(1):(0);
    c_right = (child->right)?(1):(0);
    if (*child_bf < 0) {
        // child->left > child->right
        c_left = c_right - (*child_bf);
        p_left = c_left + 1 - parent_bf;
        if (height_delta)
            *height_delta = max(c_right, max(c_left, p_left)+1) - (c_left + 1);

    } else {
        // child->left <= child->right
        c_right = c_left + (*child_bf);
        p_left = c_right + 1 - parent_bf;
        if (height_delta)
            *height_delta = max(c_right, max(c_left, p_left)+1) - (c_right + 1);

    }
    *child_bf = c_right - (max(c_left, p_left) + 1);
    avl_set_bf(parent, c_left - p_left);

    parent->right = child->left;
    if (child->left)
        avl_set_parent(child->left, parent);
    child->left = parent;
    avl_set_parent(child, avl_parent(parent));
    avl_set_parent(parent, child);

    return child;
}

INLINE struct avl_node* _rotate_LR(struct avl_node *parent, int parent_bf)
{
    int child_bf, height_delta = 0;
    struct avl_node *child = parent->left;
    struct avl_node *ret;

    if (child->right) {
        child_bf = avl_bf(child->right);
        parent->left = _rotate_RR(child, avl_bf(child), &child_bf, &height_delta);
    } else {
        child_bf = avl_bf(child);
    }

    ret = _rotate_LL(parent, parent_bf-height_delta, &child_bf, NULL);
    avl_set_bf(ret, child_bf);
    return ret;
}

INLINE struct avl_node* _rotate_RL(struct avl_node *parent, int parent_bf)
{
    int child_bf, height_delta = 0;
    struct avl_node *child = parent->right;
    struct avl_node *ret;

    if (child->left) {
        child_bf = avl_bf(child->left);
        parent->right = _rotate_LL(child, avl_bf(child), &child_bf, &height_delta);
    } else {
        child_bf = avl_bf(child);
    }

    ret = _rotate_RR(parent, parent_bf+height_delta, &child_bf, NULL);
    avl_set_bf(ret, child_bf);
    return ret;
}

#define _get_balance(node) ((node)?(avl_bf(node)):(0))

static struct avl_node* _balance_tree(struct avl_node *node, int bf)
{
    int child_bf;
    int height_diff= _get_balance(node) + bf;

    if (node) {
        __AVL_DEBUG_BAL_BEGIN(node, bf, height_diff);

        if(height_diff < -1 && node->left) {
            // balance left sub tree
            if(_get_balance(node->left) <= 0) {
                child_bf = avl_bf(node->left);
                node = _rotate_LL(node, height_diff, &child_bf, NULL);
                avl_set_bf(node, child_bf);
            } else {
                node = _rotate_LR(node, height_diff);
            }
        } else if(height_diff > 1 && node->right) {
            // balance right sub tree
            if(_get_balance(node->right) >= 0) {
                child_bf = avl_bf(node->right);
                node = _rotate_RR(node, height_diff, &child_bf, NULL);
                avl_set_bf(node, child_bf);
            } else {
                node = _rotate_RL(node, height_diff);
            }
        } else {
            avl_set_bf(node, avl_bf(node) + bf);
        }

        __AVL_DEBUG_BAL_END(node);
    }

    return node;
}

struct avl_node* avl_first(struct avl_tree *tree)
{
    struct avl_node *p = NULL;
    struct avl_node *node = tree->root;

    while(node) {
        p = node;
        node = node->left;
    }
    return p;
}

struct avl_node* avl_last(struct avl_tree *tree)
{
    struct avl_node *p = NULL;
    struct avl_node *node = tree->root;

    while(node) {
        p = node;
        node = node->right;
    }
    return p;
}

struct avl_node* avl_next(struct avl_node *node)
{
    if (node == NULL) return NULL;

#ifdef _AVL_NEXT_POINTER
    return node->next;
#else

    struct avl_node *p;

    // smallest value of right subtree
    if (node->right) {
        p = node;
        node = node->right;
        while (node) {
            p = node;
            node = node->left;
        }
        return p;
    }

    // node does not have right child
    if (avl_parent(node)) {
        // find first parent that has right child
        p = node;
        node = avl_parent(node);
        while(node) {
            if (node->left == p) {
                return node;
            }
            p = node;
            node = avl_parent(node);
        }
    }
#endif
    return NULL;
}

struct avl_node* avl_prev(struct avl_node *node)
{
    if (node == NULL) return NULL;

#ifdef _AVL_NEXT_POINTER
    return node->prev;
#else

    struct avl_node *p;

    // largest value of left subtree
    if (node->left) {
        p = node;
        node = node->left;
        while (node) {
            p = node;
            node = node->right;
        }
        return p;
    }

    // node does not have left child
    if (avl_parent(node)) {
        // find first parent that has left child
        p = node;
        node = avl_parent(node);
        while(node) {
            if (node->right == p) {
                return node;
            }
            p = node;
            node = avl_parent(node);
        }
    }
#endif
    return NULL;
}

struct avl_node* avl_search(struct avl_tree *tree,
                            struct avl_node *node,
                            avl_cmp_func *func)
// exact match
{
    struct avl_node *p = tree->root;
    int cmp;

    while(p)
    {
        cmp = func(p, node, tree->aux);
        if (cmp > 0) {
            p = p->left;
        }else if (cmp < 0){
            p = p->right;
        }else {
            // search success
            return p;
        }
    }
    // search fail
    return NULL;
}

struct avl_node* avl_search_greater(struct avl_tree *tree,
                                    struct avl_node *node,
                                    avl_cmp_func *func)
// if an exact match does not exist,
// return smallest node greater than NODE
{
    struct avl_node *p = tree->root;
    struct avl_node *pp = NULL;
    int cmp;

    while(p)
    {
        cmp = func(p, node, tree->aux);
        pp = p;

        if (cmp > 0) {
            p = p->left;
        }else if (cmp < 0){
            p = p->right;
        }else {
            // search success
            return p;
        }
    }

    if (!pp) {
        return pp;
    }

    cmp = func(pp, node, tree->aux);
    if (cmp > 0) {
        return pp;
    }else{
        return avl_next(pp);
    }
}

struct avl_node* avl_search_smaller(struct avl_tree *tree,
                                    struct avl_node *node,
                                    avl_cmp_func *func)
// if an exact match does not exist,
// return greatest node smaller than NODE
{
    struct avl_node *p = tree->root;
    struct avl_node *pp = NULL;
    int cmp;

    while(p)
    {
        cmp = func(p, node, tree->aux);
        pp = p;

        if (cmp > 0) {
            p = p->left;
        }else if (cmp < 0){
            p = p->right;
        }else {
            // search success
            return p;
        }
    }

    if (!pp) {
        return pp;
    }

    cmp = func(pp, node, tree->aux);
    if (cmp < 0) {
        return pp;
    }else{
        return avl_prev(pp);
    }
}

void avl_init(struct avl_tree *tree, void *aux)
{
    tree->root = NULL;
    tree->aux = aux;
}

struct avl_node* avl_insert(struct avl_tree *tree,
                            struct avl_node *node,
                            avl_cmp_func *func)
{
    __AVL_DEBUG_INSERT(node);

    struct avl_node *p=NULL,*cur;
    int cmp, bf, bf_old;

    cur = tree->root;
    while(cur)
    {
        cmp = func(cur, node, tree->aux);
        p = cur;

        if(cmp > 0) {
            cur = cur->left;
        }else if (cmp < 0){
            cur = cur->right;
        }else {
            // duplicated key -> return
            return cur;
        }
    }

    avl_set_parent(node, p);
    avl_set_bf(node, 0);
    node->left = node->right = NULL;
#ifdef _AVL_NEXT_POINTER
    node->prev = node->next = NULL;
#endif

    // P is parent node of CUR
    if(p) {
        if(func(p, node, tree->aux) > 0) {
            p->left = node;
#ifdef _AVL_NEXT_POINTER
            node->next = p;
            node->prev = p->prev;
            if (p->prev) p->prev->next = node;
            p->prev = node;
#endif

        }else {
            p->right = node;
#ifdef _AVL_NEXT_POINTER
            node->prev = p;
            node->next = p->next;
            if (p->next) p->next->prev = node;
            p->next = node;
#endif
        }

    } else {
        // no parent .. make NODE as root
        tree->root = node;
    }

    // recursive balancing process .. scan from leaf to root
    bf = 0;
    while(node) {
        p = avl_parent(node);

        if (p) {
            // if parent exists
            bf_old = avl_bf(node);

            if (p->right == node) {
                node = _balance_tree(node, bf);
                p->right = node;
            }else {
                node = _balance_tree(node, bf);
                p->left = node;
            }

            // calculate balance facter BF for parent
            if (node->left == NULL && node->right == NULL) {
                // leaf node
                if (p->left == node) bf = -1;
                else bf = 1;
            } else {
                // index ndoe
                bf = 0;
                if (_abs(bf_old) < _abs(avl_bf(node))) {
                    // if ABS of balance factor increases
                    // cascade to parent
                    if (p->left == node) bf = -1;
                    else bf = 1;
                }
            }

        } else if(node == tree->root){
            tree->root = _balance_tree(tree->root, bf);
            break;
        }
        if (bf == 0) break;

        node = p;
    }

    __AVL_DEBUG_DISPLAY(tree);

    return node;
}

void avl_remove(struct avl_tree *tree,
                struct avl_node *node)
{
    __AVL_DEBUG_REMOVE(node);

    // not found
    if (node == NULL) return;

    struct avl_tree right_subtree;
    struct avl_node *p=NULL,*cur, *next=NULL;
    int bf = 0, bf_old;


#ifdef _AVL_NEXT_POINTER
    if (node->prev) node->prev->next = node->next;
    if (node->next) node->next->prev = node->prev;
#endif

    // find smallest node in right sub-tree
    right_subtree.root = node->right;
    next = avl_first(&right_subtree);

    if (next) {
        // 1. NEXT exists
        if (avl_parent(next)) {
            if (avl_parent(next) != node) {
                // NODE is not NEXT's direct parent
                // MUST ensure NEXT should be *left child* of its parent
                // MUST ensure NEXT doesn't have right child
                avl_parent(next)->left = next->right;
                if (next->right)
                    avl_set_parent(next->right, avl_parent(next));
            }
        }
        if (avl_parent(node)) {
            // replace NODE by NEXT
            if (avl_parent(node)->left == node) {
                avl_parent(node)->left = next;
            } else {
                avl_parent(node)->right = next;
            }
        }

        // re-link pointers
        if (node->right != next) {
            next->right = node->right;
            if (node->right) avl_set_parent(node->right, next);
            cur = avl_parent(next);
            bf = 1;
        }else{
            cur = next;
            bf = -1;
        }

        next->left = node->left;
        if (node->left) avl_set_parent(node->left, next);
        avl_set_parent(next, avl_parent(node));

        // inherit NODE's balance factor
        avl_set_bf(next, avl_bf(node));

    } else {
        // 2. NEXT == NULL (only when there's no right sub-tree)
        p = avl_parent(node);
        if (p) {
            if (p->left == node) {
                p->left = node->left;
                bf = 1;
            } else {
                p->right = node->left;
                bf = -1;
            }
        }
        if (node->left)
            avl_set_parent(node->left, p);

        cur = avl_parent(node);
    }

    // reset root
    if (tree->root == node) {
        tree->root = next;
        if (next == NULL) {
            if (node->left) tree->root = node->left;
        }
    }

    // recursive balancing process .. scan from CUR to root
    while(cur) {
        p = avl_parent(cur);
        if (p) {
            // if parent exists
            bf_old = avl_bf(cur);

            if (p->right == cur) {
                cur = _balance_tree(cur, bf);
                p->right = cur;
            }else {
                cur = _balance_tree(cur, bf);
                p->left = cur;
            }

            // calculate balance facter BF for parent
            if (cur->left == NULL && cur->right == NULL) {
                // leaf node
                if (p->left == cur) bf = 1;
                else bf = -1;
            } else {
                // index ndoe
                bf = 0;
                if (_abs(bf_old) > _abs(avl_bf(cur))) {
                    // if ABS of balance factor decreases
                    // cascade to parent
                    if (p->left == cur) bf = 1;
                    else bf = -1;
                }
            }

        } else if(cur == tree->root){
            tree->root = _balance_tree(tree->root, bf);
            break;
        }
        if (bf == 0) break;

        cur = p;
    }

    __AVL_DEBUG_DISPLAY(tree);
}

