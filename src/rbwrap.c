/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#include "rbwrap.h"

void rbwrap_init(struct rb_root *root)
{
	root->rb_node = NULL;
}

struct rb_node * __rbwrap_insert(struct rb_root *root, struct rb_node *node, rbwrap_cmp_func *func)
{
	struct rb_node ** p = &root->rb_node;
	struct rb_node * parent = NULL;

	while (*p)
	{
		parent = *p;

		if (func(node, *p) < 0)
			p = &(*p)->rb_left;
		else if (func(node, *p) > 0)
			p = &(*p)->rb_right;
		else
			return *p;
	}

	if (parent)
		rb_link_node(node, parent, p);
	else
		rb_root_init(root, node);

	return NULL;	
}

struct rb_node * rbwrap_insert(struct rb_root *root, struct rb_node *node, rbwrap_cmp_func *func)
{
	struct rb_node *ret;
	if ((ret = __rbwrap_insert(root, node, func)))
		goto out;
	rb_insert_color(node, root);
 out:
	return ret;	
}

struct rb_node * rbwrap_search(struct rb_root *root, struct rb_node *node, rbwrap_cmp_func *func)
{
	struct rb_node * n = root->rb_node;
	//struct page * page;

	while (n)
	{
		if (func(node, n) < 0)
			n = n->rb_left;
		else if (func(node, n) > 0)
			n = n->rb_right;
		else
			return n;
	}
	return NULL;
}



