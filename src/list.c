/*
 * Copyright 2013 Jung-Sang Ahn <jungsang.ahn@gmail.com>.
 * All Rights Reserved.
 */

#include <stdio.h>
#include <assert.h>
#include "list.h"

void list_init(struct list *list)
{
	list->head = NULL;
	list->tail = NULL;
}

void list_push_front(struct list *list, struct list_elem *e)
{
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
}

void list_push_back(struct list *list, struct list_elem *e)
{
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
}

// insert E just before BEFORE
void list_insert_before(struct list *list, struct list_elem *before, struct list_elem *e)
{
	e->prev = before->prev;
	e->next = before;
	if (before->prev) before->prev->next = e;
	else list->head = e;
	before->prev = e;
}

// insert E just after AFTER
void list_insert_after(struct list *list, struct list_elem *after, struct list_elem *e)
{
	e->next = after->next;
	e->prev = after;
	if (after->next) after->next->prev = e;
	else list->tail = e;
	after->next = e;
}

struct list_elem *list_remove(struct list *list, struct list_elem *e)
{
	if (e) {
		// if not NULL
		if (e->next) e->next->prev = e->prev;
		if (e->prev) e->prev->next = e->next;
		
		if (list->head == e) list->head = e->next;
		if (list->tail == e) list->tail = e->prev;

		return e->next;
	}
	// NULL .. do nothing
	return NULL;
}

struct list_elem *list_remove_reverse(struct list *list, struct list_elem *e)
{
	if (e) {
		// if not NULL
		if (e->next) e->next->prev = e->prev;
		if (e->prev) e->prev->next = e->next;
		
		if (list->head == e) list->head = e->next;
		if (list->tail == e) list->tail = e->prev;

		return e->prev;
	}
	// NULL .. do nothing
	return NULL;
}

struct list_elem *list_pop_front(struct list *list)
{
	struct list_elem *front = list->head;
	list_remove(list, front);
	return front;
}

struct list_elem *list_pop_back(struct list *list)
{
	struct list_elem *back = list->tail;
	list_remove(list, back);
	return back;
}

struct list_elem *list_begin(struct list *list)
{
	return list->head;
}

struct list_elem *list_end(struct list *list)
{
	return list->tail;
}

struct list_elem *list_next(struct list_elem *e)
{
	return e->next;
}

struct list_elem *list_prev(struct list_elem *e)
{
	return e->prev;
}

