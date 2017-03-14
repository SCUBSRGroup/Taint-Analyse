/*doublylist tools
 klist.c by:CKT
 update:2012/10/10
 version:v0.1

 *main function：
 
 *add element to head or tail：                   k_list_append_head/k_list_append_tail
 *insert element before or after somewhere        k_list_insert_before/k_list_insert_after
 *return the first or last element				 	  		k_list_get_head/k_list_get_tail
 *return length of the list							        	k_list_get_length
 *remove element and free memory 									k_list_remove_node
 *remove all element 			   											k_list_remove_all
 *walk through the list and call the walk-func		k_list_foreach
 *search element base on the compare function			k_list_search_node
 */
#include "klist.h"

/*
 * function: add an element to the head of the list
 * para: 1、list：should be the head pointer of the list. 2、data: element data
 * return:the new head pointer
 * notice:if list=NULL,then the func create a new list
 */
KList* k_list_append_head(KList *list, void *data, int iLen)
{
	KList *new_list;
	new_list = KLIST_ALLOC();
	if (!new_list)
	{
		return NULL;
	}
	new_list->data = malloc(iLen);
	if (!new_list->data)
	{
		return NULL;
	}
	memcpy(new_list->data, data, iLen);

	new_list->next = list;
	if (list)
	{
		new_list->prev = list->prev;
		if (list->prev)
		{
			list->prev->next = new_list;//func goes here only when the para "list" is not the head element
		}
		list->prev = new_list;
	}
	else
	{
		new_list->prev = NULL;
	}
	return new_list;
}
/*
 * function: add an element to the tail of the list
 * para: 1、list：can be any element of the list. 2、data: element data
 * return:the new tail pointer
 * notice:if list=NULL,then the func create a new list
 */
KList* k_list_append_tail(KList *list, void *data, int iLen)
{
	KList *new_list;

	new_list = KLIST_ALLOC();
	if (!new_list)
	{
		return NULL;
	}
	new_list->data = malloc(iLen);
	if (!new_list->data)
	{
		return NULL;
	}
	memcpy(new_list->data, data, iLen);
	new_list->next = NULL;

	if (list)
	{
		while (list->next)//this is an O(n) operation,so the para "list" should better be close to the tail
			list = list->next;
		list->next = new_list;
		new_list->prev = list;
	}
	else
	{
		new_list->prev = NULL;
	}
	return new_list;
}

/*
 * function: insert an element before the given element
 * para: 1、list：the pointer of the given element. 2、data: element data
 * return:the new head pointer
 * notice:any para should not be "NULL"
 */
KList* k_list_insert_before(KList *list, KList *destnode, void* data, int iLen)//����������ΪNULL
{
	if (!list || !destnode || !data)
	{
		return NULL;
	}

	KList *node;
	node = KLIST_ALLOC();
	if (!node)
	{
		return NULL;
	}
	node->data = malloc(iLen);
	if (!node->data)
	{
		return NULL;
	}
	memcpy(node->data, data, iLen);
	node->prev = destnode->prev;
	node->next = destnode;
	destnode->prev = node;
	if (node->prev)
	{
		node->prev->next = node;
		return list;
	}
	else
	{
		return node;
	}
}

/*
 * function: insert an element after the given element
 * para: 1、list：the pointer of the given element. 2、data: element data
 * return:the new head pointer
 * notice:any para should not be "NULL"
 */
KList* k_list_insert_after(KList *list, KList *destnode, void* data, int iLen)
{
	if (!list || !destnode || !data)
	{
		return NULL;
	}
	KList *node;
	node = KLIST_ALLOC();
	if (!node)
	{
		return NULL;
	}
	node->data = malloc(iLen);
	if (!node->data)
	{
		return NULL;
	}
	memcpy(node->data, data, iLen);
	node->prev = destnode;
	node->next = destnode->next;
	destnode->next = node;
	if (node->next)
	{
		node->next->prev = node;
	}
	return list;
}

/*
 * function: get the head pointer of the list
 * para: 1、list：any element of the list
 * return:the  head pointer
 * notice:para should not be "NULL"
 */
KList* k_list_get_head(KList *list)
{
	if (!list)
	{
		return NULL;
	}
	while (list->prev)
		list = list->prev;
	return list;
}

/*
 * function: get the tail pointer of the list
 * para: 1、list：any element of the list
 * return:the tail pointer
 * notice:para should not be "NULL"
 */
KList* k_list_get_tail(KList *list)
{
	if (!list)
	{
		return NULL;
	}
	while (list->next)
		list = list->next;
	return list;
}

/*
 * function: get the size of the list
 * para: 1、list：the head element of the list
 * return:length of the list
 * notice:para should not be "NULL" and head element
 */
int k_list_get_length(KList *list)
{
	if (!list || list->prev)
	{
		return 0;
	}
	int iLen = 1;
	while (list->next)
	{
		iLen++;
		list = list->next;
	}
	return iLen;
}

/*
 * function: remove a node and free its space
 * para: 1、list：the head element of the list 2、node：element need to remove
 * return:new head of the list
 * notice:para should not be "NULL"
 */
KList* k_list_remove_node(KList *list, KList *node)
{
	if (!list || !node)
	{
		return NULL;
	}
	if (node->prev)
	{
		node->prev->next = node->next;
	}
	if (node->next)
	{
		node->next->prev = node->prev;
	}
	if (node == list)
	{
		list = list->next;
	}
	node->next = NULL;
	node->prev = NULL;
	if (node->data)
	{
		free(node->data);
		node->data = NULL;
	}
	free(node);
	return list;
}

/*
 * function: remove all nodes and free their space
 * para: 1、list：the head element of the list 
 * return: none
 * notice:para should not be "NULL" and the head element
 */
void k_list_remove_all(KList *list)
{
	if (!list || list->prev)
	{
		return;
	}
	KList* node = list;
	do
	{
		node = k_list_remove_node(node, node);
	} while (node);
}

/*
 * function: walk along the list with walkfunc called for all element
 * para: 1、list：the head element of the list 2、walkfunc：called for all element,you can refer to its define 3、user_data:used by walkfunc
 * return: none
 * notice: KListFunc should be define by user
 */
void k_list_foreach(KList *list, KListFunc walkfunc, void *user_data)
{
	while (list)
	{
		KList *node = list;
		list = list->next;                                                               
		(*walkfunc)(node, user_data);
	}
}

/*
 * function: search for node with comparefunc
 * para: 1、list：the head element of the list 2、comparefunc：called for all element,you can refer to its define 3、user_data:used by comparefunc
 * return: the search element(if found)
 * notice: KListCompareFunc should be define by user
 */

KList* k_list_search_node(KList *list, KListCompareFunc comparefunc, void *user_data)
{
	while (list)
	{
		KList *next = list->next;
		if ((*comparefunc)(list->data, user_data))
		{
			return list;
		}
		list = next;
	}
	return NULL;
}
