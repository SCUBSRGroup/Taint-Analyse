/*doublylist tools
 klist.h by:kk
 update:2012/10/10
 version:v0.1

 *main function£º
 *add element to head or tail£º                   		k_list_append_head/k_list_append_tail
 *insert element before or after somewhere            k_list_insert_before/k_list_insert_after
 *return the first or last element				k_list_get_head/k_list_get_tail
 *return length of the list						k_list_get_length
 *remove element and free memory 			k_list_remove_node
 *remove all element 			   			k_list_remove_all
 *walk through the list and call the walk-func		k_list_foreach
 *search element base on the compare function	k_list_search_node
 */
#ifndef __K_LIST_H__
#define __K_LIST_H__
#include <stdlib.h>
#include <string.h>

struct _KList {
	void *data;
	struct _KList *next;
	struct _KList *prev;
	int iNodeLen;
};
typedef struct _KList KList;

#define KLIST_ALLOC() (KList*)malloc(sizeof(KList));


typedef void (*KListFunc)(KList* data, void* user_data);
typedef int (*KListCompareFunc)(void* data, void* user_data);

KList* k_list_append_head(KList *list, void *data,int iLen);
KList* k_list_append_tail(KList *list, void *data,int iLen);
KList* k_list_insert_before(KList *list, KList *node, void* data,int iLen);
KList* k_list_insert_after(KList *list, KList *node, void* data,int iLen);
KList* k_list_get_head(KList *list);
KList* k_list_get_tail(KList *list);
int k_list_get_length(KList *list);
KList* k_list_remove_node(KList *list, KList *node);
void k_list_remove_all(KList *list);
void k_list_foreach(KList *list, KListFunc walkfunc, void *user_data);
KList* k_list_search_node(KList *list, KListCompareFunc comparefunc, void *user_data);
#endif
