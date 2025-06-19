#include "header.h"
// error handling module

void Insert_headpos_err(err* header,const char* data){
    err* new_node = malloc(sizeof(err));
    new_node->data = data;
    new_node->next = header->next;
    header->next = new_node;
}

cJSON* serialize_err_list(err* err_list,const char* sha1) {
    if (!err_list) {
        return NULL;
    }
    cJSON* array = cJSON_CreateArray();

    err* current = err_list->next;
    while (current != NULL) {
        cJSON_AddItemToArray(array,cJSON_CreateString(current->data));
        current = current->next;
    }
    return array;
}