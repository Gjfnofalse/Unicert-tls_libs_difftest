#include "header.h"

// memory free module
void free_san_list(sanNode* head) {
    sanNode* current = head;
    sanNode* next;

    while (current != NULL) {
        if (current->data != NULL) {
            if (current->data->value != NULL) {
                free(current->data->value);
            }
            free(current->data);
        }
        next = current->next;
        free(current);
        current = next;
    }
}

void free_crl_disp_list(crl_disp* head) {
    crl_disp* current = head;
    crl_disp* next;

    while (current != NULL) {
        if (current->data != NULL) {
            if (current->data->data != NULL){
                free(current->data->data);
            }
            free(current->data);
        }
        next = current->next;
        free(current);
        current = next;
    }
}

void free_err_list(err* head){
    err* current = head;
    err* next;

    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }
}

void free_policy_information(policy_information *pi) {
    if(!pi){
        return ;
    }
    qualifier *qualifier_current = pi->policy_qualifiers;
    qualifier *qualifier_next;
    
    while (qualifier_current != NULL) {
        qualifier_next = qualifier_current->next;
        if(qualifier_current->data){
            free(qualifier_current->data);
        }
        free(qualifier_current);
        qualifier_current = qualifier_next;
    }

    free(pi->policy_identifier);
    free(pi);
}

void free_cert_policies(cert_policies *cp) {
    cert_policies *cp_next;
    while (cp != NULL) {
        cp_next = cp->next;
        free_policy_information(cp->data);
        free(cp);
        cp = cp_next;
    }
}

