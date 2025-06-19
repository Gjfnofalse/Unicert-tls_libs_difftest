#include "header.h"

cJSON* serialize_disp(disp* entry,char* sha1) {
    if (!entry) {
        return NULL;
    }
    cJSON* obj = cJSON_CreateObject();
    cJSON* add_data = cJSON_AddStringToObject(obj, "distributionPoint", entry->data);
    if(!add_data){
        cJSON_Delete(obj);
        printf("%s,json:add full_name to disp failed.\n",sha1);
        return NULL;
    }
    cJSON* add_type = cJSON_AddStringToObject(obj, "type", entry->type);
    if(!add_type){
        cJSON_Delete(obj);
        printf("%s,json:add full_name type to disp failed.\n",sha1);
        return NULL;
    }
    return obj;
}

cJSON* serialize_crl_disp_list(crl_disp* head,char* sha1) {
    if (!head) {
        return NULL;
    }
    cJSON* array = cJSON_CreateArray();

    crl_disp* current = head->next;
    while (current != NULL) {
        cJSON* entry_json = serialize_disp(current->data,sha1);
        if (entry_json) {
            cJSON_AddItemToArray(array, entry_json);
        }else{
            cJSON_Delete(array);
            printf("%s,json:add disp to crl_disp failed.\n",sha1);
            return NULL;
        }
        current = current->next;
    }
    return array;
}

int phrase_crl_disp(gnutls_x509_crt_t cert,cJSON* root,err* err_list,char* sha1){
    gnutls_datum_t detector_crlDis = {NULL,0};
    unsigned int detector_crlDis_critical = 0;
    int crlDis_detector = gnutls_x509_crt_get_extension_by_oid2(cert,"2.5.29.31",0,&detector_crlDis,&detector_crlDis_critical);
    if(crlDis_detector ==GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE){
        //There is no CRL_DISP field. Skip the processing.
        cJSON* add_crl_disp_null = cJSON_AddNullToObject(root, "CRLDistributionPoints");
		if(!add_crl_disp_null){
            printf("%s,json:Cert without CRLDistributionPoints,json serailization failed in add null object to root object .\n",sha1);
			return 1;
		}
        return 0;
    }else if(crlDis_detector < 0){
        Insert_headpos_err(err_list,gnutls_strerror(crlDis_detector));
        cJSON* add_crl_null1 = cJSON_AddNullToObject(root, "CRLDistributionPoints");
        if(!add_crl_null1){
			printf("%s,json:Phrasing CRLDistributionPoints failed,json serailization failed in add null object to root object .\n",sha1);
		}
        return 1;
    }else if(crlDis_detector ==0){
        if(detector_crlDis.data){
            gnutls_free(detector_crlDis.data);
        }
        int crlDis_seq = 0;
        int crlDis_get_res = 0;
        void* ret=NULL; 
        unsigned int revoke_reason_save = 0;
        unsigned int crlDis_critical = 0;
        size_t crlDis_mem =0;
        crl_disp* crl_header = malloc(sizeof(crl_disp));
        crl_header->data = NULL;
        crl_header->next = NULL;
        crl_disp* crl_tailer = crl_header;
        while(crlDis_get_res==0){
            crlDis_get_res = gnutls_x509_crt_get_crl_dist_points(cert,crlDis_seq,ret,&crlDis_mem,&revoke_reason_save,&crlDis_critical);
            //I'm not clear about the order in which GNUTLS reports errors, so I'll repeat it here
            if(crlDis_get_res<0&&crlDis_get_res!=GNUTLS_E_SHORT_MEMORY_BUFFER&&crlDis_get_res!=GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE){
                Insert_headpos_err(err_list,gnutls_strerror(crlDis_get_res));
                cJSON* add_crlDis_null1 = cJSON_AddNullToObject(root, "CRLDistributionPoints");
                if(!add_crlDis_null1){
                    printf("%s,json:Phrasing crl_disp failed,add null to crl_disp filed failed , crl_disp will not show in json item.\n",sha1);
                }
                free_crl_disp_list(crl_header);
                return 1;
            }
            if(crlDis_get_res == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE){
                break;
            }
            if(crlDis_get_res ==GNUTLS_E_SHORT_MEMORY_BUFFER){
                ret = calloc(crlDis_mem+1,1);
                crlDis_get_res = gnutls_x509_crt_get_crl_dist_points(cert,crlDis_seq,ret,&crlDis_mem,&revoke_reason_save,&crlDis_critical);
            }
            if(crlDis_get_res<0&&crlDis_get_res!=GNUTLS_E_SHORT_MEMORY_BUFFER&&crlDis_get_res!=GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE){
                Insert_headpos_err(err_list,gnutls_strerror(crlDis_get_res));
                cJSON* add_crlDis_null1 = cJSON_AddNullToObject(root, "CRLDistributionPoints");
                if(!add_crlDis_null1){
                    printf("%s,json:Phrasing crl_disp failed,add null to crl_disp filed failed , crl_disp will not show in json item.\n",sha1);
                }
                free_crl_disp_list(crl_header);
                return 1;
            }
            if(crlDis_get_res == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE){
                break;
            }
            if(san_typenums_to_boolean(crlDis_get_res)==1){
                crl_disp* crl_save = malloc(sizeof(crl_disp));
                crl_tailer->next = crl_save;
                crl_tailer = crl_save;
                crl_save->next =NULL;
                
                disp* disp_item_save = malloc(sizeof(disp));
                
                disp_item_save->data = (char*)ret;
                disp_item_save->type = reflact_number_to_str(crlDis_get_res);
                crl_save->data = disp_item_save;
                
                ret =NULL;
                crlDis_mem = 0;
                crlDis_seq++;   
            }else if(san_typenums_to_boolean(crlDis_get_res)==2){
                //meets OtherName
                ret = NULL;
                crlDis_mem =0;
                crlDis_seq++;
            }
        }
        cJSON* crl_json = serialize_crl_disp_list(crl_header,sha1);
        if(!crl_json){
            cJSON* add_crl_null1 = cJSON_AddNullToObject(root, "CRLDistributionPoints");
            if(!add_crl_null1){
                printf("%s,json:Phrasing CRLDistributionPoints success,json serailization failed ,set crl_disp as null failed,no crl_disp in cert entry.\n",sha1);
            }
            free_crl_disp_list(crl_header);
            return 1;
        }
        cJSON_AddItemToObject(root, "CRLDistributionPoints", crl_json);
        free_crl_disp_list(crl_header);
        return 0;
    }
}