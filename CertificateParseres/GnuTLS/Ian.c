#include "header.h"

//same as phrase_san
int phrase_ian(gnutls_x509_crt_t cert,cJSON* root,err* err_list,const char* sha1){
    gnutls_datum_t detector_san = {NULL,0};
    unsigned int detector_san_critical = 0;
    int san_detector = gnutls_x509_crt_get_extension_by_oid2(cert,"2.5.29.18",0,&detector_san,&detector_san_critical);
    if(san_detector ==GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE){
        cJSON* add_san_null = cJSON_AddNullToObject(root, "IAN");
		if(!add_san_null){
            printf("%s,Cert without IAN,json serailization failed in add null object to root object .\n",sha1);
			return 1;
		}
        return 0;
    }else if(san_detector < 0){
        Insert_headpos_err(err_list,gnutls_strerror(san_detector));
        cJSON* add_san_null1 = cJSON_AddNullToObject(root, "IAN");
        if(!add_san_null1){
			printf("%s,Phrasing IAN failed,json serailization failed in add null object to root object .\n",sha1);
		}
        return 1;
    }else if(san_detector == 0){
        if(detector_san.data){
            gnutls_free(detector_san.data);
        }
        int init_pos =0;
        int san_get_res = 0;
        void* save_san=NULL;
        size_t save_san_mem=0;
        unsigned int * critical_san;

        sanNode* header = malloc(sizeof(sanNode));
        header->data = NULL;
        header->next = NULL;
        sanNode* tail =header;
        
        while(san_get_res != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE){
            san_get_res = gnutls_x509_crt_get_issuer_alt_name(cert,init_pos,save_san,&save_san_mem,critical_san);
            if(san_get_res==GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE){
                break;
            }
            if(san_get_res<0&&san_get_res!=GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE&&san_get_res!=GNUTLS_E_SHORT_MEMORY_BUFFER){
                Insert_headpos_err(err_list,gnutls_strerror(san_get_res));
                cJSON* add_san_null1 = cJSON_AddNullToObject(root, "IAN");
                if(!add_san_null1){
                    printf("%s,Phrasing IAN failed,add null to IAN filed failed , IAN will not show in json item.\n",sha1);
                }
                free_san_list(header);
                return 1;
            }
            if (san_get_res == GNUTLS_E_SHORT_MEMORY_BUFFER){
                printf("num_ian:%zu",save_san_mem);
                save_san = calloc(save_san_mem+1,1);
                san_get_res = gnutls_x509_crt_get_issuer_alt_name(cert,init_pos,save_san,&save_san_mem,critical_san);
            }
            if(san_get_res==GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE){
                break;
            }
            if(san_get_res<0&&san_get_res!=GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE&&san_get_res!=GNUTLS_E_SHORT_MEMORY_BUFFER){
                Insert_headpos_err(err_list,gnutls_strerror(san_get_res));
                cJSON* add_san_null1 = cJSON_AddNullToObject(root, "IAN");
                if(!add_san_null1){
                    printf("%s,Phrasing IAN failed,add null to IAN filed failed , IAN will not show in json item.\n",sha1);
                }
                free_san_list(header);
                return 1;
            }

            if(san_typenums_to_boolean(san_get_res)==1){
                sanNode* this_item = malloc(sizeof(sanNode));
                tail->next = this_item;
                san_entry* this_entry = malloc(sizeof(san_entry));
                this_entry->type = reflact_number_to_str(san_get_res);
                this_entry->value = (char*)save_san;
                this_item->data = this_entry;
                this_item->next = NULL;
                tail = this_item;

                save_san = NULL;
                save_san_mem = 0;
                init_pos++;
            }else if(san_typenums_to_boolean(san_get_res)==2){
                save_san = NULL;
                save_san_mem =0;
                init_pos++;
            }else{
                printf("%s,meet an undefined generalName type.\n",sha1);
                save_san = NULL;
                save_san_mem =0;
                init_pos++;
            }
        }
        cJSON* SAN = serializeList(header,sha1);
        if(!SAN){
            cJSON* add_san = cJSON_AddNullToObject(root, "IAN");
            if(!add_san){
                printf("%s,json:Phrasing IAN success,generate IAN json_obj failed,set IAN as NULL failed,no IAN in cert.\n",sha1);
            }
            free_san_list(header);
            return 1;
        }
        cJSON_AddItemToObject(root, "IAN", SAN);
        free_san_list(header);
        return 0;
    }
}