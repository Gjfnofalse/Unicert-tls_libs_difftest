#include "header.h"
//REF https://gnutls.org/manual/html_node/Common-types.html

// This function exists error currently.
const char* reflact_number_to_str(gnutls_x509_subject_alt_name_t GeneralNameClass){
    if(GeneralNameClass ==1){
        return "DNSNAME";//ia5String
    }else if(GeneralNameClass == 2){
        return "RFC822NAME";//ia5String
    }else if(GeneralNameClass == 3){
        return "URI";//ia5String
    }else if(GeneralNameClass == 4){
        return "IP";//octect stRING
    }else if(GeneralNameClass == 5){
        return "OTHERNAME";//OID->ascii
    }else if(GeneralNameClass == 6){
        return "DN"; //Name/？
    }else if(GeneralNameClass == 7){
        return "REGID";// OID-> ascii
    }else{
        return "UNDEFINEDTYPE";
    }
}

int san_typenums_to_boolean(int type){
    if(type<=7&&type>=1&&type!=5){
        return 1;
    }else if(type == 5 || type ==1000 || type ==1001 || type ==1002){
        return 2;//OTHERNAME
    }else{
        return 0; //Failure
    }
}

cJSON* serializeList(sanNode* head,const char* sha1){
    cJSON* jsonArray = cJSON_CreateArray();
    sanNode* current = head->next; 
    
    while (current != NULL) {
        cJSON* jsonObject = cJSON_CreateObject();

        if (current->data) {
            cJSON* add_v = cJSON_AddStringToObject(jsonObject, "value", current->data->value);
            if(!add_v){
                cJSON_Delete(jsonObject);
                cJSON_Delete(jsonArray);
                printf("%s\n,json:add generalName value to generalName failed.",sha1);
                return NULL;
            }
            cJSON* add_t = cJSON_AddStringToObject(jsonObject, "type", current->data->type);
            if(!add_t){
                cJSON_Delete(jsonObject);
                cJSON_Delete(jsonArray);
                printf("%s\n,json:add generalName type to generalName failed.",sha1);
                return NULL;
            }
        }

        cJSON_AddItemToArray(jsonArray, jsonObject);
        current = current->next;
    }
    return jsonArray;
}

int phrase_san(gnutls_x509_crt_t cert,cJSON* root,err* err_list,const char* sha1){
    gnutls_datum_t detector_san = {NULL,0};
    unsigned int detector_san_critical = 0;
    int san_detector = gnutls_x509_crt_get_extension_by_oid2(cert,"2.5.29.17",0,&detector_san,&detector_san_critical);
    if(san_detector ==GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE){
        cJSON* add_san_null = cJSON_AddNullToObject(root, "SAN");
		if(!add_san_null){
            printf("%s,Cert without SAN,json serailization failed in add null object to root object .\n",sha1);
			return 1;
		}
        return 0;
    }else if(san_detector < 0){
        Insert_headpos_err(err_list,gnutls_strerror(san_detector));
        cJSON* add_san_null1 = cJSON_AddNullToObject(root, "SAN");
        if(!add_san_null1){
			printf("%s,Phrasing SAN failed,json serailization failed in add null object to root object .\n",sha1);
		}
        return 1;
    }else if(san_detector == 0){
        if(detector_san.data){
            gnutls_free(detector_san.data);
        }
        int init_pos = 0; //get all generalNames
        int san_get_res = 0;
        void* save_san=NULL;
        size_t save_san_mem=0;
        unsigned int * critical_san;

        sanNode* header = malloc(sizeof(sanNode));
        header->data = NULL;
        header->next = NULL;
        sanNode* tail =header;
        
        while(san_get_res != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE){
            san_get_res = gnutls_x509_crt_get_subject_alt_name(cert,init_pos,save_san,&save_san_mem,critical_san);
            if(san_get_res==GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE){//I'm not sure whether to throw the memory allocation error first or this error first, so I might as well write it twice
                break;
            }
            if(san_get_res<0&&san_get_res!=GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE&&san_get_res!=GNUTLS_E_SHORT_MEMORY_BUFFER){
                Insert_headpos_err(err_list,gnutls_strerror(san_get_res));
                cJSON* add_san_null1 = cJSON_AddNullToObject(root, "SAN");
                if(!add_san_null1){
                    printf("%s,Phrasing SAN failed,add null to SAN filed failed , SAN will not show in json item.\n",sha1);
                }
                free_san_list(header);
                return 1;
            }
            if (san_get_res == GNUTLS_E_SHORT_MEMORY_BUFFER){
                printf("num_san:%zu",save_san_mem);
                save_san = calloc(save_san_mem+1,1);
                san_get_res = gnutls_x509_crt_get_subject_alt_name(cert,init_pos,save_san,&save_san_mem,critical_san);
            }
            if(san_get_res==GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE){
                break;
            }
            if(san_get_res<0&&san_get_res!=GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE&&san_get_res!=GNUTLS_E_SHORT_MEMORY_BUFFER){
                Insert_headpos_err(err_list,gnutls_strerror(san_get_res));
                cJSON* add_san_null1 = cJSON_AddNullToObject(root, "SAN");
                if(!add_san_null1){
                    printf("%s,Phrasing SAN failed,add null to SAN filed failed , SAN will not show in json item.\n",sha1);
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
                //meet OtherName
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
            cJSON* add_san = cJSON_AddNullToObject(root, "SAN");
            if(!add_san){
                printf("%s,json:Phrasing SAN success,generate SAN json_obj failed,set SAN as NULL failed,no SAN in item.\n",sha1);
            }
            free_san_list(header);
            return 1;
        }
        cJSON_AddItemToObject(root, "SAN", SAN);
        free_san_list(header);
        return 0;
    }
}