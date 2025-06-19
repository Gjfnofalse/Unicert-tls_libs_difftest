#include "header.h"

cJSON* cert_policies_to_json(cert_policies* head,char* sha1) {
    if (head == NULL) {
        return NULL;
    }
    cJSON* policiesArray = cJSON_CreateArray();

    cert_policies* current = head->next;
    while (current != NULL) {
        cJSON* policyObject = cJSON_CreateObject();

        if (current->data != NULL) {
            // add policy_identifier/oid
            cJSON* add_oid = cJSON_AddStringToObject(policyObject, "policy_identifier", current->data->policy_identifier);
            if(!add_oid){
                cJSON_Delete(policiesArray);
                cJSON_Delete(policyObject);
                printf("%s,json:add policy_identifier to policy_info failed.\n",sha1);
                return NULL;
            }
            // add policy_qualifiers
            cJSON* qualifiersArray = cJSON_CreateArray();
            qualifier* q = current->data->policy_qualifiers->next;
            while (q != NULL) {
                cJSON* qualifierObject = cJSON_CreateObject();
                cJSON* add_qualifier = cJSON_AddStringToObject(qualifierObject, "qualifier", q->data);
                if(!add_qualifier){
                    cJSON_Delete(policiesArray);
                    cJSON_Delete(policyObject);
                    cJSON_Delete(qualifiersArray);
                    cJSON_Delete(qualifierObject);
                    printf("%s,json:add cpsuri/uernotice to qualifier failed.\n",sha1);
                    return NULL;
                }
               cJSON* add_type = cJSON_AddStringToObject(qualifierObject, "type", q->type);
                if(!add_type){
                    cJSON_Delete(policiesArray);
                    cJSON_Delete(policyObject);
                    cJSON_Delete(qualifiersArray);
                    cJSON_Delete(qualifierObject);
                    printf("%s,json:add cpsuri/uernotice type to qualifier failed.\n",sha1);
                    return NULL;
                }
                cJSON_AddItemToArray(qualifiersArray, qualifierObject);
                q = q->next;
            }
            cJSON_AddItemToObject(policyObject, "policy_qualifiers", qualifiersArray);
        }
        cJSON_AddItemToArray(policiesArray, policyObject);
        current = current->next;
    }
    return policiesArray;
}

const char* num_to_cp_qualifier_type(gnutls_x509_qualifier_t type_num){
    if(type_num == 0){
        return "UNKNOWN";
    }else if(type_num ==1){
        return "CPSURI";
    }else{
        return "USERNOTICE";
    }
}

int phrase_cp(gnutls_x509_crt_t cert,cJSON* root,err* err_list,char* sha1){
    //0 represents successful parsing and add root success, and 1 represents parsing error, whether it is a parsing error or a cJSON error
    gnutls_datum_t detector_cp = {NULL,0};
    unsigned int detector_cp_critical = 0;
    
    int cp_detector = gnutls_x509_crt_get_extension_by_oid2(cert,"2.5.29.32",0,&detector_cp,&detector_cp_critical);
    if(cp_detector ==GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE){
        cJSON* add_cp_null = cJSON_AddNullToObject(root, "CertificatePolicies");
		if(!add_cp_null){
            printf("%s,json:Cert without CertificatePolicies,json serailization failed in add null object to cert object,no CertificatePolicies in cert.\n",sha1);
			return 1;
		}
        return 0;
    }else if(cp_detector<0){
        //Parsing failed and proceed to error handling
        Insert_headpos_err(err_list,gnutls_strerror(cp_detector));
        cJSON* add_cp_null1 = cJSON_AddNullToObject(root, "CertPolicies");
        if(!add_cp_null1){
			printf("%s,Phrasing CertPolices failed,json serailization failed in add null to cert object,no CertPolicies in cert.\n",sha1);
		}
        return 1;
    }else if(cp_detector==0){//parsing CertPolicies success
        if(detector_cp.data){
            gnutls_free(detector_cp.data);
        }
        int cp_pos =0;//Loop to get all policy_infomation in CertPolicies
        int cp_get_res =0;
        
        cert_policies* cp_header = malloc(sizeof(cert_policies));
        cp_header->data =NULL;
        cp_header->next = NULL;
        cert_policies* cp_tailer = cp_header;
        unsigned int cp_critical = 0;

        while(cp_get_res==0){
            gnutls_x509_policy_st cp_save;
            cp_save.oid = NULL;

            int cp_get_res = gnutls_x509_crt_get_policy(cert,cp_pos,&cp_save,&cp_critical);
            if(cp_get_res == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE){
                break;
            }

            if(cp_get_res <0 &&cp_get_res!=GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE){
                //error handling
                Insert_headpos_err(err_list,gnutls_strerror(cp_get_res));
                cJSON* add_cp_null1 = cJSON_AddNullToObject(root, "CertificatePolicies");
                if(!add_cp_null1){
                    printf("%s,Phrasing Certificate failed,add null to CertificatePolicies filed failed , CertificatePolicies will not show in json item.\n",sha1);
                }
                free_cert_policies(cp_header);
                return 1;
            }else{
                gnutls_x509_policy_st* free_this = &cp_save;
            
                cert_policies* save_p_info = malloc(sizeof(cert_policies));
                cp_tailer->next = save_p_info;
                cp_tailer = save_p_info;

                policy_information* p_info = malloc(sizeof(policy_information));
                save_p_info->data = p_info;

                p_info->policy_identifier = malloc(strlen(cp_save.oid)+1);//Copy the last \0
                strcpy(p_info->policy_identifier,cp_save.oid);

                p_info->policy_qualifiers = malloc(sizeof(qualifier));
                p_info->policy_qualifiers->data = NULL;
                p_info->policy_qualifiers->type = "header";
                p_info->policy_qualifiers->next = NULL;

                qualifier* tailer = p_info->policy_qualifiers;
                for(int i=0;i<cp_save.qualifiers;i++){
                    printf("cp_num:%u",cp_save.qualifier[i].size);
                    qualifier* tmp_cp = malloc(sizeof(qualifier));

                    tmp_cp->data = malloc(strlen(cp_save.qualifier[i].data)+1);
                    strcpy(tmp_cp->data,cp_save.qualifier[i].data);

                    tmp_cp->type = num_to_cp_qualifier_type(cp_save.qualifier[i].type);
                    tmp_cp->next = NULL;
                    tailer->next = tmp_cp;
                    tailer = tmp_cp;
                }
                cp_pos++;
                gnutls_x509_policy_release(free_this);
            }
        }

        cJSON* cp_json = cert_policies_to_json(cp_header,sha1);
        if(!cp_json){//There was an error in json serialization. Try adding NULL value.
            cJSON* add_cp = cJSON_AddNullToObject(root, "CertificatePolicies");
            if(!add_cp){
                printf("%s,json:Phrasing CertificatePolicies success,generate CertificatePolicies json_obj failed,set CertificatePolicies as NULL failed,no CertificatePolicies in cert.\n",sha1);
            }
            free_cert_policies(cp_header);
            return 1;
        }
        cJSON_AddItemToObject(root, "CertificatePolicies", cp_json);
        free_cert_policies(cp_header);
        return 0;
    }
}