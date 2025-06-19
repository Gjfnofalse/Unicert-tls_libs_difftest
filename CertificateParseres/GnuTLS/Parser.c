#include "header.h"

void* ustrcpy(unsigned char *dest, unsigned char *src) {
    size_t i;
    for (i = 0; src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    dest[i] = '\0'; // Ensure null termination
    return dest;
}

//The basic fields will be parsed in this file, and the extensions will be parsed in other files
int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        return 1; 
    }
    FILE *file = fopen(argv[1], "r");
    FILE *output = fopen(argv[2], "a");
    if (!file)
    {
        printf("%s\n","Error opening input file.");
        return 1;
    }
    if (output == NULL)
    {
        printf("%s\n","Error opening output file.");
        return 1;
    }
    char line[4096]; 
    while (fgets(line, sizeof(line), file))
    {
        cJSON *json = cJSON_Parse(line);
        if (!json)
        {
            printf("%s", "json:parse json error {sha1,pem}.");
            continue; 
        }

        cJSON *FocusFieldItem = cJSON_GetObjectItem(json, "FocusField");
        cJSON *FocusFieldValueItem = cJSON_GetObjectItem(json, "FocusFieldValue");
        cJSON *InsertValueItem = cJSON_GetObjectItem(json, "IncertValue");
        cJSON *DesItem = cJSON_GetObjectItem(json, "description");
        const char* sha1_t,*pem_t;
        cJSON *sha1Item = cJSON_GetObjectItem(json, "sha1");
        if (sha1Item && sha1Item->type == cJSON_String) {
            sha1_t = sha1Item->valuestring;
        }else{
            printf("%s\n","json:load cert info from json str failed,next json str.");
            cJSON_Delete(json);
            continue;
        }

        cJSON *pemItem = cJSON_GetObjectItem(json, "pem");
        if (pemItem && pemItem->type == cJSON_String) {
            pem_t = pemItem->valuestring;
        }else{
            printf("%s\n","json:load cert info from json str failed,next json str.");
            cJSON_Delete(json);
            continue;
        }

        size_t pem_len = strlen(pem_t);
        size_t sha1_len = strlen(sha1_t);
        char* sha1 = malloc(sha1_len+1);
        char* pem = malloc(pem_len+1);
        strcpy(pem,pem_t);
        strcpy(sha1,sha1_t);
        sha1[sha1_len] = '\0';
        pem[pem_len] = '\0';
        
        cJSON_Delete(json);
        gnutls_global_init();
        gnutls_datum_t cert_data;
        cert_data.data = (unsigned char *)pem;
        cert_data.size = strlen(pem);
        gnutls_x509_crt_t cert;
        gnutls_x509_crt_init(&cert); 
        
        cJSON *root = cJSON_CreateObject();
        cJSON_AddItemToObject(root, "FocusField", FocusFieldItem);
        cJSON_AddItemToObject(root, "FocusFieldValue", FocusFieldValueItem);
        cJSON_AddItemToObject(root, "InsertValue", InsertValueItem);
        cJSON_AddItemToObject(root, "description", DesItem);
        err* err_header = malloc(sizeof(err));
        err_header->data = NULL;
        err_header->next = NULL;
        
        cJSON* add_sha1 = cJSON_AddStringToObject(root,"sha1",sha1);
        if(!add_sha1){
            printf("%s,json:add sha1 info to cert obj failed,no sha1 in cert.\n",sha1);
        }

        int initRes = gnutls_x509_crt_import(cert, &cert_data, GNUTLS_X509_FMT_PEM); // 导入X509证书

        if (initRes < 0)
        {
            cJSON* add_loadcert_f = cJSON_AddFalseToObject(root,"LoadCertStatus");
            printf("%s",gnutls_strerror(initRes));
            Insert_headpos_err(err_header,gnutls_strerror(initRes));
            cJSON* add_status_f = cJSON_AddFalseToObject(root,"status");
            if(!add_status_f){
                printf("%s,json:add false status to cert failed,exclude this cert from json file.\n",sha1);
                cJSON_Delete(root);
                free(sha1);
                free(pem);
                free_err_list(err_header);
                gnutls_x509_crt_deinit(cert);
                continue;
            }

            cJSON* err_list_json = serialize_err_list(err_header,sha1);
            if(err_list_json){
                cJSON_AddItemToObject(root,"errors",err_list_json);
            }else{
                cJSON* add_null_to_errs = cJSON_AddNullToObject(root,"errors");
                if(!add_null_to_errs){
                    printf("%s,json:add errors to cert failed,set errors as null failed,no errors in cert.\n",sha1);
                }
                printf("%s,json:add errors to cert failed,set errors as null.\n",sha1);
            }
            free_err_list(err_header);

            char *cert_json = cJSON_PrintUnformatted(root);
            if (fprintf(output, "%s\n",cert_json) < 0) {
                printf("%s: %s ,Json serialization success,file writing failed.%s\n",sha1,"Load Cert Failed",cert_json);
            }
            
            free(cert_json);
            cJSON_Delete(root);
            free(sha1);
            free(pem);
            gnutls_x509_crt_deinit(cert);
            continue;
        }
        cJSON* add_loadcert_t = cJSON_AddTrueToObject(root,"LoadCertStatus");
        // Parsing of the basic field Subject Issuer
        //1
        //func:gnutls_x509_crt_get_issuer_dn/gnutls_x509_crt_get_dn
        //description:The output subjcet and issuer fully comply with RFC4514
        char *issuer_buf = NULL; 
        size_t issuer_buf_size = 0;

        int issuer_res = gnutls_x509_crt_get_issuer_dn(cert, issuer_buf, &issuer_buf_size);
        if (issuer_res == GNUTLS_E_SHORT_MEMORY_BUFFER)
        {
            issuer_buf = malloc(issuer_buf_size);
            issuer_res = gnutls_x509_crt_get_issuer_dn(cert, issuer_buf, &issuer_buf_size);
            if (issuer_res != 0)
            {
                Insert_headpos_err(err_header,gnutls_strerror(issuer_res));
                free(issuer_buf);
                cJSON* add_issuer_null = cJSON_AddNullToObject(root, "issuer");
                if(!add_issuer_null){
                    printf("%s,json:Phrasing issuer failed,set issuer as null failed,no issuer in cert.\n",sha1);
                }
            }
        }else{
            Insert_headpos_err(err_header,gnutls_strerror(issuer_res));
            cJSON* add_issuer_null = cJSON_AddNullToObject(root, "issuer");
            if(!add_issuer_null){
                printf("%s,json:Phrasing issuer failed,set issuer as null failed,no issuer in cert.\n",sha1);
            }
        }
        if(issuer_res==0){
            cJSON* add_issuer = cJSON_AddStringToObject(root,"issuer", issuer_buf);
            if(!add_issuer){
                printf("%s,json:Phrasing issuer success,add str to cert failed,no issuer in cert.\n",sha1);
                issuer_res =-1;
            }
            free(issuer_buf);
            cJSON* add_issuer_status_t = cJSON_AddTrueToObject(root,"issuer_status");
        }else{
            cJSON* add_issuer_status_f = cJSON_AddFalseToObject(root,"issuer_status");
        }
        

        char *subject_buf = NULL; 
        size_t subject_buf_size = 0;

        int subject_res = gnutls_x509_crt_get_dn(cert, subject_buf, &subject_buf_size);
        if (subject_res == GNUTLS_E_SHORT_MEMORY_BUFFER)
        {
            subject_buf = malloc(subject_buf_size);
            subject_res = gnutls_x509_crt_get_dn(cert, subject_buf, &subject_buf_size);
            if (subject_res != 0)
            {
                Insert_headpos_err(err_header,gnutls_strerror(subject_res));
                free(subject_buf);
                cJSON* add_subject_null = cJSON_AddNullToObject(root, "subject");
                if(!add_subject_null){
                    printf("%s,json:Phrasing subject failed,set subject as null failed,no subject in cert.\n",sha1);
                }
            }
        }else{
            Insert_headpos_err(err_header,gnutls_strerror(subject_res));
            cJSON* add_subject_null = cJSON_AddNullToObject(root, "subject");
            if(!add_subject_null){
                printf("%s,json:Phrasing subject failed,set subject as null failed,no subject in cert.\n",sha1);
            }
        }
        if(subject_res==0){
            cJSON* add_subject = cJSON_AddStringToObject(root,"subject", subject_buf);
            if(!add_subject){
                printf("%s,json:Phrasing subject success,add str to cert failed,no subject in cert.\n",sha1);
                subject_res=-1;
            }
            free(subject_buf);
            cJSON* add_subject_status_t = cJSON_AddTrueToObject(root,"subject_status");
        }else{
            cJSON* add_subject_status_f = cJSON_AddFalseToObject(root,"subject_status");
        }

        //2 
        //func:gnutls_x509_crt_get_issuer_dn3/guntls_x509_crt_get_dn3 flags ==0
        //description:If flags==0, the output string fully complies with RFC4514
        gnutls_datum_t issuer_rfc4514_fully = {NULL,0};
        int issuer_rfc4514_fullyRes = gnutls_x509_crt_get_issuer_dn3(cert,&issuer_rfc4514_fully,0);
        if(issuer_rfc4514_fullyRes !=0){
            Insert_headpos_err(err_header,gnutls_strerror(issuer_rfc4514_fullyRes));
            cJSON* add_null_issuer_rfc4514_f = cJSON_AddNullToObject(root, "issuer_rfc4514_fully");
            if(!add_null_issuer_rfc4514_f){
                printf("%s,json:Phrasing issuer_rfc4514_fully failed,set issuer_rfc4514_fully as null failed,no issuer_rfc4514_fully in cert.\n",sha1);
            }
            cJSON* add_issuer_rfc4514_status_f = cJSON_AddFalseToObject(root,"issuer_rfc4514_status");
        }else{
            char* issuer_rfc4514_fully_tmp = (char*)issuer_rfc4514_fully.data;
            cJSON* add_issuer_rfc4514_f = cJSON_AddStringToObject(root,"issuer_rfc4514_fully", issuer_rfc4514_fully_tmp);
            if(!add_issuer_rfc4514_f){
                printf("%s,json:Phrasing issuer_rfc4514_fully success,add str to cert failed,no issuer_rfc4514_fully in cert.\n",sha1);
                issuer_rfc4514_fullyRes =-1;
            }
            gnutls_free(issuer_rfc4514_fully.data);
            cJSON* add_issuer_rfc4514_status_t = cJSON_AddTrueToObject(root,"issuer_rfc4514_status");
        }
        
        gnutls_datum_t subject_rfc4514_fully = {NULL,0};
        int subject_rfc4514_fullyRes = gnutls_x509_crt_get_dn3(cert,&subject_rfc4514_fully,0);
        if(subject_rfc4514_fullyRes !=0){
            Insert_headpos_err(err_header,gnutls_strerror(subject_rfc4514_fullyRes));
            cJSON* add_null_subject_rfc4514_f = cJSON_AddNullToObject(root, "subject_rfc4514_fully");
            if(!add_null_subject_rfc4514_f){
                printf("%s,json:Phrasing subject_rfc4514_fully failed,set subject_rfc4514_fully as null failed,no subject_rfc4514_fully in cert.\n",sha1);
            }
            cJSON* add_subject_rfc4514_status_f = cJSON_AddFalseToObject(root,"subject_rfc4514_status");
        }else{
            char* subject_rfc4514_fully_tmp = (char*)subject_rfc4514_fully.data;
            cJSON* add_subject_rfc4514_f = cJSON_AddStringToObject(root,"subject_rfc4514_fully", subject_rfc4514_fully_tmp);
            if(!add_subject_rfc4514_f){
                printf("%s,json:Phrasing subject_rfc4514_fully success,add str to cert failed,no subject_rfc4514_fully in cert.\n",sha1);
                subject_rfc4514_fullyRes =-1;
            }
            gnutls_free(subject_rfc4514_fully.data);
            cJSON* add_subject_rfc4514_status_t = cJSON_AddTrueToObject(root,"subject_rfc4514_status");
        }

        //3
        //func:gnutls_x509_crt_get_issuer_dn3/guntls_x509_crt_get_dn3 flags ==GNUTLS_X509_DN_FLAG_COMPAT
        //description:if flags ==GNUTLS_X509_DN_FLAG_COMPAT, the output string is a custom format in gnutls (partially following RFC4514)
        gnutls_datum_t issuer_rfc4514_compat = {NULL,0};
        int issuer_rfc4514_compatRes = gnutls_x509_crt_get_issuer_dn3(cert,&issuer_rfc4514_compat,GNUTLS_X509_DN_FLAG_COMPAT);
        if(issuer_rfc4514_compatRes !=0){
            Insert_headpos_err(err_header,gnutls_strerror(issuer_rfc4514_compatRes));
            cJSON* add_null_issuer_rfc4514_c = cJSON_AddNullToObject(root, "issuer_rfc4514_compat");
            if(!add_null_issuer_rfc4514_c){
                printf("%s,json:Phrasing issuer_rfc4514_compat failed,set issuer_rfc4514_compat as null failed,no issuer_rfc4514_compat in cert.\n",sha1);
            }
            cJSON* add_issuer_rfc4514c_status_f = cJSON_AddFalseToObject(root,"issuer_rfc4514c_status");
        }else{
            char* issuer_rfc4514_compat_tmp = (char*)issuer_rfc4514_compat.data;
            cJSON* add_issuer_rfc4514_c = cJSON_AddStringToObject(root,"issuer_rfc4514_compat", issuer_rfc4514_compat_tmp);
            if(!add_issuer_rfc4514_c){
                printf("%s,json:Phrasing issuer_rfc4514_compat success,add str to cert failed,no issuer_rfc4514_compat in cert.\n",sha1);
                issuer_rfc4514_compatRes =-1;
            }
            gnutls_free(issuer_rfc4514_compat.data);
            cJSON* add_issuer_rfc4514c_status_t = cJSON_AddTrueToObject(root,"issuer_rfc4514c_status");
        }
        
        gnutls_datum_t subject_rfc4514_compat = {NULL,0};
        int subject_rfc4514_compatRes = gnutls_x509_crt_get_dn3(cert,&subject_rfc4514_compat,GNUTLS_X509_DN_FLAG_COMPAT);
        if(subject_rfc4514_compatRes !=0){
            Insert_headpos_err(err_header,gnutls_strerror(subject_rfc4514_compatRes));
            cJSON* add_null_subject_rfc4514_c = cJSON_AddNullToObject(root, "subject_rfc4514_compat");
            if(!add_null_subject_rfc4514_c){
                printf("%s,json:Phrasing subject_rfc4514_compat failed,set subject_rfc4514_compat as null failed,no subject_rfc4514_compat in cert.\n",sha1);
            }
            cJSON* add_subject_rfc4514c_status_f = cJSON_AddFalseToObject(root,"subject_rfc4514c_status");
        }else{
            char* subject_rfc4514_compat_tmp = (char*)subject_rfc4514_compat.data;
            cJSON* add_subject_rfc4514_c = cJSON_AddStringToObject(root,"subject_rfc4514_compat", subject_rfc4514_compat_tmp);
            if(!add_subject_rfc4514_c){
                printf("%s,json:Phrasing subject_rfc4514_compat success,add str to cert failed,no subject_rfc4514_compat in cert.\n",sha1);
                subject_rfc4514_compatRes =-1;
            }
            gnutls_free(subject_rfc4514_compat.data);
            cJSON* add_subject_rfc4514c_status_t = cJSON_AddTrueToObject(root,"subject_rfc4514c_status");
        }

        int res_san = phrase_san(cert,root,err_header,sha1);
        int res_ian = phrase_ian(cert,root,err_header,sha1);
        int res_crl_disp = phrase_crl_disp(cert,root,err_header,sha1);
        int res_cp = phrase_cp(cert,root,err_header,sha1);

        cJSON* err_list_json = serialize_err_list(err_header,sha1);
        if(err_list_json){
            cJSON_AddItemToObject(root,"errors",err_list_json);
        }else{
            cJSON* add_null_to_errs = cJSON_AddNullToObject(root,"errors");
            if(!add_null_to_errs){
                printf("%s,json:add errors to cert failed,set errors as null failed,no errors in cert.\n",sha1);
            }
            printf("%s,json:add errors to cert failed,set errors as null.\n",sha1);
        }
        free_err_list(err_header);

        if(issuer_res==0&&subject_res==0&&res_cp==0&&res_san==0&&res_ian&&res_crl_disp==0&&err_list_json
        &&issuer_rfc4514_fullyRes==0&&subject_rfc4514_fullyRes==0
        &&issuer_rfc4514_compatRes==0&&subject_rfc4514_compatRes==0&&add_sha1){//Make sure that all other fields are processed successfully
            cJSON* add_status_t = cJSON_AddTrueToObject(root,"status");
            if(!add_status_t){
                printf("%s,json:add true status to cert failed,exclude this cert from json file.\n",sha1);
                cJSON_Delete(root);
                gnutls_x509_crt_deinit(cert);
                free(sha1);
                free(pem);
                continue;
            }
        }else{
            cJSON* add_status_f = cJSON_AddFalseToObject(root,"status");
            if(!add_status_f){
                printf("%s,json:add false status to cert failed,exclude this cert from json file.\n",sha1);
                cJSON_Delete(root);
                gnutls_x509_crt_deinit(cert);
                free(sha1);
                free(pem);
                continue;
            }
        }

        char *cert_json = cJSON_PrintUnformatted(root);

        if (fprintf(output, "%s\n",cert_json) < 0) {
            printf("%s: %s ,Json serialization success,file writing failed.%s\n",sha1,"Phrase success",cert_json);
        }
        
        free(cert_json);
        cJSON_Delete(root);
        gnutls_x509_crt_deinit(cert);
        free(sha1);
        free(pem);
    }
    return 0;
}