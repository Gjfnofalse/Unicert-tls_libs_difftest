#define _DEFAULT_SOURCE
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <cjson/cJSON.h>
# include <stdbool.h>
#include <openssl/err.h>

typedef struct errs//error list
{
    char* err_info;
    struct errs* next;
}errs;

void free_err_list(errs* head){
    if (head == NULL) return;
    errs* current = head;

    while (current != NULL) {
        errs* tmp = current;
        current = current->next;
        if(tmp->err_info){
            free(tmp->err_info);
        }
        free(tmp);
    }
}

cJSON* ser_errs_2json(){
    errs* err_header = malloc(sizeof(errs));
    err_header->err_info = NULL;
    err_header->next =NULL;
    errs* tailer = err_header;

    unsigned long getErrorCodeFromQueue = 1;
    while(getErrorCodeFromQueue !=0){
        getErrorCodeFromQueue = ERR_peek_error();//get openssl error code from stack
        if(getErrorCodeFromQueue==0){
            continue;
        }else{
            errs* err_tmp =malloc(sizeof(errs));
            err_tmp->err_info = malloc(1024);
            tailer->next = err_tmp;
            tailer = err_tmp;
            ERR_error_string_n(getErrorCodeFromQueue,err_tmp->err_info,1024);
            ERR_get_error();
        }
    }

    cJSON* err_list = cJSON_CreateArray();

    errs* current = err_header->next;
    while(current){
        cJSON_AddItemToArray(err_list,cJSON_CreateString(current->err_info));
        current = current->next;
    }
    free_err_list(err_header);
    return err_list;
}

X509 *PemStrToX509(const char* pemstr){
	BIO *bio = BIO_new_mem_buf((void*)pemstr, -1);
	
    X509 *x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);

    if (x509 == NULL) {
        BIO_free(bio);
        return NULL;
    }
    BIO_free(bio);
	return x509;
}

int main(int argc,char *argv[]) {
	if (argc !=3){
		printf("usage: %s: <input.json> <output.json>\n", argv[0]);
		return 1; 
	}

    FILE *file = fopen(argv[1], "r");
	FILE *output = fopen(argv[2], "a");
    if (!file) {
        printf("%s\n","Error opening input file.");
        return 1;
    }

	if (output == NULL) {
        printf("%s\n","Error opening output file.");
        return 1;
    }

    char line[4096]; 
    while (fgets(line, sizeof(line), file)) {
		int tail =0;
        char *end = strchr(line, '\n');
        if (end) *end = '\0';

        cJSON *json = cJSON_Parse(line);
		if(!json){
			printf("%s", "json:phrase json error {sha1,pem}.");
            continue; 
		}
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
        cJSON *FocusFieldItem = cJSON_GetObjectItem(json, "FocusField");
        cJSON *newFocusFieldItem = cJSON_CreateString(FocusFieldItem->valuestring);

        cJSON *FocusFieldValueItem = cJSON_GetObjectItem(json, "FocusFieldValue");
        cJSON *newFocusFieldValueItem = cJSON_CreateString(FocusFieldValueItem->valuestring);

        cJSON *InsertValueItem = cJSON_GetObjectItem(json, "InsertValue");
        cJSON *newInsertValueItem = cJSON_CreateString(InsertValueItem->valuestring);

        cJSON *DesItem = cJSON_GetObjectItem(json, "description");
        cJSON *newDesItem = cJSON_CreateString(DesItem->valuestring);

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
        
        X509* loadCert = PemStrToX509(pem);
        cJSON* root = cJSON_CreateObject();
        
        cJSON_AddItemToObject(root, "FocusField", newFocusFieldItem);
        cJSON_AddItemToObject(root, "FocusFieldValue", newFocusFieldValueItem);
        cJSON_AddItemToObject(root, "InsertValue", newInsertValueItem);
        cJSON_AddItemToObject(root, "description", newDesItem);
        cJSON_Delete(json);
        
        cJSON* add_sha1 = cJSON_AddStringToObject(root,"sha1",sha1);
        if(!add_sha1){
            printf("%s,json:add sha1 info to cert obj failed,no sha1 in cert.\n",sha1);
        }
        
        
        
        if(loadCert ==NULL){
            cJSON* add_loadcert_f = cJSON_AddFalseToObject(root,"LoadCertStatus");
            cJSON* err_list_json = ser_errs_2json();
            cJSON_AddItemToObject(root,"errors",err_list_json);

            cJSON* add_status_f = cJSON_AddFalseToObject(root,"status");
            if(!add_status_f){
                printf("%s,json:add false status to cert failed,exclude this cert from json file.\n",sha1);
                cJSON_Delete(root);
                
                free(sha1);
                free(pem);
                continue;
            }

            char *cert_json = cJSON_PrintUnformatted(root);
            if (fprintf(output, "%s\n",cert_json) < 0) {
                printf("%s: %s ,json:Json serialization success,file writing failed.%s\n",sha1,"Phrase success",cert_json);
            }
            fflush(output);
            free(cert_json);
            cJSON_Delete(root);
            
            free(sha1);
            free(pem);
            continue;
        }else{
            cJSON* add_loadcert_t = cJSON_AddTrueToObject(root,"LoadCertStatus");
            // 1. Subject Issuer
            // ref：https://www.openssl.org/docs/man3.3/man3/X509_NAME_oneline.html
            // deprecated
            int Subject_oneline_res = 0;
            char *Subject_oneline = X509_NAME_oneline(X509_get_subject_name(loadCert), NULL, 0);
            if(Subject_oneline){
                cJSON* add_subject_oneline = cJSON_AddStringToObject(root,"SubjectOneline",Subject_oneline);
                if(!add_subject_oneline){
                    cJSON* add_subject_oneline_status_f1 = cJSON_AddFalseToObject(root,"subject_oneline_status");
                    Subject_oneline_res = 1;
                    printf("%s,json:Parsing SubjectOneline success,add SubjectOneline to cert failed,no SubjectOneline in cert.\n",sha1);
                }else{
                    cJSON* add_subject_oneline_status_t = cJSON_AddTrueToObject(root,"subject_oneline_status");
                }
                free(Subject_oneline);
            }else{
                cJSON* add_subject_oneline_status_f = cJSON_AddFalseToObject(root,"subject_oneline_status");
                Subject_oneline_res = 1;
                cJSON* add_subject_oneline_null = cJSON_AddNullToObject(root,"SubjectOneline");
                if(!add_subject_oneline_null){
                    printf("%s,json:Parsing SubjectOneline failed,set SubjectOneline as null failed,no SubjectOneline in cert.\n",sha1);
                }
            }

            int Issuer_oneline_res = 0;
            char *Issuer_oneline = X509_NAME_oneline(X509_get_issuer_name(loadCert), NULL, 0);
            if(Issuer_oneline){
                cJSON* add_issuer_oneline = cJSON_AddStringToObject(root,"IssuerOneline",Issuer_oneline);
                if(!add_issuer_oneline){
                    cJSON* add_issuer_oneline_status_f1 = cJSON_AddFalseToObject(root,"issuer_oneline_status");
                    Issuer_oneline_res = 1;
                    printf("%s,json:Parsing IssuerOneline success,add IssuerOneline to cert failed,no IssuerOneline in cert.\n",sha1);
                }else{
                    cJSON* add_issuer_oneline_status_t = cJSON_AddTrueToObject(root,"issuer_oneline_status");
                }
                free(Issuer_oneline);
            }else{
                cJSON* add_issuer_oneline_status_f = cJSON_AddFalseToObject(root,"issuer_oneline_status");
                Issuer_oneline_res = 1;
                cJSON* add_issuer_oneline_null = cJSON_AddNullToObject(root,"IssuerOneline");
                if(!add_issuer_oneline_null){
                    printf("%s,json:Parsing IssuerOneline failed,set IssuerOneline as null failed,no IssuerOneline in cert.\n",sha1);
                }
            }

            // 1.2 X509_NAME_print
            //deprecated
            int BIO_res = 0;
            BIO *tmpsave = BIO_new(BIO_s_mem());
            if(tmpsave ==NULL){
                cJSON* add_bio_status_f = cJSON_AddFalseToObject(root,"bio_status");
                BIO_res =1;
                printf("%s,openssl/BIO:Create bio for parsing remaing two format subject/Issuer strs failed,next json str.\n",sha1);

                cJSON* add_status_f = cJSON_AddFalseToObject(root,"status");
                if(!add_status_f){
                    printf("%s,json:add false status to cert failed,exclude this cert from json file.\n",sha1);
                }
                //add err
                cJSON* err_list = ser_errs_2json();
                cJSON_AddItemToObject(root,"errors",err_list);

                char *cert_json = cJSON_PrintUnformatted(root);
                if (fprintf(output, "%s\n",cert_json) < 0) {
                    printf("%s: %s ,json:Json serialization success,file writing failed.%s\n",sha1,"Phrase success",cert_json);
                }
                fflush(output);
                free(cert_json);
                cJSON_Delete(root);
                X509_free(loadCert);
                free(sha1);
                free(pem);
                continue;
            }
            cJSON* add_bio_status_t = cJSON_AddTrueToObject(root,"bio_status"); 

            int Subject_res =0;
            int retSubject = X509_NAME_print(tmpsave, X509_get_subject_name(loadCert), 0);
            if (retSubject==1){
                long subject_len = BIO_pending(tmpsave);
                char *subject_bio_str = (char*)malloc(subject_len + 1);
                size_t readBytes_num = 0;
                int readBytes = BIO_read_ex(tmpsave, subject_bio_str, subject_len,&readBytes_num);
                if (readBytes==0){
                    Subject_res = 1;
                    cJSON* add_subject_null = cJSON_AddNullToObject(root,"Subject");
                    if(!add_subject_null){
                        printf("%s,openssl/BIO:Parsing Subject success,read bytes from bio failed,set Subject as null failed,no Subject in cert.\n",sha1);
                    }
                }else{
                    subject_bio_str[subject_len] = '\0';
                    cJSON* add_subject = cJSON_AddStringToObject(root,"Subject",subject_bio_str);
                    if(!add_subject){
                        Subject_res = 1;
                        printf("%s,json:Parsing Subject success,add Subject to cert failed,no Subject in cert.\n",sha1);
                    }
                }
                free(subject_bio_str);
                BIO_reset(tmpsave);
            }else{
                Subject_res = 1;
                BIO_reset(tmpsave);
                cJSON* add_subject_null = cJSON_AddNullToObject(root,"Subject");
                if(!add_subject_null){
                    printf("%s,openssl:Parsing Subject failed,set Subject as null failed,no Subject in cert.\n",sha1);
                }
            }
            
            int Issuer_res = 0;
            int retIssuer = X509_NAME_print(tmpsave, X509_get_issuer_name(loadCert), 0);
            if (retIssuer==1){
                long issuer_len = BIO_pending(tmpsave);
                char *issuer_bio_str = (char*)malloc(issuer_len + 1);
                size_t readBytes_num = 0;
                int readBytes = BIO_read_ex(tmpsave, issuer_bio_str, issuer_len,&readBytes_num);
                if (readBytes==0){
                    Issuer_res = 1;
                    cJSON* add_issuer_null = cJSON_AddNullToObject(root,"Issuer");
                    if(!add_issuer_null){
                        printf("%s,openssl/BIO:Parsing Issuer success,read bytes from bio failed,set Issuer as null failed,no Issuer in cert.\n",sha1);
                    }
                }else{
                    issuer_bio_str[issuer_len] = '\0';
                    cJSON* add_issuer = cJSON_AddStringToObject(root,"Issuer",issuer_bio_str);
                    if(!add_issuer){
                        Issuer_res = 1;
                        printf("%s,json:Parsing Issuer success,add Issuer to cert failed,no Issuer in cert.\n",sha1);
                    }
                }
                free(issuer_bio_str);
                BIO_reset(tmpsave);
            }else{
                Issuer_res = 1;
                BIO_reset(tmpsave);
                cJSON* add_issuer_null = cJSON_AddNullToObject(root,"Issuer");
                if(!add_issuer_null){
                    printf("%s,openssl:Parsing Issuer failed,set Issuer as null failed,no Issuer in cert.\n",sha1);
                }
            }

            // 1.3 X509_NAME_print_ex,
            // “for most purposes XN_FLAG_ONELINE, XN_FLAG_MULTILINE or XN_FLAG_RFC2253 will suffice. ”
            int Subject_ex_res = 0;
            int retSubject_ex = X509_NAME_print_ex(tmpsave,X509_get_subject_name(loadCert),0,XN_FLAG_RFC2253);
            if (retSubject_ex!=-1){
                long subject_ex_len = BIO_pending(tmpsave);
                char *subject_ex_str = (char*)malloc(subject_ex_len + 1);
                size_t readBytes_num = 0;
                int readBytes_Subject_ex = BIO_read_ex(tmpsave, subject_ex_str, subject_ex_len,&readBytes_num);
                if (readBytes_Subject_ex==0){
                    Subject_ex_res = 1;
                    cJSON* add_subject_ex_null = cJSON_AddNullToObject(root,"Subject_RFC2253");
                    if(!add_subject_ex_null){
                        printf("%s,openssl/BIO:Parsing Subject_RFC2253 success,read bytes from bio failed,set Subject_RFC2253 as null failed,no Subject_RFC2253 in cert.\n",sha1);
                    }
                }else{
                    subject_ex_str[subject_ex_len] = '\0';
                    cJSON* add_subject_ex = cJSON_AddStringToObject(root,"Subject_RFC2253",subject_ex_str);
                    if(!add_subject_ex){
                        Subject_ex_res = 1;
                        printf("%s,json:Parsing Subject_RFC2253 success,add Subject_RFC2253 to cert failed,no Subject_RFC2253 in cert.\n",sha1);
                    }
                }
                free(subject_ex_str);
                BIO_reset(tmpsave);
            }else{
                Subject_ex_res = 1;
                BIO_reset(tmpsave);
                cJSON* add_subject_ex_null = cJSON_AddNullToObject(root,"Subject_RFC2253");
                if(!add_subject_ex_null){
                    printf("%s,openssl:Parsing Subject_RFC2253 failed,set Subject_RFC2253 as null failed,no Subject_RFC2253 in cert.\n",sha1);
                }
            }

            int Issuer_ex_res = 0;
            int retIssuer_ex = X509_NAME_print_ex(tmpsave,X509_get_issuer_name(loadCert),0,XN_FLAG_RFC2253);
            if (retIssuer_ex != -1){
                long issuer_ex_len = BIO_pending(tmpsave);
                char *issuer_ex_str = (char*)malloc(issuer_ex_len + 1);
                size_t readBytes_num = 0;
                int readBytes_Issuer_ex = BIO_read_ex(tmpsave, issuer_ex_str, issuer_ex_len,&readBytes_num);
                if (readBytes_Issuer_ex==0){
                    Issuer_ex_res = 1;
                    cJSON* add_issuer_ex_null = cJSON_AddNullToObject(root,"Issuer_RFC2253");
                    if(!add_issuer_ex_null){
                        printf("%s,openssl/BIO:Parsing Issuer_RFC2253 success,read bytes from bio failed,set Issuer_RFC2253 as null failed,no Issuer_RFC2253 in cert.\n",sha1);
                    }
                }else{
                    issuer_ex_str[issuer_ex_len] = '\0';
                    cJSON* add_issuer_ex = cJSON_AddStringToObject(root,"Issuer_RFC2253",issuer_ex_str);
                    if(!add_issuer_ex){
                        Issuer_ex_res =1;
                        printf("%s,json:Parsing Issuer_RFC2253 success,add Issuer_RFC2253 to cert failed,no Issuer_RFC2253 in cert.\n",sha1);
                    }
                }
                free(issuer_ex_str);
                BIO_free_all(tmpsave);
            }else{
                Issuer_ex_res = 1;
                BIO_free_all(tmpsave);
                cJSON* add_issuer_ex_null = cJSON_AddNullToObject(root,"Issuer_RFC2253");
                if(!add_issuer_ex_null){
                    printf("%s,openssl:Parsing Issuer_RFC2253 failed,set Issuer_RFC2253 as null failed,no Issuer_RFC2253 in cert.\n",sha1);
                }
            }
            
            cJSON* err_list = ser_errs_2json();
            cJSON_AddItemToObject(root,"errors",err_list);

            if(Subject_res==0){
                cJSON* add_subject_status_t = cJSON_AddTrueToObject(root,"subject_status");
            }else{
                cJSON* add_subject_status_f = cJSON_AddFalseToObject(root,"subject_status");
            }

            if(Issuer_res==0){
                cJSON* add_issuer_t = cJSON_AddTrueToObject(root,"issuer_status");
            }else{
                cJSON* add_issuer_f = cJSON_AddFalseToObject(root,"issuer_status");
            }

            if(Subject_ex_res==0){
                cJSON* add_subject_rfc2253_status_t = cJSON_AddTrueToObject(root,"subject_rfc2253_status");
            }else{
                cJSON* add_subject_rfc2253_status_f = cJSON_AddFalseToObject(root,"subject_rfc2253_status");
            }

            if(Issuer_ex_res==0){
                cJSON* add_issuer_rfc2253_status_t = cJSON_AddTrueToObject(root,"issuer_rfc2253_status");
            }else{
                cJSON* add_issuer_rfc2253_status_f = cJSON_AddFalseToObject(root,"issuer_rfc2253_status");
            }

            if(add_sha1&&Subject_ex_res==0&&Issuer_ex_res==0
            &&Subject_res==0&&Issuer_res==0&&Subject_oneline_res==0&&Issuer_oneline_res==0){
                cJSON* add_status_t = cJSON_AddTrueToObject(root,"status");
                if(!add_status_t){
                    printf("%s,json:Add true status to cert failed,no status in cert.\n",sha1);
                }
            }else{
                cJSON* add_status_f = cJSON_AddFalseToObject(root,"status");
                if(!add_status_f){
                    printf("%s,json:Add false status to cert failed,no status in cert.\n",sha1);
                }
            }

            char *cert_json = cJSON_PrintUnformatted(root);

            if (fprintf(output, "%s\n",cert_json) < 0) {
                printf("%s: %s ,json:Json serialization success,file writing failed.%s\n",sha1,"Phrase success",cert_json);
            }

            fflush(output);

            free(cert_json);
            cJSON_Delete(root);
            X509_free(loadCert);
            free(sha1);
            free(pem);
        }
    }
    fclose(file);
    fclose(output);
    return 0; 
}
