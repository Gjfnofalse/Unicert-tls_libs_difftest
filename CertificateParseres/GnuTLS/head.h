#define _DEFAULT_SOURCE
#include <stdio.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <cjson/cJSON.h>
#include <stdbool.h>
#include <gnutls/x509-ext.h>

//0. err
typedef struct err{
    const char* data;
    struct err* next;
}err;
void Insert_headpos_err(err* header,const char* data);
cJSON* serialize_err_list(err* err_list,const char* sha1);

//1.dn
typedef struct mydn{
    char* CN;
}mydn;

//2.san
typedef struct san_entry{
    char* value;
    const char* type;
}san_entry;

//generalName
typedef struct sanNode{
    san_entry* data;
    struct sanNode* next;
}sanNode;

const char* reflact_number_to_str(gnutls_x509_subject_alt_name_t GeneralNameClass);

int san_typenums_to_boolean(int type);

cJSON* serializeList(sanNode* head,const char* sha1);
int phrase_san(gnutls_x509_crt_t cert,cJSON* root,err* err_list,const char* sha1);
int phrase_ian(gnutls_x509_crt_t cert,cJSON* root,err* err_list,const char* sha1);

//3.certPolicies
typedef struct qualifier{
    char* data;
    const char* type; //cpsurior usernotice
    struct qualifier* next;
}qualifier;

typedef struct policy_information{
    char* policy_identifier;
    qualifier* policy_qualifiers;
}policy_information;

typedef struct cert_policies{
    policy_information* data;
    struct cert_policies* next;
}cert_policies;

cJSON* cert_policies_to_json(cert_policies* head,char* sha1);

const char* num_to_cp_qualifier_type(gnutls_x509_qualifier_t type_num);
int phrase_cp(gnutls_x509_crt_t cert,cJSON* root,err* err_list,char* sha1);

//4. CRLDisTributionPoints
typedef struct disp{
    char* data;
    const char* type;//generalName type
    // const char* reasonflag; 
}disp;

typedef struct crl_disp{//CRLDistributionPoints
    disp* data;
    struct crl_disp* next;
}crl_disp;

cJSON* serialize_disp(disp* entry,char* sha1);
cJSON* serialize_crl_disp_list(crl_disp* head,char* sha1);
int phrase_crl_disp(gnutls_x509_crt_t cert,cJSON* root,err* err_list,char* sha1);
const char* reflact_num_to_str_crl_disp(int num);

//5. aia
typedef struct access_description{//access_description
    unsigned char* oid;//OID->access_method
    unsigned char* type;//generalName type
    unsigned char* uri;//URI is the only type that gnutls3.7.11 can handle
    unsigned char* unknown_data;
}access_description;

typedef struct aia{//CRLDistributionPoints
    access_description* data;
    struct aia* next;
}aia;

//6. free
void free_san_list(sanNode* head);
void free_crl_disp_list(crl_disp* head);
void free_err_list(err* head);
void free_policy_information(policy_information *pi);
void free_cert_policies(cert_policies *cp);