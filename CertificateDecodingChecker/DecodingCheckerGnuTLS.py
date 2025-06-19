import json
import sys
import copy

dir_path = sys.argv[1]
output_path =sys.argv[2]

from DencodingCheckHelper import set_deduced_decoding,ASN1_list,FindAllCharlistsInDict,DN,save_info
from DecodingDetection import DecodingDetector,get_info


#Get DN Prefix
gnutls_dn_rlt_t = {'2.5.4.15': ['businessCategory',0], 
        '2.5.4.3': ['CN',0], 
        '2.5.4.46': ['dnQualifier',1], 
        '0.9.2342.19200300.100.1.25': ['DC',1], 
        '1.2.840.113549.1.9.1': ['emailAddress',1], 
        '2.5.4.44': ['generationQualifier',0], 
        '2.5.4.42': ['givenName',0], 
        '2.5.4.43': ['initials',0], 
        '1.2.643.3.131.1.1': ['INN',1],  
        '1.3.6.1.4.1.311.60.2.1.1': ['jurisdictionOfIncorporationLocalityName',0], 
        '1.3.6.1.4.1.311.60.2.1.2': ['jurisdictionOfIncorporationStateOrProvinceName',0], 
        '2.5.4.7': ['L',0], 
        '1.2.643.100.1': ['OGRN',1], 
        '2.5.4.11': ['OU',0], 
        '2.5.4.97': ['organizationIdentifier',1], 
        '2.5.4.10': ['O',0], 
        '2.5.4.16': ['postalAddress',1], 
        '2.5.4.17': ['postalCode',0], 
        '2.5.4.65': ['pseudonym',0], 
        '2.5.4.5': ['serialNumber',1], 
        '1.2.643.100.3': ['SNILS',1], 
        '2.5.4.8': ['ST',0], 
        '2.5.4.9': ['street',0], 
        '2.5.4.4': ['surName',0], 
        '2.5.4.12': ['title',0], 
        '1.2.840.113549.1.9.2': ['unstructuredName',1], 
        '0.9.2342.19200300.100.1.1': ['UID',0], 
        }

GnuTLSEncoding = {
    "Lib":"GnuTLS@V3.7.11",
    "SubjectRFC4514F":{},
    "SubjectRFC4514F1":{},
    "SubjectRFC4514C":{},
    "IssuerRFC4514F":{},
    "IssuerRFC4514F1":{},
    "IssuerRFC4514C":{},
    "SubjectAlternativeName":{"DNSName":copy.deepcopy(save_info),"URI":copy.deepcopy(save_info),"RFC822Name":copy.deepcopy(save_info)},
    "IssuerAlternativeName":{"DNSName":copy.deepcopy(save_info),"URI":copy.deepcopy(save_info),"RFC822Name":copy.deepcopy(save_info)},
    "CRLDistributionPoints":{"fullname":{"DNSName":copy.deepcopy(save_info),"URI":copy.deepcopy(save_info),"RFC822Name":copy.deepcopy(save_info)}}
}

for itm in DN:
    GnuTLSEncoding["IssuerRFC4514F"][itm] = {}
    GnuTLSEncoding["IssuerRFC4514F1"][itm] = {}
    GnuTLSEncoding["IssuerRFC4514C"][itm] = {}
    GnuTLSEncoding["SubjectRFC4514F"][itm] = {}
    GnuTLSEncoding["SubjectRFC4514F1"][itm] = {}
    GnuTLSEncoding["SubjectRFC4514C"][itm] = {}
    for ASN1 in ASN1_list:
        GnuTLSEncoding["IssuerRFC4514F"][itm][ASN1] = copy.deepcopy(save_info)
        GnuTLSEncoding["IssuerRFC4514F1"][itm][ASN1] = copy.deepcopy(save_info)
        GnuTLSEncoding["IssuerRFC4514C"][itm][ASN1] = copy.deepcopy(save_info)
        GnuTLSEncoding["SubjectRFC4514F"][itm][ASN1] = copy.deepcopy(save_info)
        GnuTLSEncoding["SubjectRFC4514F1"][itm][ASN1] = copy.deepcopy(save_info)
        GnuTLSEncoding["SubjectRFC4514C"][itm][ASN1] = copy.deepcopy(save_info)

with open(dir_path+"/output_c_gnutls.json",'r') as file:
    for line in file:
        json_obj = json.loads(line)
        FocusField = json_obj["FocusField"]
        FocusFieldValue = json_obj["FocusFieldValue"]
        InsertValue = json_obj["InsertValue"]
        FocusFieldSlices = FocusField.split(" ")

        if FocusField.startswith("Subject"):
            if json_obj["subject_status"] ==True:
                if gnutls_dn_rlt_t[FocusFieldSlices[1]][1] ==1:
                    pass
                else:
                    decodingM = DecodingDetector(FocusFieldSlices[2],FocusFieldValue,json_obj["subject"],gnutls_dn_rlt_t[FocusFieldSlices[1]][0]+"=","")
                    get_info(GnuTLSEncoding["SubjectRFC4514F"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue,decodingM)
            else:
                GnuTLSEncoding["SubjectRFC4514F"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)

            if json_obj["subject_rfc4514_status"] ==True:
                if gnutls_dn_rlt_t[FocusFieldSlices[1]][1] ==1:#Identify whether the current field is parsed or not
                    pass
                else:
                    decodingM = DecodingDetector(FocusFieldSlices[2],FocusFieldValue,json_obj["subject_rfc4514_fully"],gnutls_dn_rlt_t[FocusFieldSlices[1]][0]+"=","")
                    get_info(GnuTLSEncoding["SubjectRFC4514F1"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue,decodingM)
            else:
                GnuTLSEncoding["SubjectRFC4514F1"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)

            if json_obj["subject_rfc4514c_status"] ==True:
                if gnutls_dn_rlt_t[FocusFieldSlices[1]][1] ==1:
                    pass
                else:
                    decodingM = DecodingDetector(FocusFieldSlices[2],FocusFieldValue,json_obj["subject_rfc4514_compat"],gnutls_dn_rlt_t[FocusFieldSlices[1]][0]+"=","")
                    get_info(GnuTLSEncoding["SubjectRFC4514C"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue,decodingM)
            else:
                GnuTLSEncoding["SubjectRFC4514C"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
        
        if FocusField.startswith("Issuer"):
            if json_obj["issuer_status"] ==True:
                if gnutls_dn_rlt_t[FocusFieldSlices[1]][1] ==1:
                    pass
                else:
                    decodingM = DecodingDetector(FocusFieldSlices[2],FocusFieldValue,json_obj["issuer"],gnutls_dn_rlt_t[FocusFieldSlices[1]][0]+"=","")
                    get_info(GnuTLSEncoding["IssuerRFC4514F"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue,decodingM)
            else:
                GnuTLSEncoding["IssuerRFC4514F"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)

            if json_obj["issuer_rfc4514_status"] ==True:
                if gnutls_dn_rlt_t[FocusFieldSlices[1]][1] ==1:
                    pass
                else:
                    decodingM = DecodingDetector(FocusFieldSlices[2],FocusFieldValue,json_obj["issuer_rfc4514_fully"],gnutls_dn_rlt_t[FocusFieldSlices[1]][0]+"=","")
                    get_info(GnuTLSEncoding["IssuerRFC4514F1"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue,decodingM)
            else:
                GnuTLSEncoding["IssuerRFC4514F1"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)

            if json_obj["issuer_rfc4514c_status"] ==True:
                if gnutls_dn_rlt_t[FocusFieldSlices[1]][1] ==1:
                    pass
                else:
                    decodingM = DecodingDetector(FocusFieldSlices[2],FocusFieldValue,json_obj["issuer_rfc4514_compat"],gnutls_dn_rlt_t[FocusFieldSlices[1]][0]+"=","")
                    get_info(GnuTLSEncoding["IssuerRFC4514C"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue,decodingM)
            else:
                GnuTLSEncoding["IssuerRFC4514C"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)

        if FocusFieldSlices[0] == "SAN":
            if FocusFieldSlices[1] == "DirectoryName":
                pass
            else:
                if json_obj["status"]==False:
                    GnuTLSEncoding["SubjectAlternativeName"][FocusFieldSlices[1]]["parsing_failed"].add(InsertValue)
                else:
                    decodingM = DecodingDetector("UTF8String",FocusFieldValue,json_obj["SAN"][0]["value"],"","")
                    get_info(GnuTLSEncoding["SubjectAlternativeName"][FocusFieldSlices[1]],InsertValue,decodingM)
        
        if FocusFieldSlices[0] == "IAN":
            if FocusFieldSlices[1] == "DirectoryName":
                pass
            else:
                if json_obj["status"]==False:
                    GnuTLSEncoding["IssuerAlternativeName"][FocusFieldSlices[1]]["parsing_failed"].add(InsertValue)
                else:
                    decodingM = DecodingDetector("UTF8String",FocusFieldValue,json_obj["IAN"][0]["value"],"","")
                    get_info(GnuTLSEncoding["IssuerAlternativeName"][FocusFieldSlices[1]],InsertValue,decodingM)
                
        if FocusFieldSlices[0] == "CRL":
            #Gnutls CRL only parses fullname
            if FocusFieldSlices[1] =="fullname":
                if FocusFieldSlices[2] =="DirectoryName":
                    pass
                else:
                    if json_obj["status"] ==False:
                        GnuTLSEncoding["CRLDistributionPoints"]["fullname"][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
                    else:
                        decodingM = DecodingDetector("UTF8String",FocusFieldValue,json_obj["CRLDistributionPoints"][0]["distributionPoint"],"","")
                        get_info(GnuTLSEncoding["CRLDistributionPoints"]["fullname"][FocusFieldSlices[2]],InsertValue,decodingM)

            elif FocusFieldSlices[1] =="RDN":
                pass
            elif FocusFieldSlices[1] == "crlissuer":
                pass
            
GnuTLSPaths = FindAllCharlistsInDict(GnuTLSEncoding)

for GnuTLSPath in GnuTLSPaths:
    set_deduced_decoding(GnuTLSEncoding,GnuTLSPath)

GnuTLSStr = json.dumps(GnuTLSEncoding,indent=4)

with open(output_path+'/DecodingTestGnuTLS.json','a') as file:
    file.write(GnuTLSStr+'\n')