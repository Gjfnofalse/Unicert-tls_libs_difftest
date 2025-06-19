import json
import sys
import copy

dir_path = sys.argv[1]
output_path =sys.argv[2]

from DencodingCheckHelper import set_deduced_decoding,ASN1_list,FindAllCharlistsInDict,DN,save_info
from DecodingDetection import DecodingDetector,get_info

OpenSSLEncoding = {
    "Lib":"OpenSSL@V3.3.0",
    "SubjectOneline":{},
    "Subject":{},
    "SubjectRFC2253":{},
    "IssuerOneline":{},
    "Issuer":{},
    "IssuerRFC2253":{},
}

for itm in DN:
    OpenSSLEncoding["IssuerOneline"][itm] = {}
    OpenSSLEncoding["Issuer"][itm] = {}
    OpenSSLEncoding["IssuerRFC2253"][itm] = {}
    OpenSSLEncoding["SubjectOneline"][itm] = {}
    OpenSSLEncoding["Subject"][itm] = {}
    OpenSSLEncoding["SubjectRFC2253"][itm] = {}
    for ASN1 in ASN1_list:
        OpenSSLEncoding["IssuerOneline"][itm][ASN1] =copy.deepcopy(save_info)
        OpenSSLEncoding["Issuer"][itm][ASN1] =copy.deepcopy(save_info)
        OpenSSLEncoding["IssuerRFC2253"][itm][ASN1] =copy.deepcopy(save_info)
        OpenSSLEncoding["SubjectOneline"][itm][ASN1] = copy.deepcopy(save_info)
        OpenSSLEncoding["Subject"][itm][ASN1] = copy.deepcopy(save_info)
        OpenSSLEncoding["SubjectRFC2253"][itm][ASN1] = copy.deepcopy(save_info)

# Get Name ParsedValue Prefix
dn_rlt = {'2.5.4.15': 'businessCategory', 
        '2.5.4.3': 'CN', 
        '2.5.4.46': 'dnQualifier', 
        '0.9.2342.19200300.100.1.25': 'DC', 
        '1.2.840.113549.1.9.1': 'emailAddress', 
        '2.5.4.44': 'generationQualifier', 
        '2.5.4.42': 'GN', 
        '2.5.4.43': 'initials', 
        '1.2.643.3.131.1.1': 'INN',  
        '1.3.6.1.4.1.311.60.2.1.1': 'jurisdictionL', 
        '1.3.6.1.4.1.311.60.2.1.2': 'jurisdictionST', 
        '2.5.4.7': 'L', 
        '1.2.643.100.1': 'OGRN', 
        '2.5.4.11': 'OU', 
        '2.5.4.97': 'organizationIdentifier', 
        '2.5.4.10': 'O', 
        '2.5.4.16': 'postalAddress', 
        '2.5.4.17': 'postalCode', 
        '2.5.4.65': 'pseudonym', 
        '2.5.4.5': 'serialNumber', 
        '1.2.643.100.3': 'SNILS', 
        '2.5.4.8': 'ST', 
        '2.5.4.9': 'street', 
        '2.5.4.4': 'SN', 
        '2.5.4.12': 'title', 
        '1.2.840.113549.1.9.2': 'unstructuredName', 
        '0.9.2342.19200300.100.1.1': 'UID', 
        }

with open(dir_path+"/output_c_openssl.json",'r') as file:
    for line in file:
        json_obj = json.loads(line)
        FocusField = json_obj["FocusField"]
        FocusFieldValue = json_obj["FocusFieldValue"]
        InsertValue = json_obj["InsertValue"]
        FocusFieldSlices = FocusField.split(" ")
        
        if FocusField.startswith("Subject"):
            if json_obj["subject_oneline_status"] ==True:
                decodingM = DecodingDetector(FocusFieldSlices[2],FocusFieldValue,json_obj["SubjectOneline"],"/"+dn_rlt[FocusFieldSlices[1]]+"=","")
                get_info(OpenSSLEncoding["SubjectOneline"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue,decodingM)
            else:
                OpenSSLEncoding["SubjectOneline"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)

            if json_obj["bio_status"] == False:
                OpenSSLEncoding["Subject"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
                OpenSSLEncoding["SubjectRFC2253"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
            else:
                if json_obj["subject_status"] == True:
                    decodingM = DecodingDetector(FocusFieldSlices[2],FocusFieldValue,json_obj["Subject"],dn_rlt[FocusFieldSlices[1]]+"=","")
                    get_info(OpenSSLEncoding["Subject"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue,decodingM)
                else:
                    OpenSSLEncoding["Subject"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)

                if json_obj["subject_rfc2253_status"] == True:
                    decodingM = DecodingDetector(FocusFieldSlices[2],FocusFieldValue,json_obj["Subject_RFC2253"],dn_rlt[FocusFieldSlices[1]]+"=","")
                    get_info(OpenSSLEncoding["SubjectRFC2253"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue,decodingM)
                else:
                    OpenSSLEncoding["SubjectRFC2253"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
        
        if FocusField.startswith("Issuer"):
            if json_obj["issuer_oneline_status"] ==True:
                decodingM = DecodingDetector(FocusFieldSlices[2],FocusFieldValue,json_obj["IssuerOneline"],"/"+dn_rlt[FocusFieldSlices[1]]+"=","")
                get_info(OpenSSLEncoding["IssuerOneline"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue,decodingM)
            else:
                OpenSSLEncoding["IssuerOneline"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)

            if json_obj["bio_status"] == False:
                OpenSSLEncoding["Issuer"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
                OpenSSLEncoding["IssuerRFC2253"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
            else:
                if json_obj["issuer_status"] == True:
                    decodingM = DecodingDetector(FocusFieldSlices[2],FocusFieldValue,json_obj["Issuer"],dn_rlt[FocusFieldSlices[1]]+"=","")
                    get_info(OpenSSLEncoding["Issuer"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue,decodingM)
                else:
                    OpenSSLEncoding["Issuer"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)

                if json_obj["issuer_rfc2253_status"] == True:
                    decodingM = DecodingDetector(FocusFieldSlices[2],FocusFieldValue,json_obj["Issuer_RFC2253"],dn_rlt[FocusFieldSlices[1]]+"=","")
                    get_info(OpenSSLEncoding["IssuerRFC2253"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue,decodingM)
                else:
                    OpenSSLEncoding["IssuerRFC2253"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
                    
OpenSSLPaths = FindAllCharlistsInDict(OpenSSLEncoding)

for OpenSSLPath in OpenSSLPaths:
    set_deduced_decoding(OpenSSLEncoding,OpenSSLPath)

OpenSSLStr = json.dumps(OpenSSLEncoding,indent=4)

with open(output_path+"/DecodingTestOpenSSL.json",'a') as file:
    file.write(OpenSSLStr+'\n')

