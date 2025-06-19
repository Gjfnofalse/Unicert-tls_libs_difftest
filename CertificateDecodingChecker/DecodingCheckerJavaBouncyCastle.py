import json
import sys
import copy
dir_path = sys.argv[1]
output_path =sys.argv[2]

from DencodingCheckHelper import set_deduced_decoding,ASN1_list,FindAllCharlistsInDict,DN,save_info
from DecodingDetection import DecodingDetector,get_info

BouncyCastleEncoding = {
    "Lib":"BouncyCastle@V1.78.1",
    "Subject":{},
    "SubjectRDN":{},
    "Issuer":{},
    "IssuerRDN":{}
}

for itm in DN:
    BouncyCastleEncoding["Issuer"][itm] = {}
    BouncyCastleEncoding["IssuerRDN"][itm] = {}
    BouncyCastleEncoding["Subject"][itm] = {}
    BouncyCastleEncoding["SubjectRDN"][itm] = {}
    for ASN1 in ASN1_list:
        BouncyCastleEncoding["Issuer"][itm][ASN1] = copy.deepcopy(save_info)
        BouncyCastleEncoding["IssuerRDN"][itm][ASN1] = copy.deepcopy(save_info)
        BouncyCastleEncoding["Subject"][itm][ASN1] = copy.deepcopy(save_info)
        BouncyCastleEncoding["SubjectRDN"][itm][ASN1] = copy.deepcopy(save_info)

# Get DN ParsedValue Prefix.
bc_dn_prefix = {'2.5.4.15': 'BusinessCategory', 
                 '2.5.4.3': 'CN', 
                 '2.5.4.46': 'DN', 
                 '0.9.2342.19200300.100.1.25': 'DC', 
                 '1.2.840.113549.1.9.1': 'E', 
                 '2.5.4.44': 'GENERATION', 
                 '2.5.4.42': 'GIVENNAME', 
                 '2.5.4.43': 'INITIALS', 
                 '1.2.643.3.131.1.1': '1.2.643.3.131.1.1',  
                 '1.3.6.1.4.1.311.60.2.1.1': 'jurisdictionLocality', 
                 '1.3.6.1.4.1.311.60.2.1.2': 'jurisdictionState', 
                 '2.5.4.7': 'L', 
                 '1.2.643.100.1': '1.2.643.100.1', 
                 '2.5.4.11': 'OU', 
                 '2.5.4.97': 'organizationIdentifier', 
                 '2.5.4.10': 'O', 
                 '2.5.4.16': 'PostalAddress', 
                 '2.5.4.17': 'PostalCode', 
                 '2.5.4.65': 'Pseudonym', 
                 '2.5.4.5': 'SERIALNUMBER', 
                 '1.2.643.100.3': '1.2.643.100.3', 
                 '2.5.4.8': 'ST', 
                 '2.5.4.9': 'STREET', 
                 '2.5.4.4': 'SURNAME', 
                 '2.5.4.12': 'T', 
                 '1.2.840.113549.1.9.2': 'unstructuredName', 
                 '0.9.2342.19200300.100.1.1': 'UID', 
                 }

with open(dir_path+"/output_java_bouncycastle.json","r") as file:
    for line in file:
        json_obj = json.loads(line)
        FocusField = json_obj["FocusField"]
        FocusFieldValue = json_obj["FocusFieldValue"]
        InsertValue = json_obj["InsertValue"]
        FocusFieldSlices = FocusField.split(" ")

        if FocusFieldSlices[0] == "Subject":
            if json_obj["JBC_Subject_status"] ==False:
                BouncyCastleEncoding["Subject"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
            else:
                decodingM = DecodingDetector(FocusFieldSlices[2], FocusFieldValue,
                                                       json_obj["JBC_Subject"],
                                                       bc_dn_prefix[FocusFieldSlices[1]] + "=","")
                get_info(BouncyCastleEncoding["Subject"][FocusFieldSlices[1]][FocusFieldSlices[2]], InsertValue,decodingM)
            if json_obj["JBC_SubjectList_status"] == False:
                BouncyCastleEncoding["SubjectRDN"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
            else:
                decodingM = DecodingDetector(FocusFieldSlices[2], FocusFieldValue,
                                                       json_obj["JBC_SubjectList"][0],
                                                       "[["+FocusFieldSlices[1]+", ","]]")
                get_info(BouncyCastleEncoding["SubjectRDN"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue, decodingM)

        if FocusFieldSlices[0] == "Issuer":
            if json_obj["JBC_Issuer_status"] ==False:
                BouncyCastleEncoding["Issuer"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
            else:
                decodingM = DecodingDetector(FocusFieldSlices[2], FocusFieldValue,
                                                       json_obj["JBC_Issuer"],
                                                       bc_dn_prefix[FocusFieldSlices[1]] + "=","")
                get_info(BouncyCastleEncoding["Issuer"][FocusFieldSlices[1]][FocusFieldSlices[2]], InsertValue,decodingM)

            if json_obj["JBC_IssuerList_status"] == False:
                BouncyCastleEncoding["IssuerRDN"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
            else:
                decodingM = DecodingDetector(FocusFieldSlices[2], FocusFieldValue,
                                                       json_obj["JBC_IssuerList"][0],
                                                       "[["+FocusFieldSlices[1]+", ","]]")
                get_info(BouncyCastleEncoding["IssuerRDN"][FocusFieldSlices[1]][FocusFieldSlices[2]], InsertValue,decodingM)
    
BouncyCastlePaths = FindAllCharlistsInDict(BouncyCastleEncoding)

for BouncyCastlePath in BouncyCastlePaths:
    set_deduced_decoding(BouncyCastleEncoding,BouncyCastlePath)

BouncyCastleStr = json.dumps(BouncyCastleEncoding,indent=4)

with open(output_path+"/DecodingTestBouncyCastle.json",'a') as file:
    file.write(BouncyCastleStr+'\n')



            
            