import json
import sys
import copy
dir_path = sys.argv[1]
output_path =sys.argv[2]

from DencodingCheckHelper import set_deduced_decoding,ASN1_list,FindAllCharlistsInDict,DN,save_info
from DecodingDetection import DecodingDetector,get_info

JavaSecurityEncoding = {
    "Lib":"JDK@8/11/17/21 from zulu",
    "SubjectDeprecated":{},
    "Subject2StringDeprecated":{},
    "SubjectRFC2253":{},
    "SubjectRFC1779":{},
    "SubjectReadable":{},
    "IssuerDeprecated":{},
    "Issuer2StringDeprecated":{},
    "IssuerRFC2253":{},
    "IssuerRFC1779":{},
    "IssuerReadable":{},
    "SubjectAlternativeName":{"DNSName":copy.deepcopy(save_info),"URI":copy.deepcopy(save_info),"RFC822Name":copy.deepcopy(save_info)},
    "IssuerAlternativeName":{"DNSName":copy.deepcopy(save_info),"URI":copy.deepcopy(save_info),"RFC822Name":copy.deepcopy(save_info)}
}

for itm in DN:
    JavaSecurityEncoding["SubjectDeprecated"][itm] = {}
    JavaSecurityEncoding["Subject2StringDeprecated"][itm] = {}
    JavaSecurityEncoding["SubjectRFC2253"][itm] = {}
    JavaSecurityEncoding["SubjectRFC1779"][itm] = {}
    JavaSecurityEncoding["SubjectReadable"][itm] = {}
    JavaSecurityEncoding["IssuerDeprecated"][itm] = {}
    JavaSecurityEncoding["Issuer2StringDeprecated"][itm] = {}
    JavaSecurityEncoding["IssuerRFC2253"][itm] = {}
    JavaSecurityEncoding["IssuerRFC1779"][itm] = {}
    JavaSecurityEncoding["IssuerReadable"][itm] = {}
    for ASN1 in ASN1_list:
        JavaSecurityEncoding["SubjectDeprecated"][itm][ASN1] = copy.deepcopy(save_info)
        JavaSecurityEncoding["Subject2StringDeprecated"][itm][ASN1] = copy.deepcopy(save_info)
        JavaSecurityEncoding["SubjectRFC2253"][itm][ASN1] = copy.deepcopy(save_info)
        JavaSecurityEncoding["SubjectRFC1779"][itm][ASN1] = copy.deepcopy(save_info)
        JavaSecurityEncoding["SubjectReadable"][itm][ASN1] = copy.deepcopy(save_info)
        JavaSecurityEncoding["IssuerDeprecated"][itm][ASN1] = copy.deepcopy(save_info)
        JavaSecurityEncoding["Issuer2StringDeprecated"][itm][ASN1] = copy.deepcopy(save_info)
        JavaSecurityEncoding["IssuerRFC2253"][itm][ASN1] = copy.deepcopy(save_info)
        JavaSecurityEncoding["IssuerRFC1779"][itm][ASN1] = copy.deepcopy(save_info)
        JavaSecurityEncoding["IssuerReadable"][itm][ASN1] = copy.deepcopy(save_info)

#Get Name ParsedValue Prefix
JDK8SecurityDN_Deprecated = { #prefix=value
    '2.5.4.15': 'OID.2.5.4.15', 
    '2.5.4.3': 'CN', 
    '2.5.4.46': 'DNQ', 
    '0.9.2342.19200300.100.1.25': 'DC', 
    '1.2.840.113549.1.9.1': 'EMAILADDRESS', 
    '2.5.4.44': 'GENERATION', 
    '2.5.4.42': 'GIVENNAME', 
    '2.5.4.43': 'INITIALS', 
    '1.2.643.3.131.1.1': 'OID.1.2.643.3.131.1.1',  
    '1.3.6.1.4.1.311.60.2.1.1': 'OID.1.3.6.1.4.1.311.60.2.1.1', 
    '1.3.6.1.4.1.311.60.2.1.2': 'OID.1.3.6.1.4.1.311.60.2.1.2', 
    '2.5.4.7': 'L', 
    '1.2.643.100.1': 'OID.1.2.643.100.1', 
    '2.5.4.11': 'OU', 
    '2.5.4.97': 'OID.2.5.4.97', 
    '2.5.4.10': 'O', 
    '2.5.4.16': 'OID.2.5.4.16', 
    '2.5.4.17': 'OID.2.5.4.17', 
    '2.5.4.65': 'OID.2.5.4.65', 
    '2.5.4.5': 'SERIALNUMBER', 
    '1.2.643.100.3': 'OID.1.2.643.100.3', 
    '2.5.4.8': 'ST', 
    '2.5.4.9': 'STREET', 
    '2.5.4.4': 'SURNAME', 
    '2.5.4.12': 'T', 
    '1.2.840.113549.1.9.2': 'OID.1.2.840.113549.1.9.2', 
    '0.9.2342.19200300.100.1.1': 'UID'
}

JDK8SecurityDN2String_Deprecated = { #"prefix=value"
    '2.5.4.15': 'OID.2.5.4.15', 
    '2.5.4.3': 'CN', 
    '2.5.4.46': 'DNQ', 
    '0.9.2342.19200300.100.1.25': 'DC', 
    '1.2.840.113549.1.9.1': 'EMAILADDRESS', 
    '2.5.4.44': 'GENERATION', 
    '2.5.4.42': 'GIVENNAME', 
    '2.5.4.43': 'INITIALS', 
    '1.2.643.3.131.1.1': 'OID.1.2.643.3.131.1.1',  
    '1.3.6.1.4.1.311.60.2.1.1': 'OID.1.3.6.1.4.1.311.60.2.1.1', 
    '1.3.6.1.4.1.311.60.2.1.2': 'OID.1.3.6.1.4.1.311.60.2.1.2', 
    '2.5.4.7': 'L', 
    '1.2.643.100.1': 'OID.1.2.643.100.1', 
    '2.5.4.11': 'OU', 
    '2.5.4.97': 'OID.2.5.4.97', 
    '2.5.4.10': 'O', 
    '2.5.4.16': 'OID.2.5.4.16', 
    '2.5.4.17': 'OID.2.5.4.17', 
    '2.5.4.65': 'OID.2.5.4.65', 
    '2.5.4.5': 'SERIALNUMBER', 
    '1.2.643.100.3': 'OID.1.2.643.100.3', 
    '2.5.4.8': 'ST', 
    '2.5.4.9': 'STREET', 
    '2.5.4.4': 'SURNAME', 
    '2.5.4.12': 'T', 
    '1.2.840.113549.1.9.2': 'OID.1.2.840.113549.1.9.2', 
    '0.9.2342.19200300.100.1.1': 'UID'
}

JDK8SecurityDN_RFC2253 = { 
    '2.5.4.3': 'CN', 
    '0.9.2342.19200300.100.1.25': 'DC',      
    '2.5.4.7': 'L', 
    '2.5.4.11': 'OU', 
    '2.5.4.10': 'O',  
    '2.5.4.8': 'ST', 
    '2.5.4.9': 'STREET', 
    '0.9.2342.19200300.100.1.1': 'UID'
}

JDK8SecurityDN_RFC1779 ={
    '2.5.4.15': 'OID.2.5.4.15', 
    '2.5.4.3': 'CN', 
    '2.5.4.46': 'OID.2.5.4.46', 
    '0.9.2342.19200300.100.1.25': 'OID.0.9.2342.19200300.100.1.25', 
    '1.2.840.113549.1.9.1': 'OID.1.2.840.113549.1.9.1', 
    '2.5.4.44': 'OID.2.5.4.44', 
    '2.5.4.42': 'OID.2.5.4.42', 
    '2.5.4.43': 'OID.2.5.4.43', 
    '1.2.643.3.131.1.1': 'OID.1.2.643.3.131.1.1',  
    '1.3.6.1.4.1.311.60.2.1.1': 'OID.1.3.6.1.4.1.311.60.2.1.1', 
    '1.3.6.1.4.1.311.60.2.1.2': 'OID.1.3.6.1.4.1.311.60.2.1.2', 
    '2.5.4.7': 'L', 
    '1.2.643.100.1': 'OID.1.2.643.100.1', 
    '2.5.4.11': 'OU', 
    '2.5.4.97': 'OID.2.5.4.97', 
    '2.5.4.10': 'O', 
    '2.5.4.16': 'OID.2.5.4.16', 
    '2.5.4.17': 'OID.2.5.4.17', 
    '2.5.4.65': 'OID.2.5.4.65', 
    '2.5.4.5': 'OID.2.5.4.5', 
    '1.2.643.100.3': 'OID.1.2.643.100.3', 
    '2.5.4.8': 'ST', 
    '2.5.4.9': 'STREET', 
    '2.5.4.4': 'OID.2.5.4.4', 
    '2.5.4.12': 'OID.2.5.4.12', 
    '1.2.840.113549.1.9.2': 'OID.1.2.840.113549.1.9.2', 
    '0.9.2342.19200300.100.1.1': 'OID.0.9.2342.19200300.100.1.1'
}

JDK8SecurityDN_Readable = {
    '2.5.4.15': 'OID.2.5.4.15', 
    '2.5.4.3': 'CN', 
    '2.5.4.46': 'DNQ', 
    '0.9.2342.19200300.100.1.25': 'DC', 
    '1.2.840.113549.1.9.1': 'EMAILADDRESS', 
    '2.5.4.44': 'GENERATION', 
    '2.5.4.42': 'GIVENNAME', 
    '2.5.4.43': 'INITIALS', 
    '1.2.643.3.131.1.1': 'OID.1.2.643.3.131.1.1',  
    '1.3.6.1.4.1.311.60.2.1.1': 'OID.1.3.6.1.4.1.311.60.2.1.1', 
    '1.3.6.1.4.1.311.60.2.1.2': 'OID.1.3.6.1.4.1.311.60.2.1.2', 
    '2.5.4.7': 'L', 
    '1.2.643.100.1': 'OID.1.2.643.100.1', 
    '2.5.4.11': 'OU', 
    '2.5.4.97': 'OID.2.5.4.97', 
    '2.5.4.10': 'O', 
    '2.5.4.16': 'OID.2.5.4.16', 
    '2.5.4.17': 'OID.2.5.4.17', 
    '2.5.4.65': 'OID.2.5.4.65', 
    '2.5.4.5': 'SERIALNUMBER', 
    '1.2.643.100.3': 'OID.1.2.643.100.3', 
    '2.5.4.8': 'ST', 
    '2.5.4.9': 'STREET', 
    '2.5.4.4': 'SURNAME', 
    '2.5.4.12': 'T', 
    '1.2.840.113549.1.9.2': 'OID.1.2.840.113549.1.9.2', 
    '0.9.2342.19200300.100.1.1': 'UID'
}

JDK8SecurityDN_san = {
    '2.5.4.3': 'CN', 
    '0.9.2342.19200300.100.1.25': 'DC', 
    '2.5.4.7': 'L', 
    '2.5.4.11': 'OU', 
    '2.5.4.10': 'O', 
    '2.5.4.8': 'ST', 
    '2.5.4.9': 'STREET', 
    '0.9.2342.19200300.100.1.1': 'UID'
}

with open(dir_path+"/output_java_security.json",'r') as file:
    for line in file:
        json_obj = json.loads(line)
        FocusField = json_obj["FocusField"]
        FocusFieldValue = json_obj["FocusFieldValue"]
        InsertValue = json_obj["InsertValue"]
        FocusFieldSlices = FocusField.split(" ")

        if FocusFieldSlices[0] == "Subject":
            if json_obj["J21_SubjectDeprecated_status"] == False:
                JavaSecurityEncoding["SubjectDeprecated"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
            else:
                decodingM = DecodingDetector(FocusFieldSlices[2],FocusFieldValue,json_obj["J21_SubjectDeprecated"],JDK8SecurityDN_Deprecated[FocusFieldSlices[1]]+"=","")
                get_info(JavaSecurityEncoding["SubjectDeprecated"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue,decodingM)

            if json_obj["J21_Subject2StringDeprecated_status"] == False:
                JavaSecurityEncoding["Subject2StringDeprecated"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
            else:
                decodingM = DecodingDetector(FocusFieldSlices[2],FocusFieldValue,json_obj["J21_Subject2StringDeprecated"],JDK8SecurityDN2String_Deprecated[FocusFieldSlices[1]]+"=","")
                get_info(JavaSecurityEncoding["Subject2StringDeprecated"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue,decodingM)
            
            if json_obj["J21_SubjectRFC2253_status"] == False:
                JavaSecurityEncoding["SubjectRFC2253"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
            else:
                if FocusFieldSlices[1] not in list(JDK8SecurityDN_RFC2253.keys()):
                    pass
                else:
                    decodingM = DecodingDetector(FocusFieldSlices[2],FocusFieldValue,json_obj["J21_SubjectRFC2253"],JDK8SecurityDN_RFC2253[FocusFieldSlices[1]] + "=","")
                    get_info(JavaSecurityEncoding["SubjectRFC2253"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue,decodingM)
            
            if json_obj["J21_SubjectRFC1779_status"] ==False:
                JavaSecurityEncoding["SubjectRFC1779"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
            else:
                decodingM = DecodingDetector(FocusFieldSlices[2],FocusFieldValue,json_obj["J21_SubjectRFC1779"],JDK8SecurityDN_RFC1779[FocusFieldSlices[1]] + "=","")
                get_info(JavaSecurityEncoding["SubjectRFC1779"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue,decodingM)
            
            if json_obj["J21_SubjectReadable_status"] ==False:
                JavaSecurityEncoding["SubjectReadable"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
            else:
                decodingM = DecodingDetector(FocusFieldSlices[2],FocusFieldValue,json_obj["J21_SubjectReadable"],JDK8SecurityDN_Readable[FocusFieldSlices[1]] + "=","")
                get_info(JavaSecurityEncoding["SubjectReadable"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue,decodingM)

        if FocusFieldSlices[0] == "Issuer":
            if json_obj["J21_IssuerDeprecated_status"] == False:
                JavaSecurityEncoding["IssuerDeprecated"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
            else:
                decodingM = DecodingDetector(FocusFieldSlices[2],FocusFieldValue,json_obj["J21_IssuerDeprecated"],JDK8SecurityDN_Deprecated[FocusFieldSlices[1]]+"=","")
                get_info(JavaSecurityEncoding["IssuerDeprecated"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue,decodingM)

            if json_obj["J21_Issuer2StringDeprecated_status"] == False:
                JavaSecurityEncoding["Issuer2StringDeprecated"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
            else:
                decodingM = DecodingDetector(FocusFieldSlices[2],FocusFieldValue,json_obj["J21_Issuer2StringDeprecated"],JDK8SecurityDN2String_Deprecated[FocusFieldSlices[1]]+"=","")
                get_info(JavaSecurityEncoding["Issuer2StringDeprecated"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue,decodingM)

            if json_obj["J21_IssuerRFC2253_status"] == False:
                JavaSecurityEncoding["IssuerRFC2253"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
            else:
                if FocusFieldSlices[1] not in list(JDK8SecurityDN_RFC2253.keys()):
                    pass
                else:
                    decodingM = DecodingDetector(FocusFieldSlices[2],FocusFieldValue,json_obj["J21_IssuerRFC2253"],JDK8SecurityDN_RFC2253[FocusFieldSlices[1]] + "=","")
                    get_info(JavaSecurityEncoding["IssuerRFC2253"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue,decodingM)
                    
            if json_obj["J21_IssuerRFC1779_status"] ==False:
                JavaSecurityEncoding["IssuerRFC1779"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
            else:
                decodingM = DecodingDetector(FocusFieldSlices[2],FocusFieldValue,json_obj["J21_IssuerRFC1779"],JDK8SecurityDN_RFC1779[FocusFieldSlices[1]] + "=","")
                get_info(JavaSecurityEncoding["IssuerRFC1779"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue,decodingM)
            
            if json_obj["J21_IssuerReadable_status"] ==False:
                JavaSecurityEncoding["IssuerReadable"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
            else:
                decodingM = DecodingDetector(FocusFieldSlices[2],FocusFieldValue,json_obj["J21_IssuerReadable"],JDK8SecurityDN_Readable[FocusFieldSlices[1]] + "=","")
                get_info(JavaSecurityEncoding["IssuerReadable"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue,decodingM)

        if FocusFieldSlices[0] =="SAN":
            if FocusFieldSlices[1] == "DirectoryName":
                pass
            else:
                if json_obj["J21_status"] ==False:
                    JavaSecurityEncoding["SubjectAlternativeName"][FocusFieldSlices[1]]["parsing_failed"].add(InsertValue)
                else:
                    decodingM = DecodingDetector("UTF8String",FocusFieldValue,json_obj["J21_SAN"][0]["value"],"","")
                    get_info(JavaSecurityEncoding["SubjectAlternativeName"][FocusFieldSlices[1]],InsertValue,decodingM)


        if FocusFieldSlices[0] =="IAN":
            if FocusFieldSlices[1] == "DirectoryName":
                pass
            else:
                if json_obj["J21_status"] ==False:
                    JavaSecurityEncoding["IssuerAlternativeName"][FocusFieldSlices[1]]["parsing_failed"].add(InsertValue)
                else:
                    decodingM = DecodingDetector("UTF8String",FocusFieldValue,json_obj["J21_IAN"][0]["value"],"","")
                    get_info(JavaSecurityEncoding["IssuerAlternativeName"][FocusFieldSlices[1]],InsertValue,decodingM)

Paths = FindAllCharlistsInDict(JavaSecurityEncoding)

for path in Paths:
    set_deduced_decoding(JavaSecurityEncoding,path)

JavaSecurityEncodingStr = json.dumps(JavaSecurityEncoding,indent=4)

with open(output_path+"/DecodingTestJavaSecurity.json",'a') as file:
    file.write(JavaSecurityEncodingStr+'\n')