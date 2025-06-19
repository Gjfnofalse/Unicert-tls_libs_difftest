import json
import sys
import copy
dir_path = sys.argv[1]
output_path = sys.argv[2]
from DencodingCheckHelper import set_deduced_decoding,ASN1_list,FindAllCharlistsInDict,DN,save_info
from DecodingDetection import DecodingDetector,get_info

NodejsCryptoEncoding = {
    "Lib": "NodejsCrypto@V22.4.1",
    "Subject": {},
    "Issuer": {},
    "SubjectAlternativeName": {"DNSName": copy.deepcopy(save_info), "URI": copy.deepcopy(save_info), "RFC822Name": copy.deepcopy(save_info)},
    "AuthorityInformationAccess": {"ocsp": {"DNSName": copy.deepcopy(save_info), "URI": copy.deepcopy(save_info), "RFC822Name": copy.deepcopy(save_info)},
                                   "ca-issuer": {"DNSName": copy.deepcopy(save_info), "URI": copy.deepcopy(save_info), "RFC822Name": copy.deepcopy(save_info)}}
}

for itm in DN:
    NodejsCryptoEncoding["Issuer"][itm] = {}
    NodejsCryptoEncoding["Subject"][itm] = {}
    for ASN1 in ASN1_list:
        NodejsCryptoEncoding["Issuer"][itm][ASN1] = copy.deepcopy(save_info)
        NodejsCryptoEncoding["Subject"][itm][ASN1] = copy.deepcopy(save_info)

#Get Name GeneralName ParsedValue Prefix
gn_prefix = {
    "DNSName": "DNS",
    "RFC822Name": "email",
    "URI": "URI"
}

dn_prefix = {'2.5.4.15': 'businessCategory',
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

with open(dir_path + "/output_nodejs_crypto.json", 'r') as file:
    for line in file:
        json_obj = json.loads(line)
        FocusField = json_obj["FocusField"]
        FocusFieldValue = json_obj["FocusFieldValue"]
        InsertValue = json_obj["InsertValue"]
        FocusFieldSlices = FocusField.split(" ")

        if FocusFieldSlices[0] == "Subject":
            if json_obj["Status"] == False:
                NodejsCryptoEncoding["Subject"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
            else:
                decodingM = DecodingDetector(FocusFieldSlices[2], FocusFieldValue,
                                                       json_obj["Subject"], dn_prefix[FocusFieldSlices[1]] + "=","")
                get_info(NodejsCryptoEncoding["Subject"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue, decodingM)


        if FocusFieldSlices[0] == "Issuer":
            if json_obj["Status"] == False:
                NodejsCryptoEncoding["Issuer"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
            else:
                decodingM = DecodingDetector(FocusFieldSlices[2], FocusFieldValue,
                                                       json_obj["Issuer"], dn_prefix[FocusFieldSlices[1]] + "=","")
                get_info(NodejsCryptoEncoding["Issuer"][FocusFieldSlices[1]][FocusFieldSlices[2]], InsertValue,decodingM)

        # SAN
        if FocusFieldSlices[0] == "SAN":
            if FocusFieldSlices[1] == "DirectoryName":
                pass
            else:
                if json_obj["Status"] == False:
                    NodejsCryptoEncoding["SubjectAlternativeName"][FocusFieldSlices[1]]["parsing_failed"].add(InsertValue)
                else:
                    RawValue_san = gn_prefix[FocusFieldSlices[1]] + ":" + FocusFieldValue
                    if json_obj["SAN"]["jstype"] == "string":
                        decodingM = DecodingDetector("UTF8String", FocusFieldValue,
                                                               json_obj["SAN"]["data"], gn_prefix[FocusFieldSlices[1]] + ":","")
                        get_info(NodejsCryptoEncoding["SubjectAlternativeName"][FocusFieldSlices[1]],InsertValue, decodingM)
                    else:
                        NodejsCryptoEncoding["SubjectAlternativeName"][FocusFieldSlices[1]]["parsing_failed"].add(InsertValue)

        # IAN
        if FocusFieldSlices[0] == "IAN":
            pass

        # AIA OCSP
        if FocusFieldSlices[0] == "AIA" and FocusFieldSlices[1] == "OCSP":
            if FocusFieldSlices[2] != "DirectoryName":
                if json_obj["Status"] == False:
                    NodejsCryptoEncoding["AuthorityInformationAccess"]["ocsp"][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
                else:
                    if json_obj["AIA"]["jstype"] == "string":
                        decodingM = DecodingDetector("UTF8String", FocusFieldValue,
                                                               json_obj["AIA"]["data"],
                                                               "OCSP - " + gn_prefix[FocusFieldSlices[2]] + ":","")
                        get_info(NodejsCryptoEncoding["AuthorityInformationAccess"]["ocsp"][FocusFieldSlices[2]], InsertValue,decodingM)
                    else:
                        NodejsCryptoEncoding["AuthorityInformationAccess"]["ocsp"][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
            elif FocusFieldSlices[2] == "DirectoryName":
                pass

        if FocusFieldSlices[0] == "AIA" and FocusFieldSlices[1] == "CaIssuer":
            if FocusFieldSlices[2] != "DirectoryName":
                if json_obj["Status"] == False:
                    NodejsCryptoEncoding["AuthorityInformationAccess"]["ca-issuer"][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
                else:
                    if json_obj["AIA"]["jstype"] == "string":
                        decodingM = DecodingDetector("UTF8String", FocusFieldValue,
                                                               json_obj["AIA"]["data"],
                                                               "CA Issuers - " + gn_prefix[FocusFieldSlices[2]] + ":","")
                        get_info(NodejsCryptoEncoding["AuthorityInformationAccess"]["ca-issuer"][FocusFieldSlices[2]],InsertValue,
                                 decodingM)
                    else:
                        NodejsCryptoEncoding["AuthorityInformationAccess"]["ca-issuer"][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
            elif FocusFieldSlices[2] == "DirectoryName":
                pass

        if FocusField.startswith("SIA"):
            pass

        if FocusFieldSlices[0] == "CertPolicies":
            pass

        if FocusField.startswith("CRL RDN"):
            pass

NodejsCryptoPaths = FindAllCharlistsInDict(NodejsCryptoEncoding)

for NodejsCryptoPath in NodejsCryptoPaths:
    set_deduced_decoding(NodejsCryptoEncoding, NodejsCryptoPath)

NodejsCryptoStr = json.dumps(NodejsCryptoEncoding, indent=4)

with open(output_path + "/DecodingTestNodejsCrypto.json", 'a') as file:
    file.write(NodejsCryptoStr + '\n')


