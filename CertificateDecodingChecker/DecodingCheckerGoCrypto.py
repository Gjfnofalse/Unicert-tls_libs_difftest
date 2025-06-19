import json
import sys
import copy

dir_path = sys.argv[1]
output_path =sys.argv[2]

from DencodingCheckHelper import set_deduced_decoding,ASN1_list,FindAllCharlistsInDict,DN,save_info
from DecodingDetection import DecodingDetector,get_info

GolangCryptoEncoding = {
    "Lib": "GolangCrypto@Vgo1.23.0 linux/amd64",
    "Subject": {},
    "Issuer": {},
    "SubjectAlternativeName": {"DNSName": copy.deepcopy(save_info), "RFC822Name": copy.deepcopy(save_info)},
    "AuthorityInformationAccess": {"ocsp": {"URI": copy.deepcopy(save_info)},
                                   "ca-issuer": {"URI": copy.deepcopy(save_info)}},
    "CRLDistributionPoints": {"fullname": {"URI": copy.deepcopy(save_info)}}
}

for itm in DN:
    GolangCryptoEncoding["Issuer"][itm] = {}
    GolangCryptoEncoding["Subject"][itm] = {}
    for ASN1 in ASN1_list:
        GolangCryptoEncoding["Issuer"][itm][ASN1] = copy.deepcopy(save_info)
        GolangCryptoEncoding["Subject"][itm][ASN1] = copy.deepcopy(save_info)

# Get Name GeneralName ParsedValue Prefix
string_dn_rlt = {
    '2.5.4.3': 'CommonName',
    '2.5.4.5': "SerialNumber"
}
list_dn_rlt = {
    '2.5.4.10': "Organization",
    '2.5.4.11': 'OrganizationalUnit',
    '2.5.4.7': "Locality",
    "2.5.4.8": "Province",
    "2.5.4.9": "StreetAddress",
    "2.5.4.17": "PostalCode"
}

generalNames_rlt = {
    "DNSName": "DNSNames",
    "RFC822Name": "EmailAddresses"
}

with open(dir_path + "/output_golang_crypto.json", 'r') as file:
    for line in file:
        json_obj = json.loads(line)
        FocusField = json_obj["FocusField"]
        FocusFieldValue = json_obj["FocusFieldValue"]
        InsertValue = json_obj["InsertValue"]
        FocusFieldSlices = FocusField.split(" ")

        if FocusFieldSlices[0] == "Subject" and FocusFieldSlices[1] in list(string_dn_rlt.keys()):
            if json_obj["status"] == False:
                GolangCryptoEncoding["Subject"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
            else:
                decodingM = DecodingDetector(FocusFieldSlices[2], FocusFieldValue,
                                                       json_obj["Subject"][string_dn_rlt[FocusFieldSlices[1]]],
                                                       "","")
                get_info(GolangCryptoEncoding["Subject"][FocusFieldSlices[1]][FocusFieldSlices[2]], InsertValue,decodingM)
        elif FocusFieldSlices[0] == "Subject" and FocusFieldSlices[1] in list(list_dn_rlt.keys()):
            if json_obj["status"] == False:
                GolangCryptoEncoding["Subject"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
            else:
                decodingM = DecodingDetector(FocusFieldSlices[2], FocusFieldValue,
                                                       json_obj["Subject"][list_dn_rlt[FocusFieldSlices[1]]][0],
                                                       "","")
                get_info(GolangCryptoEncoding["Subject"][FocusFieldSlices[1]][FocusFieldSlices[2]], InsertValue,decodingM)

        if FocusFieldSlices[0] == "Issuer" and FocusFieldSlices[1] in list(string_dn_rlt.keys()):
            if json_obj["status"] == False:
                GolangCryptoEncoding["Issuer"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
            else:
                decodingM = DecodingDetector(FocusFieldSlices[2], FocusFieldValue,
                                                       json_obj["Issuer"][string_dn_rlt[FocusFieldSlices[1]]],
                                                       "","")
                get_info(GolangCryptoEncoding["Issuer"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue, decodingM)
        elif FocusFieldSlices[0] == "Issuer" and FocusFieldSlices[1] in list(list_dn_rlt.keys()):
            if json_obj["status"] == False:
                GolangCryptoEncoding["Issuer"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
            else:
                decodingM = DecodingDetector(FocusFieldSlices[2], FocusFieldValue,
                                                       json_obj["Issuer"][list_dn_rlt[FocusFieldSlices[1]]][0],
                                                       "","")
                get_info(GolangCryptoEncoding["Issuer"][FocusFieldSlices[1]][FocusFieldSlices[2]], InsertValue,decodingM)

        if FocusFieldSlices[0] == "SAN" and (FocusFieldSlices[1] == "DNSName" or FocusFieldSlices[1] == "RFC822Name"):
            if json_obj["status"] == False:
                GolangCryptoEncoding["SubjectAlternativeName"][FocusFieldSlices[1]]["parsing_failed"].add(InsertValue)
            else:
                decodingM = DecodingDetector("UTF8String", FocusFieldValue,
                                                       json_obj["SubjectAlternativeName"][generalNames_rlt[FocusFieldSlices[1]]][0],
                                                       "","")
                get_info(GolangCryptoEncoding["SubjectAlternativeName"][FocusFieldSlices[1]], InsertValue,decodingM)

        if FocusField.startswith("AIA OCSP"):
            if FocusFieldSlices[2] == "URI":  #The only identifiable GeneralName
                if json_obj["status"] == False:
                    GolangCryptoEncoding["AuthorityInformationAccess"]["ocsp"]["URI"]["parsing_failed"].add(InsertValue)
                else:
                    decodingM = DecodingDetector("UTF8String", FocusFieldValue,
                                                           json_obj["AuthorityInfoAccess"]["OCSPserver"][0],
                                                           "","")
                    get_info(GolangCryptoEncoding["AuthorityInformationAccess"]["ocsp"]["URI"], InsertValue,decodingM)

        if FocusField.startswith("AIA CaIssuer"):
            if FocusFieldSlices[2] == "URI":  #The only identifiable GeneralName
                if json_obj["status"] == False:
                    GolangCryptoEncoding["AuthorityInformationAccess"]["ca-issuer"]["URI"]["parsing_failed"].add(InsertValue)
                else:
                    decodingM = DecodingDetector("UTF8String", FocusFieldValue,
                                                           json_obj["AuthorityInfoAccess"]["IssuingCertificateURL"][0],
                                                           "","")
                    get_info(GolangCryptoEncoding["AuthorityInformationAccess"]["ca-issuer"]["URI"], InsertValue,decodingM)

        if FocusFieldSlices[0] == "CRL" and FocusFieldSlices[1] == "fullname":
            if FocusFieldSlices[2] != "DirectoryName":
                if FocusFieldSlices[2] == "URI":
                    if json_obj["status"] == False:
                        GolangCryptoEncoding["CRLDistributionPoints"]["fullname"]["URI"]["parsing_failed"].add(InsertValue)
                    else:
                        decodingM = DecodingDetector("UTF8String", FocusFieldValue,
                                                               json_obj["CRLDistributionPoints"][0],
                                                               "","")
                        get_info(GolangCryptoEncoding["CRLDistributionPoints"]["fullname"]["URI"], InsertValue,decodingM)

GolangCryptoPaths = FindAllCharlistsInDict(GolangCryptoEncoding)

for GolangCryptoPath in GolangCryptoPaths:
    set_deduced_decoding(GolangCryptoEncoding,GolangCryptoPath)

GolangCryptoStr = json.dumps(GolangCryptoEncoding, indent=4)

with open(output_path + "/DecodingTestGolangCrypto.json", 'a') as file:
    file.write(GolangCryptoStr + '\n')
