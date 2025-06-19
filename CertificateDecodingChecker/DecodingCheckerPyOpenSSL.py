import json
import sys
import copy

from DencodingCheckHelper import set_deduced_decoding,ASN1_list,FindAllCharlistsInDict,DN,save_info
from DecodingDetection import DecodingDetector,get_info

dir_path = sys.argv[1]
output_path = sys.argv[2]

#Build dict{OID:NameStr}
AttrTypesPyOpenSSLStr = ["organizationName", "localityName", "commonName", "organizationalUnitName",
                         "stateOrProvinceName",
                         "domainComponent", "emailAddress", "businessCategory", "serialNumber", "streetAddress",
                         "postalCode",
                         "postOfficeBox", "organizationIdentifier", "surname", "givenName",
                         "jurisdictionLocalityName"]

AttrTypesPyOpenSSL = ["2.5.4.10", "2.5.4.7", "2.5.4.3", "2.5.4.11", "2.5.4.8",
                      "0.9.2342.19200300.100.1.25", "1.2.840.113549.1.9.1", "2.5.4.15", "2.5.4.5", "2.5.4.9",
                      "2.5.4.17",
                      "2.5.4.4", "2.5.4.42", "1.3.6.1.4.1.311.60.2.1.1"]

attrTypeRlt = {
}

for i in range(len(AttrTypesPyOpenSSL)):
    attrTypeRlt[AttrTypesPyOpenSSL[i]] = AttrTypesPyOpenSSLStr[i]

PyOpenSSLEncoding = {
    "Lib": "PyOpenSSL@V24.2.1",
    "Subject": {},
    "Issuer": {},
    "SubjectAlternativeName": {"DNSName": copy.deepcopy(save_info), "URI": copy.deepcopy(save_info), "RFC822Name": copy.deepcopy(save_info)},
    "IssuerAlternativeName": {"DNSName": copy.deepcopy(save_info), "URI": copy.deepcopy(save_info), "RFC822Name": copy.deepcopy(save_info)},
    "AuthorityInformationAccess": {"ocsp": {"DNSName": copy.deepcopy(save_info), "URI": copy.deepcopy(save_info), "RFC822Name": copy.deepcopy(save_info)},
                                   "ca-issuer": {"DNSName": copy.deepcopy(save_info), "URI": copy.deepcopy(save_info), "RFC822Name": copy.deepcopy(save_info)}},
    "CRLDistributionPoints": {"fullname": {"DNSName": copy.deepcopy(save_info), "URI": copy.deepcopy(save_info), "RFC822Name": copy.deepcopy(save_info)},
                              "crlissuer": {"DNSName": copy.deepcopy(save_info), "URI": copy.deepcopy(save_info), "RFC822Name": copy.deepcopy(save_info)}}
}

for itm in DN:
    PyOpenSSLEncoding["Issuer"][itm] = {}
    PyOpenSSLEncoding["Subject"][itm] = {}
    for ASN1 in ASN1_list:
        PyOpenSSLEncoding["Issuer"][itm][ASN1] = copy.deepcopy(save_info)
        PyOpenSSLEncoding["Subject"][itm][ASN1] = copy.deepcopy(save_info)

# Get Name GeneralName ParsedValue Prefix
GeneralNamePrefixRlt = {
    "URI": "URI:",
    "DNSName": "DNS:",
    "RFC822Name": "email:"
}

san_dn_prefix = {'2.5.4.15': 'businessCategory',
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

with open(dir_path + "/output_python_pyopenssl.json", 'r') as file:
    for line in file:
        json_obj = json.loads(line)
        FocusField = json_obj["FocusField"]
        FocusFieldValue = json_obj["FocusFieldValue"]
        InsertValue = json_obj["InsertValue"]
        FocusFieldSlices = FocusField.split(" ")

        if FocusFieldSlices[0] == "Subject" and FocusFieldSlices[1] in AttrTypesPyOpenSSL:
            if json_obj["status"] == False:
                PyOpenSSLEncoding["Subject"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
            else:
                decodingM = DecodingDetector(FocusFieldSlices[2], FocusFieldValue,
                                                       json_obj["subject_" + attrTypeRlt[FocusFieldSlices[1]]], "","")
                get_info(PyOpenSSLEncoding["Subject"][FocusFieldSlices[1]][FocusFieldSlices[2]], InsertValue,decodingM)
        elif FocusFieldSlices[0] == "Subject" and FocusFieldSlices[1] not in AttrTypesPyOpenSSL:
            pass

        if FocusFieldSlices[0] == "Issuer" and FocusFieldSlices[1] in AttrTypesPyOpenSSL:
            if json_obj["status"] == False:
                PyOpenSSLEncoding["Issuer"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
            else:
                decodingM = DecodingDetector(FocusFieldSlices[2], FocusFieldValue,
                                                       json_obj["issuer_" + attrTypeRlt[FocusFieldSlices[1]]], "","")
                get_info(PyOpenSSLEncoding["Issuer"][FocusFieldSlices[1]][FocusFieldSlices[2]], InsertValue,decodingM)
        elif FocusFieldSlices[0] == "Issuer" and FocusFieldSlices[1] not in AttrTypesPyOpenSSL:
            pass

        if FocusFieldSlices[0] == "SAN" and FocusFieldSlices[1] != "DirectoryName":
            if json_obj["status"] == False:
                PyOpenSSLEncoding["SubjectAlternativeName"][FocusFieldSlices[1]]["parsing_failed"].add(InsertValue)
            else:
                decodingM = DecodingDetector("UTF8String", FocusFieldValue,
                                                       json_obj["subjectAltName"], GeneralNamePrefixRlt[FocusFieldSlices[1]],"")
                get_info(PyOpenSSLEncoding["SubjectAlternativeName"][FocusFieldSlices[1]],InsertValue, decodingM)
        elif FocusFieldSlices[0] == "SAN" and FocusFieldSlices[1] == "DirectoryName":
            pass

        if FocusField.startswith("IAN") and FocusFieldSlices[1] != "DirectoryName":
            if json_obj["status"] == False:
                PyOpenSSLEncoding["IssuerAlternativeName"][FocusFieldSlices[1]]["parsing_failed"].add(InsertValue)
            else:
                decodingM = DecodingDetector("UTF8String", FocusFieldValue,
                                                       json_obj["issuerAltName"],
                                                       GeneralNamePrefixRlt[FocusFieldSlices[1]],"")
                get_info(PyOpenSSLEncoding["IssuerAlternativeName"][FocusFieldSlices[1]], InsertValue,decodingM)
        elif FocusFieldSlices[0] == "IAN" and FocusFieldSlices[1] == "DirectoryName":
            pass

        # 处理AIA CaIssuer
        if FocusFieldSlices[0] == "AIA" and FocusFieldSlices[1] == "CaIssuer":
            if FocusFieldSlices[2] != "DirectoryName":
                if json_obj["status"] == False:
                    PyOpenSSLEncoding["AuthorityInformationAccess"]["ca-issuer"][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
                else:
                    decodingM = DecodingDetector("UTF8String", FocusFieldValue,
                                                           json_obj["authorityInfoAccess"],
                                                           "CA Issuers - " + GeneralNamePrefixRlt[FocusFieldSlices[2]],"")
                    get_info(PyOpenSSLEncoding["AuthorityInformationAccess"]["ca-issuer"][FocusFieldSlices[2]], InsertValue,decodingM)
            else:
                pass

        if FocusFieldSlices[0] == "AIA" and FocusFieldSlices[1] == "OCSP":
            if FocusFieldSlices[2] != "DirectoryName":
                if json_obj["status"] == False:
                    PyOpenSSLEncoding["AuthorityInformationAccess"]["ocsp"][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
                else:
                    decodingM = DecodingDetector("UTF8String", FocusFieldValue,
                                                           json_obj["authorityInfoAccess"],
                                                           "OCSP - " + GeneralNamePrefixRlt[FocusFieldSlices[2]],"")
                    get_info(PyOpenSSLEncoding["AuthorityInformationAccess"]["ocsp"][FocusFieldSlices[2]], InsertValue,decodingM)
            else:
                pass

        if FocusFieldSlices[0] == "SIA" and FocusFieldSlices[1] == "CaIssuer":
            pass

        if FocusFieldSlices[0] == "SIA" and FocusFieldSlices[1] == "OCSP":
            pass

        if FocusFieldSlices[0] == "CRL" and FocusFieldSlices[1] == "RDN":
            pass

        if FocusFieldSlices[0] == "CRL" and FocusFieldSlices[1] == "fullname":
            if FocusFieldSlices[2] != "DirectoryName":
                if json_obj["status"] == False:
                    PyOpenSSLEncoding["CRLDistributionPoints"]["fullname"][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
                else:
                    decodingM = DecodingDetector("UTF8String", FocusFieldValue,
                                                           json_obj["cRLDistributionPoints"],
                                                           "Full Name:\n  " + GeneralNamePrefixRlt[FocusFieldSlices[
                        2]],"Reasons:\n  CA Compromise, Privilege Withdrawn\nCRL Issuer:\n  DNS:www.testfullname.com")
                    get_info(PyOpenSSLEncoding["CRLDistributionPoints"]["fullname"][FocusFieldSlices[2]],InsertValue, decodingM)
            else:
                pass

        if ("CRL" in FocusField) and ("crlissuer" in FocusField):
            if FocusFieldSlices[2] != "DirectoryName":
                if json_obj["status"] == False:
                    PyOpenSSLEncoding["CRLDistributionPoints"]["crlissuer"][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
                else:
                    decodingM = DecodingDetector("UTF8String", FocusFieldValue,
                                                           json_obj["cRLDistributionPoints"],
                                                           "Full Name:\n  DNS:www.testcrlissuer.comReasons:\n  CA Compromise, Privilege Withdrawn\nCRL Issuer:\n  " + \
                                             GeneralNamePrefixRlt[FocusFieldSlices[2]],
                                                           "")
                    get_info(PyOpenSSLEncoding["CRLDistributionPoints"]["crlissuer"][FocusFieldSlices[2]], InsertValue,decodingM)
            else:
                pass

PyOpenSSLPaths = FindAllCharlistsInDict(PyOpenSSLEncoding)

for PyOpenSSLPath in PyOpenSSLPaths:
    set_deduced_decoding(PyOpenSSLEncoding, PyOpenSSLPath)

PyOpenSSLStr = json.dumps(PyOpenSSLEncoding, indent=4)

with open(sys.argv[2] + "/DecodingTestPyOpenSSL.json", 'a') as file:
    file.write(PyOpenSSLStr + '\n')
