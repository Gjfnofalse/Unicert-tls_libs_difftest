import json
import sys
import copy
from DencodingCheckHelper import set_deduced_decoding,ASN1_list,FindAllCharlistsInDict,DN,save_info
from DecodingDetection import DecodingDetector,get_info

CryptoGraphyEncoding = {
    "Lib": "CryptoGraphy@V42.0.7",
    "Subject": {},
    "Issuer": {},
    "SubjectAlternativeName": {"DNSName": copy.deepcopy(save_info), "URI": copy.deepcopy(save_info), "RFC822Name": copy.deepcopy(save_info)},
    "IssuerAlternativeName": {"DNSName": copy.deepcopy(save_info), "URI": copy.deepcopy(save_info), "RFC822Name": copy.deepcopy(save_info)},
    "AuthorityInformationAccess": {"ocsp": {"DNSName": copy.deepcopy(save_info), "URI": copy.deepcopy(save_info), "RFC822Name": copy.deepcopy(save_info)},
                                   "ca-issuer": {"DNSName": copy.deepcopy(save_info), "URI": copy.deepcopy(save_info), "RFC822Name": copy.deepcopy(save_info)}},
    "SubjectInformationAccess": {"ocsp": {"DNSName": copy.deepcopy(save_info), "URI": copy.deepcopy(save_info), "RFC822Name": copy.deepcopy(save_info)},
                                 "ca-issuer": {"DNSName": copy.deepcopy(save_info), "URI": copy.deepcopy(save_info), "RFC822Name": copy.deepcopy(save_info)}},
    "CRLDistributionPoints": {"fullname": {"DNSName": copy.deepcopy(save_info), "URI": copy.deepcopy(save_info), "RFC822Name": copy.deepcopy(save_info)},
                              "crlissuer": {"DNSName": copy.deepcopy(save_info), "URI": copy.deepcopy(save_info), "RFC822Name": copy.deepcopy(save_info)}}
}

for itm in DN:
    CryptoGraphyEncoding["Issuer"][itm] = {}
    CryptoGraphyEncoding["Subject"][itm] = {}
    for ASN1 in ASN1_list:
        CryptoGraphyEncoding["Issuer"][itm][ASN1] = copy.deepcopy(save_info)
        CryptoGraphyEncoding["Subject"][itm][ASN1] = copy.deepcopy(save_info)

gn_rlt_cry = {
    "DNSName": "DnsName",
    "RFC822Name": "RFC822Name",
    "URI": "URI",
    "DirectoryName": "DirectoryName"
}

if __name__ == "__main__":
    dir_path = sys.argv[1]
    output_path = sys.argv[2]

    with open(dir_path + "/output_python_cryptography.json", 'r') as file:

        # Subject prefix
        subject_dn_string = {}
        subject_value = []

        # Generate DN Prefix
        with open("CertificateDecodingChecker/cryptography_subject_issuer_prefix.json", 'r') as cry_file:
            cry_entries = cry_file.readlines()

            for cry_entry in cry_entries:
                cry_obj = json.loads(cry_entry)
                if cry_obj["subject"] not in subject_value:
                    subject_value.append(cry_obj["subject"])

            subject_value.remove("CN=BaseSubject")

            subject_prefix = [itm.split("=")[0] for itm in subject_value]

            for subject_prefix_itm in subject_prefix:
                if "." in subject_prefix_itm:
                    subject_dn_string[subject_prefix_itm] = subject_prefix_itm
                else:
                    if subject_prefix_itm == 'CN':
                        subject_dn_string["2.5.4.3"] = subject_prefix_itm
                    if subject_prefix_itm == "DC":
                        subject_dn_string["0.9.2342.19200300.100.1.25"] = "DC"
                    if subject_prefix_itm == "L":
                        subject_dn_string["2.5.4.7"] = "L"
                    if subject_prefix_itm == "OU":
                        subject_dn_string["2.5.4.11"] = "OU"
                    if subject_prefix_itm == "O":
                        subject_dn_string["2.5.4.10"] = "O"
                    if subject_prefix_itm == "ST":
                        subject_dn_string["2.5.4.8"] = "ST"
                    if subject_prefix_itm == "STREET":
                        subject_dn_string["2.5.4.9"] = "STREET"
                    if subject_prefix_itm == "UID":
                        subject_dn_string["0.9.2342.19200300.100.1.1"] = "UID"

        for line in file:
            json_obj = json.loads(line)
            FocusField = json_obj["FocusField"]
            FocusFieldValue = json_obj["FocusFieldValue"]
            InsertValue = json_obj["InsertValue"]
            FocusFieldSlices = FocusField.split(" ")  

            if json_obj["status"] == True:
                if FocusFieldSlices[0] == "Subject":
                    decodingM = DecodingDetector(FocusFieldSlices[2], FocusFieldValue, json_obj["subject"],
                                                           subject_dn_string[FocusFieldSlices[1]] + "=","")
                    get_info(CryptoGraphyEncoding["Subject"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue, decodingM)

                if FocusFieldSlices[0] == "Issuer":
                    decodingM = DecodingDetector(FocusFieldSlices[2], FocusFieldValue, json_obj["issuer"],subject_dn_string[FocusFieldSlices[1]] + "=","")
                    get_info(CryptoGraphyEncoding["Issuer"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue,decodingM)

                if FocusFieldSlices[0] == "SAN":
                    if FocusFieldSlices[1] != "DirectoryName":
                        decodingM = DecodingDetector("UTF8String", FocusFieldValue, json_obj["SubjectAlternativeName"][gn_rlt_cry[FocusFieldSlices[1]]][0],"","")
                        get_info(CryptoGraphyEncoding["SubjectAlternativeName"][FocusFieldSlices[1]], InsertValue,decodingM)
                    else:
                        pass

                if FocusFieldSlices[0] == "IAN":
                    if FocusFieldSlices[1] != "DirectoryName":
                        decodingM = DecodingDetector("UTF8String", FocusFieldValue, json_obj["IssuerAlternativeName"][gn_rlt_cry[FocusFieldSlices[1]]][0],"","")
                        get_info(CryptoGraphyEncoding["IssuerAlternativeName"][FocusFieldSlices[1]], InsertValue,decodingM)
                    else:
                        pass

                if FocusFieldSlices[0] == "AIA" and FocusFieldSlices[1] == "CaIssuer":
                    if FocusFieldSlices[2] != "DirectoryName":
                        decodingM = DecodingDetector("UTF8String", FocusFieldValue,
                                                               json_obj["aia"][0][1][FocusFieldSlices[2]], "","")
                        get_info(CryptoGraphyEncoding["AuthorityInformationAccess"]["ca-issuer"][FocusFieldSlices[2]],InsertValue, decodingM)
                    else:
                        pass

                if FocusFieldSlices[0] == "AIA" and FocusFieldSlices[1] == "OCSP":
                    if FocusFieldSlices[2] != "DirectoryName":
                        decodingM = DecodingDetector("UTF8String", FocusFieldValue,
                                                               json_obj["aia"][0][1][FocusFieldSlices[2]], "","")
                        get_info(CryptoGraphyEncoding["AuthorityInformationAccess"]["ocsp"][FocusFieldSlices[2]],InsertValue,
                                 decodingM)
                    else:
                        pass

                if FocusFieldSlices[0] == "SIA" and FocusFieldSlices[1] == "CaIssuer":
                    if FocusFieldSlices[2] != "DirectoryName":
                        decodingM = DecodingDetector("UTF8String", FocusFieldValue,
                                                               json_obj["sia"][0][1][FocusFieldSlices[2]], "","")
                        get_info(CryptoGraphyEncoding["SubjectInformationAccess"]["ca-issuer"][
                                     FocusFieldSlices[2]], InsertValue,decodingM)
                    else:
                        pass

                if FocusFieldSlices[0] == "SIA" and FocusFieldSlices[1] == "OCSP":
                    if FocusFieldSlices[2] != "DirectoryName":
                        decodingM = DecodingDetector("UTF8String", FocusFieldValue,
                                                               json_obj["sia"][0][1][FocusFieldSlices[2]], "","")
                        get_info(
                            CryptoGraphyEncoding["SubjectInformationAccess"]["ocsp"][FocusFieldSlices[2]],InsertValue,
                            decodingM)
                    else:
                        pass

                if FocusFieldSlices[0] == "CRL" and FocusFieldSlices[1] == "RDN":
                    pass
                elif FocusFieldSlices[0] == "CRL" and FocusFieldSlices[1] == "fullname":
                    if FocusFieldSlices[2] == "DirectoryName":
                        pass
                    else:
                        decodingM = DecodingDetector("UTF8String", FocusFieldValue,
                                                               json_obj["crlDistributionPoints"][0]["fullName"][0][
                                                                   FocusFieldSlices[2]], "","")
                        get_info(
                            CryptoGraphyEncoding["CRLDistributionPoints"]["fullname"][FocusFieldSlices[2]],InsertValue,
                            decodingM)
                elif FocusFieldSlices[0] == "CRL" and FocusFieldSlices[1] == "crlissuer":
                    if FocusFieldSlices[2] == "DirectoryName":
                        pass
                    else:
                        decodingM = DecodingDetector("UTF8String", FocusFieldValue,
                                                               json_obj["crlDistributionPoints"][0]["crlIssuer"][0][
                                                                   FocusFieldSlices[2]], "","")
                        get_info(
                            CryptoGraphyEncoding["CRLDistributionPoints"]["crlissuer"][FocusFieldSlices[2]],InsertValue,
                            decodingM)
            else:
                # Subject
                if FocusFieldSlices[0] == "Subject":
                    CryptoGraphyEncoding["Subject"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)

                if FocusFieldSlices[0] == "Issuer":
                    CryptoGraphyEncoding["Issuer"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
                    continue

                # san
                if FocusFieldSlices[0] == "SAN":
                    if FocusFieldSlices[1] != "DirectoryName":
                        CryptoGraphyEncoding["SubjectAlternativeName"][FocusFieldSlices[1]]["parsing_failed"].add(InsertValue)
                    else:
                        pass

                # ian
                if FocusFieldSlices[0] == "IAN":
                    if FocusFieldSlices[1] != "DirectoryName":
                        CryptoGraphyEncoding["IssuerAlternativeName"][FocusFieldSlices[1]]["parsing_failed"].add(InsertValue)
                    else:
                        pass

                # AIA
                if FocusFieldSlices[0] == "AIA" and FocusFieldSlices[1] == "CaIssuer":
                    if FocusFieldSlices[2] != "DirectoryName":
                        CryptoGraphyEncoding["AuthorityInformationAccess"]["ca-issuer"][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
                    else:
                        pass

                if FocusFieldSlices[0] == "AIA" and FocusFieldSlices[1] == "OCSP":
                    if FocusFieldSlices[2] != "DirectoryName":
                        CryptoGraphyEncoding["AuthorityInformationAccess"]["ocsp"][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
                    else:
                        pass

                # SIA
                if FocusFieldSlices[0] == "SIA" and FocusFieldSlices[1] == "CaIssuer":
                    if FocusFieldSlices[2] != "DirectoryName":
                        CryptoGraphyEncoding["SubjectInformationAccess"]["ca-issuer"][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
                    else:
                        pass

                if FocusFieldSlices[0] == "SIA" and FocusFieldSlices[1] == "OCSP":
                    if FocusFieldSlices[2] != "DirectoryName":
                        CryptoGraphyEncoding["SubjectInformationAccess"]["ocsp"][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
                    else:
                        pass

                # CRLDistributionPoints
                if FocusFieldSlices[0] == "CRL" and FocusFieldSlices[1] == "RDN":
                    pass
                elif FocusFieldSlices[0] == "CRL" and FocusFieldSlices[1] == "fullname":
                    if FocusFieldSlices[2] == "DirectoryName":
                        pass
                    else:
                        CryptoGraphyEncoding["CRLDistributionPoints"]["fullname"][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
                elif FocusFieldSlices[0] == "CRL" and FocusFieldSlices[1] == "crlissuer":
                    if FocusFieldSlices[2] == "DirectoryName":
                        pass
                    else:
                        CryptoGraphyEncoding["CRLDistributionPoints"]["crlissuer"][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)

    CryptoGraphyPaths = FindAllCharlistsInDict(CryptoGraphyEncoding)

    for CryptoGraphyPath in CryptoGraphyPaths:
        set_deduced_decoding(CryptoGraphyEncoding,CryptoGraphyPath)

    CryptoGraphyStr = json.dumps(CryptoGraphyEncoding, indent=4)

    with open(sys.argv[2] + "/DecodingTestCryptoGraphy.json", 'a') as file:
        file.write(CryptoGraphyStr + '\n')

