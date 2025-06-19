import os
import argparse
import json
import hashlib

from tqdm import tqdm
from OpenSSL import crypto

# Name Switcher
subject_switcher = {
    'c': 'subject_countryName',
    'o': 'subject_organizationName',
    'l': 'subject_localityName',
    'cn': 'subject_commonName',
    'ou': 'subject_organizationalUnitName',
    'st': 'subject_stateOrProvinceName',
    'dc': 'subject_domainComponent',
    'emailaddress': 'subject_emailAddress',
    'businesscategory': 'subject_businessCategory',
    'serialnumber': 'subject_serialNumber',
    'street': "subject_streetAddress",
    'postalcode': 'subject_postalCode',
    'distinguishednamequalifier': 'subject_distinguishedNameQualifier',
    'postofficebox': 'subject_postOfficeBox',
    'organizationidentifier': 'subject_organizationIdentifier',
    'surname': 'subject_surname',
    'givenName': 'subject_givenName'
}

issuer_switcher = {
    'c': 'issuer_countryName',
    'o': 'issuer_organizationName',
    'l': 'issuer_localityName',
    'cn': 'issuer_commonName',
    'ou': 'issuer_organizationalUnitName',
    'st': 'issuer_stateOrProvinceName',
    'dc': 'issuer_domainComponent',
    'emailaddress': 'issuer_emailAddress',
    'businesscategory': 'issuer_businessCategory',
    'serialnumber': 'issuer_serialNumber',
    'street': "issuer_streetAddress",
    'postalcode': 'issuer_postalCode',
    'distinguishednamequalifier': 'issuer_distinguishedNameQualifier',
    'surname': 'issuer_surname',
    'givenName': 'issuer_givenName',
    'organizationidentifier': 'issuer_organizationIdentifier'
}

extension_switcher = {
    'subjectaltname': 'subjectAltName',
    'subject_alternative_name': 'subjectAltName',
    'issueraltname': 'issuerAltName',
    'issuer_alternative_name': 'issuerAltName',
    'basicconstraints': 'basicConstraints',
    'subjectkeyidentifier': 'subjectKeyIdentifier',
    'authoritykeyidentifier': 'authorityKeyIdentifier',
    'extendedkeyusage': 'extendedKeyUsage',
    'authorityinfoaccess': 'authorityInfoAccess',
    'keyusage': 'keyUsage',
    'certificatepolicies': 'certificatePolicies',
    'crldistributionpoints': 'cRLDistributionPoints',
    'crl_distribution_points': 'cRLDistributionPoints',
    'privatekeyusageperiod': 'privateKeyUsagePeriod',
    'policymappings': 'policyMappings',
    'policyconstraints': 'policyConstraints',
    'subjectinfoaccess': 'subjectInfoAccess',
    'ct_precert_scts': 'ctPrecertScts',
    'ct_precert_poison': 'ctPrecertPoison',
    'issuerorganizationunitname': 'issuerOrganizationUnitName'
}




def quick_parse(pemStr):
    """
    parse the information of an X.509 certificate
    :param cert: The X509 object (e.g., crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data_string))
    :return: certificate attributes dict
    """
    cert_json ={
        "sha1": record["sha1"],
        "status": True,
        "errors": []
    }
    try:
        x509Obj = crypto.load_certificate(crypto.FILETYPE_PEM, pemStr)
    except Exception as e:
        cert_json["errors"].append("load cert error,"+str(e))
        cert_json["status"] = False
        return cert_json

    try:
    # Subject
        subject_obj = x509Obj.get_subject()
        cert_json["subject_countryName"] = subject_obj.C
        cert_json["subject_organizationName"] = subject_obj.O
        cert_json["subject_localityName"] = subject_obj.L
        cert_json["subject_commonName"] = subject_obj.CN
        cert_json["subject_organizationalUnitName"] = subject_obj.OU
        cert_json["subject_stateOrProvinceName"] = subject_obj.ST
        cert_json["subject_domainComponent"] = subject_obj.DC
        cert_json["subject_emailAddress"] = subject_obj.emailAddress
        cert_json["subject_businessCategory"] = subject_obj.businessCategory
        cert_json["subject_serialNumber"] = subject_obj.serialNumber
        cert_json["subject_streetAddress"] = subject_obj.streetAddress
        cert_json["subject_postalCode"] = subject_obj.postalCode
        cert_json["subject_postOfficeBox"] = subject_obj.postOfficeBox
        cert_json["subject_organizationIdentifier"] = subject_obj.organizationIdentifier
        cert_json["subject_surname"] = subject_obj.surname
        cert_json["subject_givenName"] = subject_obj.givenName
        cert_json["subject_description"] = subject_obj.description
        cert_json["subject_jurisdictionLocalityName"]  = subject_obj.jurisdictionL
        cert_json["subject_jurisdictionCountryName"]  = subject_obj.jurisdictionC

        try:
            subjects = subject_obj.get_components()
            for subject in subjects:
                try:
                    # key = "subject_" + subject[0].decode("utf-8")
                    key = subject_switcher.get(subject[0].decode().lower(), "subject_" + subject[0].decode())
                    if key not in  cert_json.keys():
                        # value = subject[1].decode("utf-8", "replace")
                        value = subject[1].decode("utf-8")
                        cert_json[key] = value
                except Exception as e:
                    except_info = "Error in parsing subject {}: {}".format(key, e.args[0])
                    cert_json["errors"].append(except_info)
                    cert_json["status"] = False
                    
        except Exception as e:
            cert_json["errors"].append("Error in parsing subject components.")
            cert_json["status"] = False
    except Exception as e:
        cert_json["errors"].append(str(e))
        cert_json["status"] = False

    # Issuer
    try:
        issuer_obj = x509Obj.get_issuer()
        cert_json["issuer_countryName"] = issuer_obj.C
        cert_json["issuer_organizationName"] = issuer_obj.O
        cert_json["issuer_localityName"] = issuer_obj.L
        cert_json["issuer_commonName"] = issuer_obj.CN
        cert_json["issuer_organizationalUnitName"] = issuer_obj.OU
        cert_json["issuer_stateOrProvinceName"] = issuer_obj.ST
        cert_json["issuer_domainComponent"] = issuer_obj.DC
        cert_json["issuer_emailAddress"] = issuer_obj.emailAddress
        cert_json["issuer_businessCategory"] = issuer_obj.businessCategory
        cert_json["issuer_serialNumber"] = issuer_obj.serialNumber
        cert_json["issuer_streetAddress"] = issuer_obj.streetAddress
        cert_json["issuer_postalCode"] = issuer_obj.postalCode
        cert_json["issuer_postOfficeBox"] = issuer_obj.postOfficeBox
        cert_json["issuer_organizationIdentifier"] = issuer_obj.organizationIdentifier
        cert_json["issuer_surname"] = issuer_obj.surname
        cert_json["issuer_givenName"] = issuer_obj.givenName

        try:
            issuerinfos = issuer_obj.get_components()
            for issuerinfo in issuerinfos:
                try:
                    key = issuer_switcher.get(issuerinfo[0].decode().lower(), "issuer_" + issuerinfo[0].decode().lower())
                    if key not in cert_json.keys():
                        value = issuerinfo[1].decode()
                        cert_json[key] = value
                except Exception as e:
                    except_info = "Error in parsing issuer {}: {}".format(key, e.args[0])
                    cert_json["errors"].append(except_info)
                    cert_json["status"] = False
        except Exception as e:
            cert_json["errors"].append("Error in parsing issuer components.")
            cert_json["status"] = False
    except:
        cert_json["errors"].append(str(e))
        cert_json["status"] = False
    


    # # 解析公钥
    # try:
    #     pubkey = crypto.dump_publickey(crypto.FILETYPE_ASN1, cert.get_pubkey())
    #     hasher = hashlib.sha1()
    #     hasher.update(pubkey)
    #     cert_json["public_key_sha1"] = hasher.hexdigest()
    # except Exception as e:
    #     except_info = "Error in parsing public_key: {}".format(e.args[0])
    #     cert_json["errors"].append(except_info)

    # # 解析有效期
    # try:
    #     notbefore_datetime = parser.parse(cert.get_notBefore())
    #     cert_json["notBefore"] = notbefore_datetime.strftime('%Y-%m-%d %H:%M:%S')
    #     notafter_datetime = parser.parse(cert.get_notAfter())
    #     cert_json["notAfter"] = notafter_datetime.strftime('%Y-%m-%d %H:%M:%S')
    #     cert_json['lifetime'] = (notafter_datetime - notbefore_datetime).days
    # except Exception as e:
    #     except_info = "Error in parsing validity: {}".format(e.args[0])
    #     cert_json["errors"].append(except_info)

    # # 解析签名算法和序列号
    # try:
    #     cert_json["signatureAlgorithm"] = cert.get_signature_algorithm().decode()
    #     cert_json["serial_number"] = hex(cert.get_serial_number())[2:]
    # except Exception as e:
    #     except_info = "Error in parsing serial_num/sig_algo: {}".format(e.args[0])
    #     cert_json["errors"].append(except_info)


    # Extensions
    try:
        e_count = x509Obj.get_extension_count()
        selected_ext_names = ['subjectAltName', 'issuerAltName', 'authorityInfoAccess', 'certificatePolicies', 'cRLDistributionPoints']
        if e_count > 0:
            for i in range(0, e_count):
                try:
                    extension = x509Obj.get_extension(i)
                    critical = extension.get_critical()
                    ext_name = extension.get_short_name().decode().lower()
                    # SAN,IAN,AIA,SIA,CertPolicies,CrlDistributionPoints
                    if ext_name in ('subjectdirectoryattributes', 'qcstatements', 'undef', 'biometricinfo', 'smime-caps'):
                        continue
                    else:
                        ext_name = extension_switcher.get(ext_name, ext_name)
                        if ext_name not in selected_ext_names:
                            continue
                        ext_str = str(extension)
                        # ext_bytes = extension.get_data() # The ASN.1 encoded data of this X509 extension
                        cert_json[ext_name] = ext_str
                except Exception as e:
                    except_info = "Error in parsing extension {}: {}".format(ext_name, e)
                    cert_json["status"] = False
                    cert_json["errors"].append(except_info)
    except Exception as e:
        cert_json["status"] = False
        cert_json["errors"].append(str(e))

    return cert_json


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Input params")
    parser.add_argument("-i","--input",metavar="INPUT",help="input filepath")
    parser.add_argument("-o", "--output", metavar="OUTPUT", help="output filepath")

    args = parser.parse_args()
    inputPath = args.input
    outputPath = args.output

    with open(inputPath, 'r') as fd:
        with open(outputPath, 'a+') as save_fd:
            for line in fd:
                try:
                    record = json.loads(line)
                    pemStr = record['pem']
                    savecert = quick_parse(pemStr)
                    savecert["FocusField"] = record["FocusField"]
                    savecert["FocusFieldValue"] = record["FocusFieldValue"]
                    savecert["InsertValue"] = record["InsertValue"]
                    savecert["description"] = record["description"]
                    
                    try :
                        strObj = json.dumps(savecert)
                        save_fd.write(strObj+"\n")
                    except:
                        print("sha1: " + savecert["sha1"]+ " ,The certificate parsing was successful, the JSON sequence was successful, the write failed, and no entry was generated")
                except Exception as e:
                    print(str(e)+" json:load cert failed,next cert.")