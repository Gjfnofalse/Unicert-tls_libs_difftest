# Entries with status==False should be regarded as parsing failures, even if some fields exist
# Usage: python3 -i inputpath -o outputpath

import argparse
import json
import base64
import warnings
from cryptography.x509 import load_der_x509_certificate
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.bindings._rust import ObjectIdentifier
from cryptography.hazmat.bindings._rust import openssl as rust_openssl
from cryptography.x509.general_name import (
    DirectoryName,
    DNSName,
    IPAddress,
    OtherName,
    RegisteredID,
    RFC822Name,
    UniformResourceIdentifier
)

gns_rlt = {
    DirectoryName :"DirectoryName",
    DNSName : "DNSName",
    IPAddress:"IP",
    OtherName : "OName",
    RFC822Name : "RFC822Name",
    RegisteredID : "RegID",
    UniformResourceIdentifier : "URI"
}

# The reasons for revocation in the CRL distributionPoints
CrlReasonFlags = {
    x509.ReasonFlags.unspecified : "unspecified",
    x509.ReasonFlags.key_compromise :"keyCompromise",
    x509.ReasonFlags.ca_compromise : "cACompromise",
    x509.ReasonFlags.affiliation_changed : "affiliationChanged",
    x509.ReasonFlags.superseded : "superseded",
    x509.ReasonFlags.cessation_of_operation : "cessationOfOperation",
    x509.ReasonFlags.certificate_hold : "certificateHold",
    x509.ReasonFlags.privilege_withdrawn : "privilegeWithdrawn",
    x509.ReasonFlags.aa_compromise : "aACompromise",
    x509.ReasonFlags.remove_from_crl : "removeFromCRL"
    }

# The self-defined SAN class is used for JSON serialization
class SubjectAlternativeName:
    def __init__(self,itmFromX509):
        self.DnsName = itmFromX509.get_values_for_type(DNSName)
        self.Uri = itmFromX509.get_values_for_type(UniformResourceIdentifier)
        self.Rfc822Name = itmFromX509.get_values_for_type(RFC822Name)

        Ip = itmFromX509.get_values_for_type(IPAddress)
        if len(Ip) ==0:
            self.Ip = []
        else :
            self.Ip =[]
            for i in Ip :
                self.Ip.append(str(i)) 

        DN = itmFromX509.get_values_for_type(DirectoryName)
        if len(DN) ==0:
            self.DirectoryName =[]
        else:
            self.DirectoryName = []
            for i in DN :
                self.DirectoryName.append(i.rfc4514_string())

        RegId = itmFromX509.get_values_for_type(RegisteredID)
        if len(RegId) ==0:
            self.RegId = []
        else:
            self.RegId = []
            for id in RegId:
                self.RegId.append(id.dotted_string)
        
        OName = itmFromX509.get_values_for_type(OtherName)
        if len(OName) == 0 :
            self.OName = []
        else:
            self.OName =[]
            for i in OName:
                self.OName.append([i._type_id.dotted_string,i.value])

    def toDict(self):
        return {
            "DnsName": self.DnsName,
            "RFC822Name" :self.Rfc822Name,
            "Ip" :self.Ip,
            "URI" :self.Uri,
            "DirectoryName" :self.DirectoryName,
            "RegID" : self.RegId,
            "OtherName" : self.OName
        }
            
class IssuerAlternativeName:
    def __init__(self,itmFromX509):
        self.DnsName = itmFromX509.get_values_for_type(DNSName)
        self.Uri = itmFromX509.get_values_for_type(UniformResourceIdentifier)
        self.Rfc822Name = itmFromX509.get_values_for_type(RFC822Name)

        Ip = itmFromX509.get_values_for_type(IPAddress)
        if len(Ip) ==0:
            self.Ip = []
        else :
            self.Ip =[]
            for i in Ip :
                self.Ip.append(str(i)) 

        DN = itmFromX509.get_values_for_type(DirectoryName)
        if len(DN) ==0:
            self.DirectoryName =[]
        else:
            self.DirectoryName = []
            for i in DN :
                self.DirectoryName.append(i.rfc4514_string())

        RegId = itmFromX509.get_values_for_type(RegisteredID)
        if len(RegId) ==0:
            self.RegId = []
        else:
            self.RegId = []
            for id in RegId:
                self.RegId.append(id.dotted_string)
        
        OName = itmFromX509.get_values_for_type(OtherName)
        if len(OName) == 0 :
            self.OName = []
        else:
            self.OName =[]
            for i in OName:
                self.OName.append([i._type_id.dotted_string,i.value])

    def toDict(self):
        return {
            "DnsName": self.DnsName,
            "RFC822Name" :self.Rfc822Name,
            "Ip" :self.Ip,
            "URI" :self.Uri,
            "DirectoryName" :self.DirectoryName,
            "RegID" : self.RegId,
            "OtherName" : self.OName
        }

# The self-defined DistributionPoint class is used for JSON serialization
class DistributionPoint:
    def __init__(self,itmFromX509):
        fullName = itmFromX509.full_name
        if fullName == None :
            self.fullName = None
        else:
            self.fullName =[]
            for name in fullName :
                self.fullName.append(PhraseGeneralName_ad(name))

        relative_name = itmFromX509.relative_name
        if relative_name == None:
            self.relativeName = None
        else:
            self.relativeName = relative_name.rfc4514_string()

        crlReasons = itmFromX509.reasons
        if crlReasons == None:
            self.reasons = None
        else:
            self.reasons = []
            for reason in crlReasons:
                self.reasons.append(CrlReasonFlags[reason]) 

        crlIssuers = itmFromX509.crl_issuer
        if crlIssuers == None:
            self.crlIssuer = None
        else:
            self.crlIssuer = []
            for crlIssuer in crlIssuers:
                self.crlIssuer.append(PhraseGeneralName_ad(crlIssuer))

    def toDict(self):
        return {
            "fullName":self.fullName,
            "relativeName" : self.relativeName,
            "reasons" : self.reasons,
            "crlIssuer" : self.crlIssuer
        }

class NoticeReference:
    def __init__(self,itmFromX509):
        self.organization = itmFromX509.organization
        self.noticeNumbers = itmFromX509.notice_numbers
    
    def toDict(self):
        return {
            "organization":self.organization,
            "noticenNumbers":self.noticeNumbers
        }
    
class UserNotice:
    def __init__(self,itmFromX509):
        if itmFromX509.notice_reference ==None :
            self.noticeRef =None 
        else:
            self.noticeRef = NoticeReference(itmFromX509.notice_reference)
        self.explicit_text = itmFromX509.explicit_text

    def toDict(self):
        if self.noticeRef ==None:
            return {
                "noticeRef":None, 
                "explicit_text":self.explicit_text
            }
        else:
            return {
                "noticeRef":self.noticeRef.toDict(),
                "explicit_text":self.explicit_text
            }
        
class PolicyInfomation:
    def __init__(self,itmFromX509):
        self.pOID = itmFromX509.policy_identifier.dotted_string
        Qualifiers = itmFromX509.policy_qualifiers
        if Qualifiers == None :
            self.pQualifiers =None
        else:
            self.pQualifiers = []
            for Qualifier in Qualifiers:
                if isinstance(Qualifier,str):
                    self.pQualifiers.append({"cpsuri":Qualifier})
                else :
                    self.pQualifiers.append(UserNotice(Qualifier).toDict())

    def toDict(self):
        return{
            "PolicyOID":self.pOID,
            "PolicyQualifiers":self.pQualifiers
        }

def PhraseGeneralName(itm):
    if isinstance(itm,DNSName) or isinstance(itm,UniformResourceIdentifier) or isinstance(itm,RFC822Name):
        return itm.value
    elif isinstance(itm,DirectoryName):
        return itm.value.rfc4514_string()
    elif isinstance(itm,RegisteredID):
        return itm.value.dotted_string
    elif isinstance(itm,IPAddress):
        return str(itm.value)
    elif isinstance(itm,OtherName):
        return [itm.type_id.dotted_string,itm.value]

def PhraseGeneralName_ad(itm):
    if isinstance(itm,DNSName) or isinstance(itm,UniformResourceIdentifier) or isinstance(itm,RFC822Name):
        return {gns_rlt[type(itm)]:itm.value}
    elif isinstance(itm,DirectoryName):
        return {gns_rlt[type(itm)]:itm.value.rfc4514_string()}
    elif isinstance(itm,RegisteredID):
        return {gns_rlt[type(itm)]:itm.value.dotted_string}
    elif isinstance(itm,IPAddress):
        return {gns_rlt[type(itm)]:str(itm.value)}
    elif isinstance(itm,OtherName):
        return {gns_rlt[type(itm)]:[itm.type_id.dotted_string,itm.value]}
    
def PhraseAccessDes(itm:x509.AccessDescription):
    res = [itm.access_method.dotted_string,PhraseGeneralName_ad(itm.access_location)]
    return res

def ReflactPubKeyType(type):
    if isinstance(type,rust_openssl.dh.DHPublicKey):
        return "DHPublicKey"
    elif isinstance(type,rust_openssl.dsa.DSAPublicKey):
        return "DSAPublicKey"
    elif isinstance(type,rust_openssl.rsa.RSAPublicKey):
        return "RSAPublicKey"
    elif isinstance(type,rust_openssl.ec.ECPublicKey):
        return "EllipticCurvePublicKey"
    elif isinstance(type,rust_openssl.ed25519.Ed25519PublicKey):
        return "Ed25519PublicKey"
    elif isinstance(type,rust_openssl.ed448.Ed448PublicKey):
        return "Ed448PublicKey"
    elif isinstance(type,rust_openssl.x25519.X25519PublicKey):
        return "X25519PublicKey"
    elif isinstance(type,rust_openssl.x448.X448PublicKey):
        return "X448PublicKey"
    else :
        return "UNKOWNEN PublicKey Type"

parser = argparse.ArgumentParser(description="input params")
parser.add_argument("-i","--input",metavar="INPUT",help="input file path")
parser.add_argument("-o", "--output", metavar="OUTPUT", help="output file path")

args = parser.parse_args()

with open(args.input,'r') as file:
    files = file.readlines()

for file in files :
    jsonObj = json.loads(file)
    pemstr = jsonObj["pem"]
    savecert ={"sha1":jsonObj["sha1"],"err":[],"status":True,"certType":"unidentification","warnings":[]}
    savecert["FocusField"] = jsonObj["FocusField"]
    savecert["FocusFieldValue"] = jsonObj["FocusFieldValue"]
    savecert["InsertValue"] = jsonObj["InsertValue"]
    savecert["description"] = jsonObj["description"]

    pem_certificate_encoded = pemstr.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "")#.replace("\n", "")
    der_certificate_base64_decoded = base64.b64decode(pem_certificate_encoded)
    cert = None
    
    #load X.509Certificates
    try:
        with warnings.catch_warnings(record=True) as ws:
            cert = load_der_x509_certificate(der_certificate_base64_decoded,default_backend())

            if ws:
                for w in ws:
                    savecert["warnings"].append({"category":str(w.category),"message":str(w.message)})
    except Exception as e:
        savecert["err"].append({"type":str(type(e).__name__),"content":str(e)}) 
        savecert["status"]=False
        try :
            strObj = json.dumps(savecert)
            try :
                with open(args.output,'a') as save:
                    save.write(strObj+"\n")
            except:
                if savecert["warnings"] :
                    print("sha1: " + jsonObj["sha1"]+ " ,An error occurred when importing X509. The JSON serialization was successful, but an error was made when writing the JSON string. No entry was generated" + " ,warnings: "+savecert["warnings"])
                else:
                    print("sha1: " + jsonObj["sha1"]+ " ,An error occurred when importing X509. The JSON serialization was successful, but an error was made when writing the JSON string. No entry was generated")
        except:
            if savecert["warnings"] :
                print("sha1: " + jsonObj["sha1"]+ " ,An error occurred when importing X509. The JSON serialization was failed. No entry was generated" + " ,warnings: "+savecert["warnings"])
            else:
                print("sha1: " + jsonObj["sha1"]+ " ,An error occurred when importing X509. The JSON serialization was failed. No entry was generated")
        continue

    # Parse Issuer Subject pubKey type
    try:
        with warnings.catch_warnings(record=True) as ws:
            savecert["issuer"] = cert.issuer.rfc4514_string()
            
            if ws:
                for w in ws:
                    savecert["warnings"].append({"category":str(w.category),"message":str(w.message)})
    except Exception as e:
        savecert["status"] = False
        savecert["issuer"] = None
        savecert["err"].append({"type":str(type(e).__name__),"content":str(e)})
        try :
            strObj = json.dumps(savecert)
            try :
                with open(args.output,'a') as save:
                    save.write(strObj+"\n")
            except:
                if savecert["warnings"] :
                    print("sha1: " + jsonObj["sha1"]+ " ,The Issuer field parsing error occurred, the JSON serialization was successful, an error was made when writing the JSON string, and no entry was generated" + " ,warnings: "+savecert["warnings"])
                else:
                    print("sha1: " + jsonObj["sha1"]+ " ,The Issuer field parsing error occurred, the JSON serialization was successful, an error was made when writing the JSON string, and no entry was generated")
        except:
            if savecert["warnings"] :
                print("sha1: " + jsonObj["sha1"]+ " ,The Issuer field parsing error,JSON serialization error, and no entry is generated" + " ,warnings: "+savecert["warnings"])
            else:
                print("sha1: " + jsonObj["sha1"]+ " ,The Issuer field parsing error,JSON serialization error, and no entry is generated")
        continue
    
    try:
        with warnings.catch_warnings(record=True) as ws:
            savecert["subject"] = cert.subject.rfc4514_string()

            if ws:
                for w in ws:
                    savecert["warnings"].append({"category":str(w.category),"message":str(w.message)})
    except Exception as e:
        savecert["status"] = False
        savecert["subject"] = None
        savecert["err"].append({"type":str(type(e).__name__),"content":str(e)})
        try :
            strObj = json.dumps(savecert)
            try :
                with open(args.output,'a') as save:
                    save.write(strObj+"\n")
            except:
                if savecert["warnings"] :
                    print("sha1: " + jsonObj["sha1"]+ " ,There was an error in the Subject field parsing, the JSON serialization was successful, an error was made when writing the JSON string, and no entry was generated" + " ,warnings: "+savecert["warnings"])
                else:
                    print("sha1: " + jsonObj["sha1"]+ " ,There was an error in the Subject field parsing, the JSON serialization was successful, an error was made when writing the JSON string, and no entry was generated")
        except:
            if savecert["warnings"] :
                print("sha1: " + jsonObj["sha1"]+ " ,The Subject field parsing error,JSON serialization error, and no entry is generated" + " ,warnings: "+savecert["warnings"])
            else:
                print("sha1: " + jsonObj["sha1"]+ " ,The Subject field parsing error,JSON serialization error, and no entry is generated")
        continue

    try:
        with warnings.catch_warnings(record=True) as ws:
            savecert["publicKeyType"] = ReflactPubKeyType(cert.public_key())

            if ws:
                for w in ws:
                    savecert["warnings"].append({"category":str(w.category),"message":str(w.message)})
    except Exception as e:
        savecert["status"] = False
        savecert["publicKeyType"] = None
        savecert["err"].append({"type":str(type(e).__name__),"content":str(e)})
        try :
            strObj = json.dumps(savecert)
            try :
                with open(args.output,'a') as save:
                    save.write(strObj+"\n")
            except:
                if savecert["warnings"] :
                    print("sha1: " + jsonObj["sha1"]+ " ,The public key type of the certificate was parsed incorrectly, the JSON serialization was successful, an error was made when writing the JSON string, and no entry was generated" + " ,warnings: "+savecert["warnings"])
                else:
                    print("sha1: " + jsonObj["sha1"]+ " ,The public key type of the certificate was parsed incorrectly, the JSON serialization was successful, an error was made when writing the JSON string, and no entry was generated")
        except:
            if savecert["warnings"] :
                print("sha1: " + jsonObj["sha1"]+ " ,There was an error in the parsing of the certificate public key type, the JSON serialization was incorrect, and no entry was generated" + " ,warnings: "+savecert["warnings"])
            else:
                print("sha1: " + jsonObj["sha1"]+ " ,There was an error in the parsing of the certificate public key type, the JSON serialization was incorrect, and no entry was generated")
        continue

    # Parse Extensions
    extensions = []
    try:
        with warnings.catch_warnings(record=True) as ws:
            extensions = cert.extensions

            if ws:
                for w in ws:
                    savecert["warnings"].append({"category":str(w.category),"message":str(w.message)})
    except Exception as e:
        savecert["status"] = False
        savecert["err"].append({"type":str(type(e).__name__),"content":str(e)})
        try :
            strObj = json.dumps(savecert)
            try :
                with open(args.output,'a') as save:
                    save.write(strObj+"\n")
            except:
                if savecert["warnings"] :
                    print("sha1: " + jsonObj["sha1"]+ " ,Certificate extension parsing error,JSON serialization successful, writing JSON string error, no entry generated" + " ,warnings: "+savecert["warnings"])
                else:
                    print("sha1: " + jsonObj["sha1"]+ " ,Certificate extension parsing error,JSON serialization successful, writing JSON string error, no entry generated")
        except:
            if savecert["warnings"] :
                print("sha1: " + jsonObj["sha1"]+ " ,There was an error in the certificate extension parsing and JSON serialization, and no entries were generated" + " ,warnings: "+savecert["warnings"])
            else:
                print("sha1: " + jsonObj["sha1"]+ " ,There was an error in the certificate extension parsing and JSON serialization, and no entries were generated")
        continue

    # Parse SAN
    try:
        with warnings.catch_warnings(record=True) as ws:
            san = extensions.get_extension_for_oid(ObjectIdentifier("2.5.29.17")).value
            savecert["SubjectAlternativeName"] = SubjectAlternativeName(san).toDict()
            if ws:
                for w in ws:
                    savecert["warnings"].append({"category":str(w.category),"message":str(w.message)})
    except x509.ExtensionNotFound as e:
        savecert["SubjectAlternativeName"] = None 
    except Exception as e :
        savecert["SubjectAlternativeName"] = None
        savecert["status"] = False
        savecert["err"].append({"type":str(type(e).__name__),"content":str(e)})
        
        try :
            strObj = json.dumps(savecert)
            try :
                with open(args.output,'a') as save:
                    save.write(strObj+"\n")
            except:
                if savecert["warnings"] :
                    print("sha1: " + jsonObj["sha1"]+ " ,SAN parsing error,JSON serialization successful, writing JSON string error, no entry generated" + " ,warnings: "+savecert["warnings"])
                else:
                    print("sha1: " + jsonObj["sha1"]+ " ,SAN parsing error,JSON serialization successful, writing JSON string error, no entry generated")
        except:
            if savecert["warnings"] :
                print("sha1: " + jsonObj["sha1"]+ " ,SAN parsing error,JSON serialization error, no entry generated" + " ,warnings: "+savecert["warnings"])
            else:
                print("sha1: " + jsonObj["sha1"]+ " ,SAN parsing error,JSON serialization error, no entry generated")
        continue
            
    # Parse IAN
    try:
        with warnings.catch_warnings(record=True) as ws:
            ian = extensions.get_extension_for_oid(ObjectIdentifier("2.5.29.18")).value
            savecert["IssuerAlternativeName"] = IssuerAlternativeName(ian).toDict()

            if ws:
                for w in ws:
                    savecert["warnings"].append({"category":str(w.category),"message":str(w.message)})

    except x509.ExtensionNotFound as e:
        savecert["IssuerAlternativeName"] = None 
    except Exception as e :
        savecert["IssuerAlternativeName"] = None
        savecert["status"] = False
        savecert["err"].append({"type":str(type(e).__name__),"content":str(e)})
        
        try :
            strObj = json.dumps(savecert)
            try :
                with open(args.output,'a') as save:
                    save.write(strObj+"\n")
            except:
                if savecert["warnings"] :
                    print("sha1: " + jsonObj["sha1"]+ " ,IAN parsing error,JSON serialization successful, writing JSON string error, no entry generated" + " ,warnings: "+savecert["warnings"])
                else:
                    print("sha1: " + jsonObj["sha1"]+ " ,IAN parsing error,JSON serialization successful, writing JSON string error, no entry generated")
        except:
            if savecert["warnings"] :
                print("sha1: " + jsonObj["sha1"]+ " ,IAN parsing error,JSON serialization error, no entry generated" + " ,warnings: "+savecert["warnings"])
            else:
                print("sha1: " + jsonObj["sha1"]+ " ,IAN parsing error,JSON serialization error, no entry generated")
        continue

    # Parse AIA
    try:
        with warnings.catch_warnings(record=True) as ws:
            aia = extensions.get_extension_for_oid(ObjectIdentifier("1.3.6.1.5.5.7.1.1")).value
            dess = aia._descriptions
            savecert["aia"] = []
            for des in dess :
                savecert["aia"].append(PhraseAccessDes(des))
 
            if ws:
                for w in ws:
                    savecert["warnings"].append({"category":str(w.category),"message":str(w.message)})
    except x509.ExtensionNotFound as e:
        savecert["aia"] = None 
    except Exception as e :
        savecert["aia"] = None
        savecert["status"] = False
        savecert["err"].append({"type":str(type(e).__name__),"content":str(e)})
        
        try :
            strObj = json.dumps(savecert)
            try :
                with open(args.output,'a') as save:
                    save.write(strObj+"\n")
            except:
                if savecert["warnings"] :
                    print("sha1: " + jsonObj["sha1"]+ " ,The aia parsing error occurred, the JSON serialization was successful, the writing of the JSON string was incorrect, and no entry was generated" + " ,warnings: "+savecert["warnings"])
                else:
                    print("sha1: " + jsonObj["sha1"]+ " ,The aia parsing error occurred, the JSON serialization was successful, the writing of the JSON string was incorrect, and no entry was generated")
        except:
            if savecert["warnings"] :
                print("sha1: " + jsonObj["sha1"]+ " ,There was an error in aia parsing and JSON serialization, and no entries were generated" + " ,warnings: "+savecert["warnings"])
            else:
                print("sha1: " + jsonObj["sha1"]+ " ,There was an error in aia parsing and JSON serialization, and no entries were generated")
        continue

    # Parse SIA
    try:
        with warnings.catch_warnings(record=True) as ws:
            sia = extensions.get_extension_for_oid(ExtensionOID.SUBJECT_INFORMATION_ACCESS).value
            dess = sia._descriptions
            savecert["sia"] = []
            for des in dess :
                savecert["sia"].append(PhraseAccessDes(des))
            
            if ws:
                for w in ws:
                    savecert["warnings"].append({"category":str(w.category),"message":str(w.message)})
    except x509.ExtensionNotFound as e:
        savecert["sia"] = None 
    except Exception as e :
        savecert["sia"] = None
        savecert["status"] = False
        savecert["err"].append({"type":str(type(e).__name__),"content":str(e)})
        
        try :
            strObj = json.dumps(savecert)
            try :
                with open(args.output,'a') as save:
                    save.write(strObj+"\n")
            except:
                if savecert["warnings"] :
                    print("sha1: " + jsonObj["sha1"]+ " ,The sia parsing error,JSON serialization successful, writing JSON string error, no entry generated" + " ,warnings: "+savecert["warnings"])
                else:
                    print("sha1: " + jsonObj["sha1"]+ " ,The sia parsing error,JSON serialization successful, writing JSON string error, no entry generated")
        except:
            if savecert["warnings"] :
                print("sha1: " + jsonObj["sha1"]+ " ,The sia parsing error,JSON serialization error, no entry generated" + " ,warnings: "+savecert["warnings"])
            else:
                print("sha1: " + jsonObj["sha1"]+ " ,The sia parsing error,JSON serialization error, no entry generated")
        continue

    # Parse CertPolicies
    try:
        with warnings.catch_warnings(record=True) as ws:
            cps = extensions.get_extension_for_oid(ObjectIdentifier("2.5.29.32")).value
            policyInfos = cps._policies
            savecert["certPolicies"] = []
            for policyInfo in policyInfos:
                savecert["certPolicies"].append(PolicyInfomation(policyInfo).toDict())

            if ws:
                for w in ws:
                    savecert["warnings"].append({"category":str(w.category),"message":str(w.message)})
    except x509.ExtensionNotFound as e:
        savecert["certPolicies"] = None 
    except Exception as e :
        savecert["certPolicies"] = None
        savecert["status"] = False
        savecert["err"].append({"type":str(type(e).__name__),"content":str(e)})
        
        try :
            strObj = json.dumps(savecert)
            try :
                with open(args.output,'a') as save:
                    save.write(strObj+"\n")
            except:
                if savecert["warnings"] :
                    print("sha1: " + jsonObj["sha1"]+ " ,certPolicies parsing error,JSON serialization successful, writing JSON string error, no entry generated" + " ,warnings: "+savecert["warnings"])
                else:
                    print("sha1: " + jsonObj["sha1"]+ " ,certPolicies parsing error,JSON serialization successful, writing JSON string error, no entry generated")
        except:
            if savecert["warnings"] :
                print("sha1: " + jsonObj["sha1"]+ " ,certPolicies parsing error,JSON serialization error, no entry generated" + " ,warnings: "+savecert["warnings"])
            else:
                print("sha1: " + jsonObj["sha1"]+ " ,certPolicies parsing error,JSON serialization error, no entry generated")
        continue

    # Parse CrlDis
    try:
        with warnings.catch_warnings(record=True) as ws:
            CrlsDis = extensions.get_extension_for_oid(ObjectIdentifier("2.5.29.31")).value
            savecert["crlDistributionPoints"] = []
            for dis in CrlsDis._distribution_points:
                savecert["crlDistributionPoints"].append(DistributionPoint(dis).toDict())

            if ws:
                for w in ws:
                    savecert["warnings"].append({"category":str(w.category),"message":str(w.message)})
    except x509.ExtensionNotFound as e:
        savecert["crlDistributionPoints"] = None 
    except Exception as e :
        savecert["crlDistributionPoints"] = None
        savecert["status"] = False
        savecert["err"].append({"type":str(type(e).__name__),"content":str(e)})
        
        try :
            strObj = json.dumps(savecert)
            try :
                with open(args.output,'a') as save:
                    save.write(strObj+"\n")
            except:
                if savecert["warnings"] :
                    print("sha1: " + jsonObj["sha1"]+ " ,crlDistributionPoints parsing error,JSON serialization successful, writing JSON string error, no entry generated" + " ,warnings: "+savecert["warnings"])
                else:
                    print("sha1: " + jsonObj["sha1"]+ " ,crlDistributionPoints parsing error,JSON serialization successful, writing JSON string error, no entry generated")
        except:
            if savecert["warnings"] :
                print("sha1: " + jsonObj["sha1"]+ " ,crlDistributionPoints parsing error,JSON serialization error, no entry generated" + " ,warnings: "+savecert["warnings"])
            else:
                print("sha1: " + jsonObj["sha1"]+ " ,crlDistributionPoints parsing error,JSON serialization error, no entry generated")
        continue
    
    # Parse KeyUsage
    try:
        with warnings.catch_warnings(record=True) as ws:
            
            KeyUsage = extensions.get_extension_for_oid(ObjectIdentifier("2.5.29.15")).value
            savecert["KeyUsage"] = []
            if KeyUsage.digital_signature == True :
                savecert["KeyUsage"].append("digital_signature")
            if KeyUsage.content_commitment == True :
                savecert["KeyUsage"].append("content_commitment")
            if KeyUsage.key_encipherment == True :
                savecert["KeyUsage"].append("key_encipherment")
            if KeyUsage.data_encipherment == True :
                savecert["KeyUsage"].append("data_encipherment")
            if KeyUsage.key_agreement == True :
                savecert["KeyUsage"].append("key_agreement")
            if KeyUsage.key_cert_sign == True :
                savecert["KeyUsage"].append("key_cert_sign")
            if KeyUsage.crl_sign == True :
                savecert["KeyUsage"].append("crl_sign")
            if KeyUsage._encipher_only == True:
                savecert["KeyUsage"].append("crl_sign")
            if KeyUsage._decipher_only == True:
                savecert["KeyUsage"].append("decipher_only")
            
            if ws:
                for w in ws:
                    savecert["warnings"].append({"category":str(w.category),"message":str(w.message)})
    except x509.ExtensionNotFound as e:
        savecert["KeyUsage"] = None 
    except Exception as e :
        savecert["KeyUsage"] = None
        savecert["status"] = False
        savecert["err"].append({"type":str(type(e).__name__),"content":str(e)})
        
        try :
            strObj = json.dumps(savecert)
            try :
                with open(args.output,'a') as save:
                    save.write(strObj+"\n")
            except:
                if savecert["warnings"] :
                    print("sha1: " + jsonObj["sha1"]+ " ,KeyUsage parsing error,JSON serialization successful, writing JSON string error, no entry generated" + " ,warnings: "+savecert["warnings"])
                else:
                    print("sha1: " + jsonObj["sha1"]+ " ,KeyUsage parsing error,JSON serialization successful, writing JSON string error, no entry generated")
        except:
            if savecert["warnings"] :
                print("sha1: " + jsonObj["sha1"]+ " ,KeyUsage parsing error,JSON serialization error, no entry generated" + " ,warnings: "+savecert["warnings"])
            else:
                print("sha1: " + jsonObj["sha1"]+ " ,KeyUsage parsing error,JSON serialization error, no entry generated")
        continue
            
    # Parse ExtendedKeyUsage
    try:
        with warnings.catch_warnings(record=True) as ws:
            ExtendedKeyUsage = extensions.get_extension_for_oid(ObjectIdentifier("2.5.29.37")).value
            EKUs = ExtendedKeyUsage._usages
            savecert["ExtendedKeyUsage"] = []
            for eku in EKUs :
                savecert["ExtendedKeyUsage"].append(eku.dotted_string)
            
            if ws:
                for w in ws:
                    savecert["warnings"].append({"category":str(w.category),"message":str(w.message)})
    except x509.ExtensionNotFound as e:
        savecert["ExtendedKeyUsage"] = None 
    except Exception as e :
        savecert["ExtendedKeyUsage"] = None
        savecert["status"] = False
        savecert["err"].append({"type":str(type(e).__name__),"content":str(e)})
        
        try :
            strObj = json.dumps(savecert)
            try :
                with open(args.output,'a') as save:
                    save.write(strObj+"\n")
            except:
                if savecert["warnings"] :
                    print("sha1: " + jsonObj["sha1"]+ " ,ExtendedKeyUsage parsing error,JSON serialization successful, writing JSON string error, no entry generated" + " ,warnings: "+savecert["warnings"])
                else:
                    print("sha1: " + jsonObj["sha1"]+ " ,ExtendedKeyUsage parsing error,JSON serialization successful, writing JSON string error, no entry generated")
        except:
            if savecert["warnings"] :
                print("sha1: " + jsonObj["sha1"]+ " ,ExtendedKeyUsage parsing error,JSON serialization error, no entry generated" + " ,warnings: "+savecert["warnings"])
            else:
                print("sha1: " + jsonObj["sha1"]+ " ,ExtendedKeyUsage parsing error,JSON serialization error, no entry generated")
        continue

    try :
        strObj = json.dumps(savecert)
        try :
            with open(args.output,'a') as save:
                save.write(strObj+"\n")
        except:
            if savecert["warnings"] :
                print("sha1: " + jsonObj["sha1"]+ " ,The certificate parsing was successful, the JSON sequence was successful, the write failed, and no entries were generated" + " ,warnings: "+savecert["warnings"])
            else:
                print("sha1: " + jsonObj["sha1"]+ " ,The certificate parsing was successful, the JSON sequence was successful, the write failed, and no entries were generated")
    except:
        if savecert["warnings"] :
            print("sha1: " + jsonObj["sha1"]+ " ,The certificate parsing was successful, but the JSON serialization failed and no entries were generated" + " ,warnings: "+savecert["warnings"])
        else:
            print("sha1: " + jsonObj["sha1"]+ " ,The certificate parsing was successful, but the JSON serialization failed and no entries were generated")