from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.x509.name import _ASN1Type
import datetime
from cryptography import x509
import ipaddress
import json
import typing
import hashlib
from cryptography.hazmat.bindings._rust import ObjectIdentifier

ASN1Types ={ 
    "UTF8String":_ASN1Type.UTF8String,
    "TeletexString":_ASN1Type.T61String,
    "UniversalString":_ASN1Type.UniversalString,
    "PrintableString":_ASN1Type.PrintableString,
    "BMPString":_ASN1Type.BMPString, 
    "VisibleString":_ASN1Type.VisibleString,
    "NumericString":_ASN1Type.NumericString,
    "OctetString":_ASN1Type.OctetString,
    "BitString":_ASN1Type.BitString,
    "Ia5String":_ASN1Type.IA5String,
    "GeneralizedTime":_ASN1Type.GeneralizedTime,
    "UTCTime":_ASN1Type.UTCTime
}
class TypeAndValue:
    # type = NameOID.OIDs
    # value 
    # encoding _ASN1_TYPE
    # des The description of this TypeAndValue generated
    def __init__(self,type:NameOID,value,encoding:_ASN1Type):
        self.type = type
        self.value = value
        self.encoding = encoding

def listToTypeAndValue(plist):
    """
    Input example: ["12.3.4.67",strValue|bytesValue,"BMPString"]
    The input of OID must be dotted str
    """
    return x509.NameAttribute(ObjectIdentifier(plist[0]),plist[1],ASN1Types[plist[2]])

def listToRDN(RDN):
    """
    Input: [TypeAndValueObj]
    """
    if RDN ==None: 
        return None 
    saveattr=[]
    for rdn in RDN :
        saveattr.append(listToTypeAndValue(rdn))
    return x509.RelativeDistinguishedName(saveattr)


def listToName(RDNS): 
    """
    The input list becomes x509.Name. If there is no RDN, None is returned.
    """
    numRDN = len(RDNS)
    saveRDN = []
    if numRDN >=0:
        for rdn in RDNS:
            saveRDN.append(x509.RelativeDistinguishedName(listToRDN(rdn)))
        return x509.Name(saveRDN)
    else:
        return None
    
Ipdefined = typing.Union[ 
    ipaddress.IPv4Address,
    ipaddress.IPv6Address,
    ipaddress.IPv4Network,
    ipaddress.IPv6Network,
]

GeneralNameMapToString ={
    "RFC822Name" : [1,x509.RFC822Name,str],
    "DNSName" : [2,x509.DNSName,str],
    "URI" : [6,x509.UniformResourceIdentifier,str],
    "DirectoryName" : [4,x509.DirectoryName,x509.Name],
    "RegID" : [8,x509.RegisteredID,ObjectIdentifier],
    "IP" : [7,x509.IPAddress,Ipdefined],
    "OtherName" : [0,x509.OtherName,str,bytes]
}

MapGN ={
    x509.RFC822Name :"[1] RFC822Name",
    x509.DNSName : "[2] DNSName",
    x509.UniformResourceIdentifier : "[6] URI",
    x509.DirectoryName : "[4] DirectoryName",
    x509.RegisteredID : "[8] RegID",
    x509.IPAddress : "[7] IP",
    x509.OtherName : "[0] OtherName"
}

def listToGeneralName(GeneralName) :
    if GeneralNameMapToString[GeneralName[0]][1] == x509.OtherName:
        return x509.OtherName(ObjectIdentifier(GeneralName[1]),GeneralName[2])
    elif GeneralNameMapToString[GeneralName[0]][1] == x509.IPAddress:
        # ["IP",4a/6a/4n/6n,v1,v2|None]
        if GeneralName[1] =="4a":
            return x509.IPAddress(ipaddress.IPv4Address(GeneralName[2]))
        if GeneralName[1] =="6a":
            return x509.IPAddress(ipaddress.IPv6Address(GeneralName[2]))
        if GeneralName[1] =="4n":
            return x509.IPAddress(ipaddress.IPv4Network(GeneralName[2],GeneralName[3]))
        if GeneralName[1] =="6n":
            return x509.IPAddress(ipaddress.IPv6Network(GeneralName[2],GeneralName[3]))
    elif GeneralNameMapToString[GeneralName[0]][1] == x509.RegisteredID :
        return x509.RegisteredID(ObjectIdentifier(GeneralName[1]))
    elif GeneralNameMapToString[GeneralName[0]][1] == x509.DirectoryName :
        return x509.DirectoryName(listToName(GeneralName[1]))
    else:
        return GeneralNameMapToString[GeneralName[0]][1](GeneralName[1])


def listToGeneralNames(GeneralNames) :
    """
    Input: [[listToGeneralName],[......]]
    """
    if GeneralNames ==None: 
        return None
    gns =[]
    for gn in GeneralNames :
        gns.append(listToGeneralName(gn))
    return x509.GeneralNames(gns)

def listToInfoAccess(infos):
    """
    Input: [[dotted_OIDstring,[listToGeneralName]]]
    The AIA field is checked for OID. Using an illegal OID will result in an error.
    """
    ias =[]
    for info in infos:
        ias.append(x509.AccessDescription(ObjectIdentifier(info[0]),listToGeneralName(info[1])))
    return ias

def listToAIA(infos):
    itr = listToInfoAccess(infos)
    return x509.AuthorityInformationAccess(itr)

def listToSIA(infos):
    itr = listToInfoAccess(infos)
    return x509.SubjectInformationAccess(itr)

reasonFlags = {
    "unspecified":x509.ReasonFlags.unspecified,
    "keyCompromise":x509.ReasonFlags.key_compromise,
    "cACompromise":x509.ReasonFlags.ca_compromise,
    "affiliationChanged":x509.ReasonFlags.affiliation_changed,
    "superseded":x509.ReasonFlags.superseded,
    "cessationOfOperation":x509.ReasonFlags.cessation_of_operation,
    "certificateHold":x509.ReasonFlags.certificate_hold,
    "privilegeWithdrawn":x509.ReasonFlags.privilege_withdrawn,
    "aACompromise":x509.ReasonFlags.aa_compromise,
    "removeFromCRL":x509.ReasonFlags.remove_from_crl
    }

def stringlistToRFlist(plist):
    buf=[]
    for itm in plist:
        buf.append(reasonFlags[itm])
    return buf
    
def listToCrls(crls):
    """
    Input: [[listToGeneralnames,rdn,[readFlags],listToGeneralNames],[......]]
    """
    CRL = []
    for crl in crls:
        if crl[2]==None:
            CRL.append(x509.DistributionPoint(listToGeneralNames(crl[0]),listToRDN(crl[1]),None,listToGeneralNames(crl[3])))
        else:
            CRL.append(x509.DistributionPoint(listToGeneralNames(crl[0]),listToRDN(crl[1]),frozenset(stringlistToRFlist(crl[2])),listToGeneralNames(crl[3])))
    return x509.CRLDistributionPoints(CRL)

def listToNoticeReference(plist):
    if plist==None:
        return None
    return x509.NoticeReference(plist[0],plist[1])

def listToUserNotice(plist):
    """
    Input: [[listToNoticeReference]|None,str|None]
    """
    # if plist==None:
    #     return None
    # else:
    return x509.UserNotice(listToNoticeReference(plist[0]),plist[1])
    
def listToPolicyInfo(pInfo):
    """
    Input: [OID_string:eg,"1.2.3.4",[[type:str/x509.UserNotice],[[listToNoticeReference]|None,str|None]]|None]
    """
    if pInfo[1] ==None:
        return x509.PolicyInformation(ObjectIdentifier(pInfo[0]))
    else:
        buf =[]
        len_itr = len(pInfo[1][0])
        for i in range(len_itr):
            if pInfo[1][0][i] =="str":
                buf.append(pInfo[1][1][i])
            if pInfo[1][0][i] == "x509.UserNotice":
                buf.append(listToUserNotice(pInfo[1][1][i]))
        return x509.PolicyInformation(ObjectIdentifier(pInfo[0]),buf)
    
def listToPolicy(Cp):
    buf =[]
    for cp in Cp:
        buf.append(listToPolicyInfo(cp))
    return x509.CertificatePolicies(buf)

class Template:
    def __init__(
            self,certpath,Subject,Issuer,
            SAN,SAN_cri,
            IAN,IAN_cri,
            CRL,CRL_cri,
            Policies,Policies_cri,
            AIA,AIA_cri,
            SIA,SIA_cri
            ):
        with open("CertificateGenerator/SelfSignedRoot/cert/root.pem", "rb") as cert_file:
            root_cert = x509.load_pem_x509_certificate(cert_file.read())

        with open("CertificateGenerator/SelfSignedRoot/key/root.pem", "rb") as key_file:
            self.root_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None, 
            )
        self.cert = x509.CertificateBuilder()
        self.cert_path = certpath
        self.Subject = Subject
        self.Issuer = Issuer
        self.SAN = SAN
        self.IAN = IAN
        self.CRL =CRL
        self.Policies = Policies
        self.AIA = AIA
        self.SIA = SIA
        self.desDict = {
            "Subject":Subject,
            "Issuer":Issuer
        }
        
        self.key = rsa.generate_private_key(key_size=2048,public_exponent=65537)
        self.cert = self.cert.subject_name(
            listToName(Subject)
        ).issuer_name(
            listToName(Issuer)
        ).public_key(
            self.key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=90)
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()),
            critical=False
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(self.root_key.public_key()),
            critical=False
        )
        if SAN !=None :
            self.cert = self.cert.add_extension(x509.SubjectAlternativeName(listToGeneralNames(SAN)),critical=SAN_cri)
            self.desDict["SAN"] = SAN
        if IAN !=None :
            self.cert = self.cert.add_extension(x509.IssuerAlternativeName(listToGeneralNames(IAN)),critical=IAN_cri)
            self.desDict["IAN"] = IAN
        if CRL !=None :
            self.cert = self.cert.add_extension(listToCrls(CRL),critical=CRL_cri)
            self.desDict["CRLDis"] = CRL
        if Policies !=None :
            self.cert = self.cert.add_extension(listToPolicy(Policies),critical=Policies_cri)
            self.desDict["CertPolicies"] = Policies
        if AIA !=None:
            self.cert = self.cert.add_extension(listToAIA(AIA),critical=AIA_cri)
            self.desDict["AIA"] = AIA
        if SIA !=None:
            self.cert = self.cert.add_extension(listToSIA(SIA),critical=SIA_cri)
            self.desDict["SIA"] = SIA

    def gen_cert(self,DesFilepath:str,WriteFile:str,FocusField:str,FocusFieldValue:str,InsertValue:str,des:str) -> None:
        self.cert = self.cert.sign(self.root_key,hashes.SHA256())
        with open(self.cert_path,"wb") as certfile:
            certfile.write(self.cert.public_bytes(serialization.Encoding.PEM))

        # save certificate meta-information
        with open(DesFilepath,'a') as f:
            a = {}
            a["Path"] = self.cert_path
            a["sha1"] = hashlib.sha1(self.cert.fingerprint(hashes.SHA1())).hexdigest()
            a["description"] = self.desDict
            desc = json.dumps(a,ensure_ascii=False)
            f.write(desc+'\n')

        # save test cases
        with open(WriteFile,'a') as f:
            a ={}
            a["sha1"] = hashlib.sha1(self.cert.fingerprint(hashes.SHA1())).hexdigest()
            with open(self.cert_path,"r") as certfile:
                a["pem"] = certfile.read()
            a["FocusField"] = FocusField
            a["FocusFieldValue"] = FocusFieldValue
            a["InsertValue"] = InsertValue
            a["description"] = des
            json_obj = json.dumps(a)
            f.write(json_obj+'\n')
