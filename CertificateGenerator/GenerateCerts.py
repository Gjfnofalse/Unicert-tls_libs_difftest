from Generator import *
from cryptography.hazmat.bindings._rust import ObjectIdentifier
from cryptography.hazmat._oid import NameOID
import json 
import random
import sys

DN=['2.5.4.3','2.5.4.15','0.9.2342.19200300.100.1.25','1.2.840.113549.1.9.1','2.5.4.7','2.5.4.11','2.5.4.10','2.5.4.5','2.5.4.8']
ex_ascii_chars = []
for i in range(0x0000, 0x00FF + 1): 
    char = chr(i)
    formatted_char = f'00{i:02X}'
    ex_ascii_chars.append([char,formatted_char])

UTF8String = ex_ascii_chars
def unicode_range_to_chars(start_hex, end_hex):
    start = int(start_hex, 16)
    end = int(end_hex, 16)
    return [chr(code_point) for code_point in range(start, end + 1)]

def random_codepoints(start_hex, end_hex, count=1):
    chars = unicode_range_to_chars(start_hex, end_hex)
    selected_chars = random.sample(chars, count)
    return sorted([f'{ord(char):04X}' for char in selected_chars])

def sampling_random_fromFile(path:str):
    CharList = []
    with open(path,'r',encoding='utf-8') as file:
        for line in file:
            json_obj = json.loads(line)
            random_charlist = random_codepoints(json_obj["start"],json_obj["end"])
            for char in random_charlist:
                CharList.append([chr(int(char,16)),char])
    return CharList

UTF8String.extend(sampling_random_fromFile('CertificateGenerator/Block_unicode15.0.json'))

RandomCharList = []

for char in UTF8String:
    RandomCharList.append(char[1])

# The current random UTF8String list needs to be stored.
with open(sys.argv[2],'a') as file:
    json.dump(RandomCharList,file)

UniversalString = UTF8String

def insert_random_char(s, char):
    # Insert characters at random positions other than the beginning and the end(This can avoid some other special circumstances, which are not within the scope of our experiment's test)
    length = len(s)
    index = random.randint(1, length-1)
    new_string = s[:index] + char + s[index:]
    return new_string

ASN1_list = [
    "PrintableString",
    "Ia5String",
    "UTF8String",
    "TeletexString",
    "BMPString"
]

BaseSubject = [[["2.5.4.3","BaseSubject",'UTF8String']]]
BaseIssuer = [[["2.5.4.3","BaseIssuer",'UTF8String']]]

# GenerateCerts-Name
for type in DN:
    for v in ASN1_list:
        for vi in UTF8String:
            value = insert_random_char("subject", vi[0])
            v_len = len(value)
            value_issuer = insert_random_char("issuer", vi[0]) 
            encodingType = v
            attrType = type
            RDN = [[attrType,value,encodingType]]
            Subject = [[[attrType,value,encodingType]]]
            Issuer = [[[attrType,value_issuer,encodingType]]]
            try:
                cert = Template(certpath=sys.argv[1]+"/cert/"+"Subject "+attrType + " "+encodingType+" value:"+vi[1]+".pem",Subject=Subject,Issuer=BaseIssuer,SAN=None,SAN_cri=False,IAN=None,IAN_cri=False
                ,CRL=None,CRL_cri=False,Policies=None,Policies_cri=False,AIA=None,AIA_cri=False
                ,SIA=None,SIA_cri=False)
                cert.gen_cert(sys.argv[1]+"/description.json",sys.argv[1]+"/input.json","Subject "+attrType + " "+encodingType,value,vi[1],"NoDes")
            except Exception as e:
                print(str(e)+' '+sys.argv[1]+"/cert/"+"Subject "+attrType + " "+encodingType+" value:"+vi[1]+'\n')

            try:
                cert89 = Template(certpath=sys.argv[1]+"/cert/"+"Issuer "+attrType + " "+encodingType+" value:"+vi[1]+".pem",Subject=BaseSubject,Issuer=Issuer,SAN=None,SAN_cri=False,IAN=None,IAN_cri=False
                ,CRL=None,CRL_cri=False,Policies=None,Policies_cri=False,AIA=None,AIA_cri=False
                ,SIA=None,SIA_cri=False)
                cert89.gen_cert(sys.argv[1]+"/description.json",sys.argv[1]+"/input.json","Issuer "+attrType + " "+encodingType,value_issuer,vi[1],"NoDes")
            except Exception as e:
                print(str(e)+' ' + sys.argv[1]+"/cert/"+"Issuer "+attrType + " "+encodingType+" value:"+vi[1]+'\n')

            san_dn = [["DirectoryName",Subject]]
            ian_dn = [["DirectoryName",Subject]]
            try:
                cert1 = Template(certpath=sys.argv[1]+"/cert/"+"SAN DirectoryName "+attrType+" "+encodingType+" value:"+vi[1]+".pem",Subject=BaseSubject,Issuer=BaseIssuer,SAN=san_dn,SAN_cri=False,IAN=None,IAN_cri=False
                    ,CRL=None,CRL_cri=False,Policies=None,Policies_cri=False,AIA=None,AIA_cri=False
                    ,SIA=None,SIA_cri=False)
                cert1.gen_cert(sys.argv[1]+"/description.json",sys.argv[1]+"/input.json","SAN DirectoryName "+attrType+" "+encodingType,value,vi[1],"NoDes")
            except Exception as e:
                print(str(e)+' '+sys.argv[1]+"/cert/"+"SAN DirectoryName "+attrType+" "+encodingType+" value:"+vi[1]+'\n')
            
            try:
                cert2 = Template(certpath=sys.argv[1]+"/cert/"+"IAN DirectoryName "+attrType+" "+encodingType+" value:"+vi[1]+".pem",Subject=BaseSubject,Issuer=BaseIssuer,SAN=None,SAN_cri=False,IAN=ian_dn,IAN_cri=False
                ,CRL=None,CRL_cri=False,Policies=None,Policies_cri=False,AIA=None,AIA_cri=False
                ,SIA=None,SIA_cri=False)
                cert2.gen_cert(sys.argv[1]+"/description.json",sys.argv[1]+"/input.json","IAN DirectoryName "+attrType+" "+encodingType,value,vi[1],"NoDes")
            except Exception as e:
                print(str(e)+' '+sys.argv[1]+"/cert/"+"IAN DirectoryName "+attrType+" "+encodingType+" value:"+vi[1]+'\n')

            crl_dn = [
            [None,RDN,["cACompromise","privilegeWithdrawn"],
            [["DNSName","www.google.com"]]]
            ]

            try:
                cert8 = Template(certpath=sys.argv[1]+"/cert/"+"CRL RDN "+attrType+" "+encodingType+" value:"+vi[1]+".pem",Subject=BaseSubject,Issuer=BaseIssuer,SAN=None,SAN_cri=False,IAN=None,IAN_cri=False
                ,CRL=crl_dn,CRL_cri=False,Policies=None,Policies_cri=False,AIA=None,AIA_cri=False
                ,SIA=None,SIA_cri=False)
                cert8.gen_cert(sys.argv[1]+"/description.json",sys.argv[1]+"/input.json","CRL RDN "+attrType+" "+encodingType,value,vi[1],"NoDes")
            except Exception as e:
                print(str(e)+" "+sys.argv[1]+"/cert/"+"CRL RDN "+attrType+" "+encodingType+" value:"+vi[1]+'\n')
            
            crl_dn_fullname = [
            [[["DirectoryName",Subject]],None,["cACompromise","privilegeWithdrawn"],
            [["DNSName","www.testfullname.com"]]]
            ]
            try:
                cert71 = Template(certpath=sys.argv[1]+"/cert/"+"CRL fullname DirectoryName "+attrType+" "+encodingType+" value:"+vi[1]+".pem",Subject=BaseSubject,Issuer=BaseIssuer,SAN=None,SAN_cri=False,IAN=None,IAN_cri=False
                ,CRL=crl_dn_fullname,CRL_cri=False,Policies=None,Policies_cri=False,AIA=None,AIA_cri=False
                ,SIA=None,SIA_cri=False)
                cert71.gen_cert(sys.argv[1]+"/description.json",sys.argv[1]+"/input.json","CRL fullname DirectoryName "+attrType+" "+encodingType,value,vi[1],"NoDes")
            except Exception as e:
                print(str(e)+" "+sys.argv[1]+"/cert/"+"CRL fullname DirectoryName "+attrType+" "+encodingType+" value:"+vi[1]+'\n')

            crl_dn_crlissuer =[
                [[["DNSName","www.testcrlissuer.com"]],None,["cACompromise","privilegeWithdrawn"],
                [["DirectoryName",Subject]]]
            ]

            try:
                cert72 = Template(certpath=sys.argv[1]+"/cert/"+"CRL crlissuer DirectoryName "+attrType+" "+encodingType+" value:"+vi[1]+".pem",Subject=BaseSubject,Issuer=BaseIssuer,SAN=None,SAN_cri=False,IAN=None,IAN_cri=False
                ,CRL=crl_dn_crlissuer,CRL_cri=False,Policies=None,Policies_cri=False,AIA=None,AIA_cri=False
                ,SIA=None,SIA_cri=False)
                cert72.gen_cert(sys.argv[1]+"/description.json",sys.argv[1]+"/input.json","CRL crlissuer DirectoryName "+attrType+" "+encodingType,value,vi[1],"NoDes")
            except Exception as e:
                print(str(e)+" "+sys.argv[1]+"/cert/"+"CRL crlissuer DirectoryName "+attrType+" "+encodingType+" value:"+vi[1]+'\n')

            aia_dn_caissuer = [["1.3.6.1.5.5.7.48.2",["DirectoryName",Subject]]]
            sia_dn_caissuer = [["1.3.6.1.5.5.7.48.2",["DirectoryName",Subject]]]

            aia_dn_ocsp = [["1.3.6.1.5.5.7.48.1",["DirectoryName",Subject]]]
            sia_dn_ocsp = [["1.3.6.1.5.5.7.48.1",["DirectoryName",Subject]]]

            try:
                cert73 = Template(certpath=sys.argv[1]+"/cert/"+"SIA CaIssuer DirectoryName "+attrType+" "+encodingType+" value:"+vi[1]+".pem",Subject=BaseSubject,Issuer=BaseIssuer,SAN=None,SAN_cri=False,IAN=None,IAN_cri=False
                    ,CRL=None,CRL_cri=False,Policies=None,Policies_cri=False,AIA=None,AIA_cri=False
                    ,SIA=sia_dn_caissuer,SIA_cri=False)
                cert73.gen_cert(sys.argv[1]+"/description.json",sys.argv[1]+"/input.json","SIA CaIssuer DirectoryName "+attrType+" "+encodingType,value,vi[1],"NoDes")
            except Exception as e:
                print(str(e)+" "+sys.argv[1]+"/cert/"+"SIA CaIssuer DirectoryName "+attrType+" "+encodingType+" value:"+vi[1]+'\n')
                
            try:
                cert76 = Template(certpath=sys.argv[1]+"/cert/"+"AIA CaIssuer DirectoryName "+attrType+" "+encodingType+" value:"+vi[1]+".pem",Subject=BaseSubject,Issuer=BaseIssuer,SAN=None,SAN_cri=False,IAN=None,IAN_cri=False
                    ,CRL=None,CRL_cri=False,Policies=None,Policies_cri=False,AIA=aia_dn_caissuer,AIA_cri=False
                    ,SIA=None,SIA_cri=False)
                cert76.gen_cert(sys.argv[1]+"/description.json",sys.argv[1]+"/input.json","AIA CaIssuer DirectoryName "+attrType+" "+encodingType,value,vi[1],"NoDes")
            except Exception as e:
                print(str(e)+" "+sys.argv[1]+"/cert/"+"AIA CaIssuer DirectoryName "+attrType+" "+encodingType+" value:"+vi[1]+'\n' )

            try:
                cert74 = Template(certpath=sys.argv[1]+"/cert/"+"AIA OCSP DirectoryName "+attrType+" "+encodingType+" value:"+vi[1]+".pem",Subject=BaseSubject,Issuer=BaseIssuer,SAN=None,SAN_cri=False,IAN=None,IAN_cri=False
                    ,CRL=None,CRL_cri=False,Policies=None,Policies_cri=False,AIA=aia_dn_ocsp,AIA_cri=False
                    ,SIA=None,SIA_cri=False)
                cert74.gen_cert(sys.argv[1]+"/description.json",sys.argv[1]+"/input.json","AIA OCSP DirectoryName "+attrType+" "+encodingType,value,vi[1],"NoDes")
            except Exception as e:
                print(str(e)+" "+sys.argv[1]+"/cert/"+"AIA OCSP DirectoryName "+attrType+" "+encodingType+" value:"+vi[1]+'\n' )

            try:
                cert75 = Template(certpath=sys.argv[1]+"/cert/"+"SIA OCSP DirectoryName "+attrType+" "+encodingType+" value:"+vi[1]+".pem",Subject=BaseSubject,Issuer=BaseIssuer,SAN=None,SAN_cri=False,IAN=None,IAN_cri=False
                    ,CRL=None,CRL_cri=False,Policies=None,Policies_cri=False,AIA=None,AIA_cri=False
                    ,SIA=sia_dn_ocsp,SIA_cri=False)
                cert75.gen_cert(sys.argv[1]+"/description.json",sys.argv[1]+"/input.json","SIA OCSP DirectoryName "+attrType+" "+encodingType,value,vi[1],"NoDes")
            except Exception as e:
                print(str(e)+" "+sys.argv[1]+"/cert/"+"SIA OCSP DirectoryName "+attrType+" "+encodingType+" value:"+vi[1]+'\n' )
            
#GenerateCerts-GeneralName
san_list=["DNSName","RFC822Name","URI"]

BaseDNSName = "www.google.com"
BaseEmail = "usr@usr.com"
BaseUri = "http://test.test"
for gn in san_list:
    for vi in UTF8String:
        encodingType = gn 
        if gn=="DNSName":
            value = insert_random_char(BaseDNSName, vi[0])
        if gn=="RFC822Name":
            value = insert_random_char(BaseEmail, vi[0])
        if gn=="URI":
            value = insert_random_char(BaseUri, vi[0])
        SAN = [[gn,value]]
        IAN = [[gn,value]]
        
        try:
            cert3 = Template(certpath=sys.argv[1]+"/cert/"+"SAN "+gn+" value:"+vi[1]+".pem",Subject=BaseSubject,Issuer=BaseIssuer,SAN=SAN,SAN_cri=False,IAN=None,IAN_cri=False
            ,CRL=None,CRL_cri=False,Policies=None,Policies_cri=False,AIA=None,AIA_cri=False
            ,SIA=None,SIA_cri=False)
            cert3.gen_cert(sys.argv[1]+"/description.json",sys.argv[1]+"/input.json","SAN "+gn,value,vi[1],"NoDes")
        except Exception as e:
            print(str(e)+" "+sys.argv[1]+"/cert/"+"SAN "+gn+" value:"+vi[1]+'\n')
        
        try:
            cert4 = Template(certpath=sys.argv[1]+"/cert/"+"IAN "+gn+" value:"+vi[1]+".pem",Subject=BaseSubject,Issuer=BaseIssuer,SAN=None,SAN_cri=False,IAN=IAN,IAN_cri=False
            ,CRL=None,CRL_cri=False,Policies=None,Policies_cri=False,AIA=None,AIA_cri=False
            ,SIA=None,SIA_cri=False)
            cert4.gen_cert(sys.argv[1]+"/description.json",sys.argv[1]+"/input.json","IAN "+gn,value,vi[1],"NoDes")
        except Exception as e:
            print(str(e)+" "+sys.argv[1]+"/cert/"+"IAN "+gn+" value:"+vi[1]+'\n')

        aia = [["1.3.6.1.5.5.7.48.2",[gn,value]]]
        sia = [["1.3.6.1.5.5.7.48.2",[gn,value]]]

        aia_ocsp = [["1.3.6.1.5.5.7.48.1",[gn,value]]]
        sia_ocsp = [["1.3.6.1.5.5.7.48.1",[gn,value]]]

        try:
            cert5 = Template(certpath=sys.argv[1]+"/cert/"+"AIA CaIssuer "+gn+" value:"+vi[1]+".pem",Subject=BaseSubject,Issuer=BaseIssuer,SAN=None,SAN_cri=False,IAN=None,IAN_cri=False
            ,CRL=None,CRL_cri=False,Policies=None,Policies_cri=False,AIA=aia,AIA_cri=False
            ,SIA=None,SIA_cri=False)
            cert5.gen_cert(sys.argv[1]+"/description.json",sys.argv[1]+"/input.json","AIA CaIssuer "+gn,value,vi[1],"NoDes")
        except Exception as e:
            print(str(e)+" "+sys.argv[1]+"/cert/"+"AIA CaIssuer "+gn+" value:"+vi[1]+'\n')

        try:
            cert6 = Template(certpath=sys.argv[1]+"/cert/"+"SIA CaIssuer "+gn+" value:"+vi[1]+".pem",Subject=BaseSubject,Issuer=BaseIssuer,SAN=None,SAN_cri=False,IAN=None,IAN_cri=False
            ,CRL=None,CRL_cri=False,Policies=None,Policies_cri=False,AIA=None,AIA_cri=False
            ,SIA=sia,SIA_cri=False)
            cert6.gen_cert(sys.argv[1]+"/description.json",sys.argv[1]+"/input.json","SIA CaIssuer "+gn,value,vi[1],"NoDes")
        except Exception as e:
            print(str(e)+" "+sys.argv[1]+"/cert/"+"SIA CaIssuer "+gn+" value:"+vi[1]+'\n')

        try:
            cert100 = Template(certpath=sys.argv[1]+"/cert/"+"AIA OCSP "+gn+" value:"+vi[1]+".pem",Subject=BaseSubject,Issuer=BaseIssuer,SAN=None,SAN_cri=False,IAN=None,IAN_cri=False
            ,CRL=None,CRL_cri=False,Policies=None,Policies_cri=False,AIA=aia_ocsp,AIA_cri=False
            ,SIA=None,SIA_cri=False)
            cert100.gen_cert(sys.argv[1]+"/description.json",sys.argv[1]+"/input.json","AIA OCSP "+gn,value,vi[1],"NoDes")
        except Exception as e:
            print(str(e)+" "+sys.argv[1]+"/cert/"+"AIA OCSP "+gn+" value:"+vi[1]+'\n')

        try:
            cert101 = Template(certpath=sys.argv[1]+"/cert/"+"SIA OCSP "+gn+" value:"+vi[1]+".pem",Subject=BaseSubject,Issuer=BaseIssuer,SAN=None,SAN_cri=False,IAN=None,IAN_cri=False
            ,CRL=None,CRL_cri=False,Policies=None,Policies_cri=False,AIA=None,AIA_cri=False
            ,SIA=sia_ocsp,SIA_cri=False)
            cert101.gen_cert(sys.argv[1]+"/description.json",sys.argv[1]+"/input.json","SIA OCSP "+gn,value,vi[1],"NoDes")
        except Exception as e:
            print(str(e)+" "+sys.argv[1]+"/cert/"+"SIA OCSP "+gn+" value:"+vi[1]+'\n')

        crl_disp = [
        [SAN,None,["cACompromise","privilegeWithdrawn"],
        [["DNSName","www.testfullname.com"]]]
        ]
        
        try:
            cert7 = Template(certpath=sys.argv[1]+"/cert/"+"CRL fullname "+gn+" value:"+vi[1]+".pem",Subject=BaseSubject,Issuer=BaseIssuer,SAN=None,SAN_cri=False,IAN=None,IAN_cri=False
            ,CRL=crl_disp,CRL_cri=False,Policies=None,Policies_cri=False,AIA=None,AIA_cri=False
            ,SIA=None,SIA_cri=False)
            cert7.gen_cert(sys.argv[1]+"/description.json",sys.argv[1]+"/input.json","CRL fullname "+gn,value,vi[1],"NoDes")
        except Exception as e:
            print(str(e)+" "+sys.argv[1]+"/cert/"+"CRL fullname "+gn+" value:"+vi[1]+'\n')

        crl_disp_1 = [
        [[["DNSName","www.testcrlissuer.com"]],None,["cACompromise","privilegeWithdrawn"],
        SAN]
        ]
        
        try:
            cert22 = Template(certpath=sys.argv[1]+"/cert/"+"CRL crlissuer "+gn+" value:"+vi[1]+".pem",Subject=BaseSubject,Issuer=BaseIssuer,SAN=None,SAN_cri=False,IAN=None,IAN_cri=False
            ,CRL=crl_disp_1,CRL_cri=False,Policies=None,Policies_cri=False,AIA=None,AIA_cri=False
            ,SIA=None,SIA_cri=False)
            cert22.gen_cert(sys.argv[1]+"/description.json",sys.argv[1]+"/input.json","CRL crlissuer "+gn,value,vi[1],"NoDes")
        except Exception as e:
            print(str(e)+" "+sys.argv[1]+"/cert/"+"CRL crlissuer "+gn+" value:"+vi[1]+'\n')


# CERTPOLICIES
for v in UTF8String:
    value = insert_random_char("TestCert", v[0])
    policies1 =[["1.2.3.4",[["str"],[value]]]]
    try:
        cert9 = Template(certpath=sys.argv[1]+"/cert/"+"CertPolicies cpsuri "+" value:"+v[1]+".pem",Subject=BaseSubject,Issuer=BaseIssuer,SAN=None,SAN_cri=False,IAN=None,IAN_cri=False
                ,CRL=None,CRL_cri=False,Policies=policies1,Policies_cri=False,AIA=None,AIA_cri=False
                ,SIA=None,SIA_cri=False)
        cert9.gen_cert(sys.argv[1]+"/description.json",sys.argv[1]+"/input.json","CertPolicies cpsuri",value,v[1],"NoDes")
    except Exception as e:
        print(str(e)+" "+sys.argv[1]+"/cert/"+"CertPolicies cpsuri "+" value:"+v[1]+'\n')

    policies2 = [["1.2.3.4",[["x509.UserNotice"],[[["bug",[1,2,3,4]],value]]]]]
    try:
        cert10 = Template(certpath=sys.argv[1]+"/cert/"+"CertPolicies explicit_text "+"value:"+v[1]+".pem",Subject=BaseSubject,Issuer=BaseIssuer,SAN=None,SAN_cri=False,IAN=None,IAN_cri=False
                ,CRL=None,CRL_cri=False,Policies=policies2,Policies_cri=False,AIA=None,AIA_cri=False
                ,SIA=None,SIA_cri=False)
        cert10.gen_cert(sys.argv[1]+"/description.json",sys.argv[1]+"/input.json","CertPolicies explicit_text",value,v[1],"NoDes")
    except Exception as e:
        print(str(e)+" "+sys.argv[1]+"/cert/"+"CertPolicies explicit_text "+"value:"+v[1]+'\n')

    policies3 = [["1.2.3.4",[["x509.UserNotice"],[[[value,[1,2,3,4]],None]]]]]
    try:
        cert16 = Template(certpath=sys.argv[1]+"/cert/"+"CertPolicies organzation "+"value:"+v[1]+".pem",Subject=BaseSubject,Issuer=BaseIssuer,SAN=None,SAN_cri=False,IAN=None,IAN_cri=False
                ,CRL=None,CRL_cri=False,Policies=policies3,Policies_cri=False,AIA=None,AIA_cri=False
                ,SIA=None,SIA_cri=False)
        cert16.gen_cert(sys.argv[1]+"/description.json",sys.argv[1]+"/input.json","CertPolicies organzation",value,v[1],"NoDes")
    except Exception as e:
        print(str(e)+" "+sys.argv[1]+"/cert/"+"CertPolicies organzation "+"value:"+v[1]+'\n')