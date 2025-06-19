from Generator import *

#The following code is an example about how you can generate certificate using Generator.py.
Subject = [[["2.5.4.3","gjf","UTF8String"],["2.5.4.6","CN","UTF8String"]],[["2.5.4.3","test","UTF8String"]]]
Issuer = [[["2.5.4.3","gjf","UTF8String"],["2.5.4.6","CN","UTF8String"]],[["2.5.4.3","test","UTF8String"]]]
SAN = [["IP","4n","127.0.0.1",None],["DNSName","www.google.com"],["DirectoryName",[[["2.5.4.3","gjf","UTF8String"],["2.5.4.6","CN","UTF8String"]],[["2.5.4.3","test","UTF8String"]]]]]
IAN = [["IP","4n","127.0.0.1",None],["DNSName","www.google.com"],["DNSName","www.GO0ole.com"]]
crls = [  
    [[["IP","4n","127.0.0.1",None],["DNSName","www.google.com"]],None,["cACompromise","privilegeWithdrawn"],
         [["DNSName","www.google.com"]]]
    ]

aia = [["1.3.6.1.5.5.7.48.2",["IP","4n","127.0.0.1",None]],["1.3.6.1.5.5.7.48.2",["IP","4n","127.0.0.4",None]]]
sia = [["1.3.6.1.5.5.7.48.1",["IP","4n","127.0.0.1",None]],["1.3.6.1.5.5.7.48.1",["IP","4n","127.0.0.8",None]]]
policies =[["1.2.3.4",[["x509.UserNotice","str"],[[["中国",[1,2,3,4]],"中国"],"zhongguo"]]],
     ["1.2.3.3",[["x509.UserNotice","str"],[[["中国",[1,2,3,4]],"中国"],"zhongguolove"]]]]

cert = Template(certpath="cert/newcodetest.pem",
         Subject=Subject,Issuer=Issuer,SAN=SAN,SAN_cri=False,IAN=IAN,IAN_cri=False,CRL=crls,CRL_cri=False,
         AIA=aia,AIA_cri=False,SIA=sia,SIA_cri=False,Policies=policies,Policies_cri=False)
cert.gen_cert("DesFile.json","TestInput.json","FocusField","FocusFieldValue","InsertValue","NoDes")