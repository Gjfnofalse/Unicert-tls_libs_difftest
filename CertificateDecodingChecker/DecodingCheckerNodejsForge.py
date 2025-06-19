import json
import sys
import copy
dir_path = sys.argv[1]
output_path = sys.argv[2]
from DencodingCheckHelper import set_deduced_decoding,ASN1_list,FindAllCharlistsInDict,DN,save_info
from DecodingDetection import DecodingDetector,get_info

#Get Name GeneralName ParsedValue Prefix
forge_dn_prefix = {
    '2.5.4.3': 'CN',
    '1.2.840.113549.1.9.1': 'E',
    '2.5.4.7': 'L',
    '2.5.4.8': 'ST',
    '2.5.4.11': 'OU',
    '2.5.4.10': 'O'
}

forge_san_rlt = {
    "DNSName": "DnsName",
    "RFC822Name": "Rfc822Name",
    "URI": "URI"
}
NodejsForgeEncoding = {
    "Lib": "NodejsForge@V1.3.1",
    "Subject": {},
    "Issuer": {},
    "SubjectAlternativeName": {"DNSName": copy.deepcopy(save_info), "URI": copy.deepcopy(save_info), "RFC822Name": copy.deepcopy(save_info)},
}

for itm in DN:
    NodejsForgeEncoding["Issuer"][itm] = {}
    NodejsForgeEncoding["Subject"][itm] = {}
    for ASN1 in ASN1_list:
        NodejsForgeEncoding["Issuer"][itm][ASN1] = copy.deepcopy(save_info)
        NodejsForgeEncoding["Subject"][itm][ASN1] = copy.deepcopy(save_info)

with open(dir_path + "/output_nodejs_forge.json", 'r') as file:
    for line in file:
        json_obj = json.loads(line)

        FocusField = json_obj["FocusField"]
        FocusFieldValue = json_obj["FocusFieldValue"]
        InsertValue = json_obj["InsertValue"]
        FocusFieldSlices = FocusField.split(" ")

        if FocusFieldSlices[0] == "Subject":
            if FocusFieldSlices[1] in list(forge_dn_prefix.keys()):
                if json_obj["Status"] == False:
                    NodejsForgeEncoding["Subject"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
                else:
                    decodingM = DecodingDetector(FocusFieldSlices[2], FocusFieldValue,
                                                           json_obj["Subject"][forge_dn_prefix[FocusFieldSlices[1]]]["data"], "","")
                    get_info(NodejsForgeEncoding["Subject"][FocusFieldSlices[1]][FocusFieldSlices[2]], InsertValue,decodingM)
            else:
                pass

        if FocusFieldSlices[0] == "Issuer":
            if FocusFieldSlices[1] in list(forge_dn_prefix.keys()):
                if json_obj["Status"] == False:
                    NodejsForgeEncoding["Issuer"][FocusFieldSlices[1]][FocusFieldSlices[2]]["parsing_failed"].add(InsertValue)
                else:
                    decodingM = DecodingDetector(FocusFieldSlices[2], FocusFieldValue,
                                                           json_obj["Issuer"][forge_dn_prefix[FocusFieldSlices[1]]]["data"], "","")
                    get_info(NodejsForgeEncoding["Issuer"][FocusFieldSlices[1]][FocusFieldSlices[2]],InsertValue, decodingM)
            else:
                pass

        if FocusFieldSlices[0] == "SAN":
            if FocusField.startswith("SAN DirectoryName"):
                pass
            else:
                if json_obj["Status"] == False:
                    NodejsForgeEncoding["SubjectAlternativeName"][FocusFieldSlices[1]]["parsing_failed"].add(InsertValue)
                else:
                    decodingM = DecodingDetector("UTF8String", FocusFieldValue,
                                                           json_obj["SAN"][0][forge_san_rlt[FocusFieldSlices[1]]], "","")
                    get_info(NodejsForgeEncoding["SubjectAlternativeName"][FocusFieldSlices[1]],InsertValue, decodingM)

NodejsForgePaths = FindAllCharlistsInDict(NodejsForgeEncoding)

for NodejsForgePath in NodejsForgePaths:
    set_deduced_decoding(NodejsForgeEncoding, NodejsForgePath)

NodejsForgeStr = json.dumps(NodejsForgeEncoding, indent=4)

with open(output_path + '/DecodingTestNodejsForge.json', 'a') as file:
    file.write(NodejsForgeStr + '\n')