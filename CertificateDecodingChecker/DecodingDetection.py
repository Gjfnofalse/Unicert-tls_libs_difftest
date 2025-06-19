# DecodingChecker

def Encoder(tag:str,raw:str)->bytes:
    if tag !="BMPString":
        return raw.encode("utf-8")
    else:
        return raw.encode("utf-16-be")

def DecodingSelector(res:dict[str,bool])->str|None:# Select the minimum decoding method from compatible set.
    if res["ascii"]:
        return "ascii"
    if res["utf-8"]:
        return "utf-8"
    if res["ucs-2"]:
        return "ucs-2"
    if res["utf-16"]:
        return "utf-16"
    if res["iso-8859-1"]:
        return "iso-8859-1"
    return None

def get_info(Encoding_slice:dict,InsertValue:str,decodingM:str):
    if decodingM.startswith("possible"):
        Encoding_slice[decodingM].add(InsertValue)
    elif len(decodingM.split(" ")) == 2:
        Encoding_slice[decodingM.split(" ")[1]].add(InsertValue)
        Encoding_slice["possible_decodings_ex"].add(decodingM.split(" ")[0])
    else:
        Encoding_slice["possible_decodings"].add(decodingM)

def DecodingChecker(possible_decodings_raw:set)->str|None:# Select the maximum decoding method from compatible set.
    possible_decodings = possible_decodings_raw.copy()
    
    if len(possible_decodings) ==0:
        return "unknown"
    if len(possible_decodings) ==1 and "ascii" in possible_decodings:
        return "ascii"
    if possible_decodings == {"ascii","utf-8"} or possible_decodings == {"utf-8"}:
        return "utf-8"
    if possible_decodings == {"ucs-2"}:
        return "ucs-2"
    if possible_decodings == {"utf-16"} or possible_decodings == {"ucs-2","utf-16"}:
        return "utf-16"
    if possible_decodings == {"ascii","iso-8859-1"} or possible_decodings == {"iso-8859-1"}:
        return "iso-8859-1"
    return "error"

def DecodingDetectorEx(raw:str,res:str)-> str | None:
    if len(raw) > len(res):
        num_matched_chars = 0
        for i in range(len(res)):
            if raw[i]!=res[i]:
                return "possible_truncation"
        return "truncation"
        
    if len(raw) < len(res):
        for i in range(len(raw)):
            if raw[i] != res[i]:
                remainings = len(raw) - i-1
                if remainings >0:
                    if raw[-remainings] == res[-remainings]:
                        return "escaping"
                    else:
                        return "possible_escaping"
                else:
                    return "escaping"
        return "possible_escaping"
            
    if len(raw) == len(res):
        num_matched_chars = 0
        for i in range(len(raw)):
            if raw[i] ==res[i]:
                num_matched_chars = num_matched_chars + 1
        
        if num_matched_chars == len(raw) -1:
            return "replacement"
        else:
            return "possible_replacement"

def DecodingDetector(tag: str, raw: str, res: str,prefix:str,suffix:str)->str:
    raw_bytes = Encoder(tag, raw)

    result = {
        "ascii": False,
        "iso-8859-1": False,
        "utf-8": False,
        "ucs-2": False,
        "utf-16": False
    }

    tag_res = {
        "ascii": False,
        "iso-8859-1": False,
        "utf-8": False,
        "ucs-2": False,
        "utf-16": False
    }
    tag_res_save = {}

    # ASCII
    try:
        if prefix+DecodingWithASCII(raw_bytes)+suffix ==res:
            result["ascii"] =True
        else:
            res_str = prefix + DecodingWithASCII(raw_bytes)+suffix
            if not DecodingDetectorEx(res_str,res).startswith("possible"):
                tag_res["ascii"] =True
                tag_res_save["ascii"] = DecodingDetectorEx(res_str,res)
    except:
        pass

    try:
        if prefix+DecodingWithUTF8(raw_bytes)+suffix ==res:
            result["utf-8"] =True
        else:
            res_str = prefix + DecodingWithUTF8(raw_bytes)+suffix
            if not DecodingDetectorEx(res_str,res).startswith("possible"):
                tag_res["utf-8"] =True
                tag_res_save["utf-8"] = DecodingDetectorEx(res_str,res)
    except:
        pass

    try:
        if prefix+DecodingWithUCS2(raw_bytes)+suffix ==res:
            result["ucs-2"] =True
        else:
            res_str = prefix + DecodingWithUCS2(raw_bytes)+suffix
            if not DecodingDetectorEx(res_str,res).startswith("possible"):
                tag_res["ucs-2"] =True
                tag_res_save["ucs-2"] = DecodingDetectorEx(res_str,res)
    except:
        pass

    try:
        if prefix+DecodingWithUTF16(raw_bytes)+suffix ==res:
            result["utf-16"] =True
        else:
            res_str = prefix + DecodingWithUTF16(raw_bytes)+suffix
            if not DecodingDetectorEx(res_str, res).startswith("possible"):
                tag_res["utf-16"] = True
                tag_res_save["utf-16"] = DecodingDetectorEx(res_str, res)
    except:
        pass

    try:
        if prefix+DecodingWithISO_8859_1(raw_bytes)+suffix ==res:
            result["iso-8859-1"] =True
        else:
            res_str = prefix + DecodingWithISO_8859_1(raw_bytes)+suffix
            if not DecodingDetectorEx(res_str, res).startswith("possible"):
                tag_res["iso-8859-1"] = True
                tag_res_save["iso-8859-1"] = DecodingDetectorEx(res_str, res)
    except:
        pass

    if DecodingSelector(result):
        return DecodingSelector(result)
    elif not DecodingSelector(result) and DecodingSelector(tag_res):
        return DecodingSelector(tag_res) + " " + tag_res_save[DecodingSelector(tag_res)]
    else:
        if len(raw) == len(res):
            return "possible_replacement"
        elif len(raw) < len(res):
            return "possible_escaping"
        else:
            return "possible_truncation"

def DecodingWithUCS2(src:bytes)->str:
    des = src.decode("utf-16-be")

    for _,char in enumerate(des):
        if ord(char) > 0xFFFF:
            raise UnicodeDecodeError("Invaild ucs-2 bytes.")

    return des

def DecodingWithUTF16(src:bytes)->str:
    des = src.decode("utf-16-be")
    return des

def DecodingWithASCII(src:bytes)->str:
    des = src.decode("ascii")
    return des

def DecodingWithISO_8859_1(src:bytes)->str:
    des = src.decode("iso-8859-1")
    return des

def DecodingWithUTF8(src:bytes)->str:
    des = src.decode("utf-8")
    return des