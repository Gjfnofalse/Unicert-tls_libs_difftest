package EncodingDetection.src.main.java.TlsImplementationTest.Unicert;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

public class ASN1DecodingChecker {


    //The character set can also be restricted
    public static boolean isValidPrintableString(byte[] value) {
        for(byte b : value){//Are there any bytes other than 0x7F
            if ((b & 0xFF) > 0x7F) {
                return false;
            }
        }
        return true;
    }


    public static boolean isValidIA5String(byte[] value) {
        for(byte b : value){//Are there any bytes other than 0x7F
            if ((b & 0xFF) > 0x7F) {
                return false;
            }
        }
        return true;
    }

    public static boolean isValidVisibleString(byte[] value) {
        for(byte b : value){
            if ((b & 0xFF) > 0x7F) {
                return false;
            }
        }
        return true;
    }

    public static boolean isValidUTF8String(byte[] value) {
        try {
            StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(value));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean isValidBMPString(byte[] value) {
        if(value.length%2 !=0){
            return false;
        }
        try{
            CharsetDecoder decoder = StandardCharsets.UTF_16BE.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT);
            CharBuffer test = decoder.decode(ByteBuffer.wrap(value));
            for (int i = 0; i < test.length(); i++) {
                char c = test.charAt(i);
                if (c >= 0xD800 && c <= 0xDFFF) {
                    return false;
                }
            }
            return true;
        }catch(Exception e){
            return false;
        }
    }
}
