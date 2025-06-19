import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.asn1.x500.RDN;

class JSONCert{
    public String sha1;
    public String pem;
    public String description;
    public String FocusField;
    public String FocusFieldValue;
    public String InsertValue;

    public String getSha1() { return sha1; }
    public void setSha1(String sha1) { this.sha1 = sha1; }

    public String getFocusField() { return FocusField; }
    public void setFocusField(String FocusField) { this.FocusField = FocusField; }

    public String getFocusFieldValue() { return FocusFieldValue; }
    public void setFocusFieldValue(String FocusFieldValue) { this.FocusFieldValue = FocusFieldValue; }

    public String getInsertValue() { return InsertValue; }
    public void setInsertValue(String InsertValue) { this.InsertValue = InsertValue; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getPem() { return pem; }
    public void setPem(String pem) { this.pem = pem; }
}

class X509CertDefine {
    public boolean JBC_status = true;
    public List<String> JBC_errInfo = new ArrayList<>();
    public Set<String> JBC_matchedUnicodes = new HashSet<>();
    public String sha1;

    public Boolean LoadCertStatus;
    public String JBC_Subject;

    public Boolean JBC_Subject_status;

    public String FocusField;

    public String FocusFieldValue;

    public String InsertValue;

    public String description;

    public List<String> JBC_SubjectList = new ArrayList<>();

    public Boolean JBC_SubjectList_status;

    public String JBC_Issuer;

    public Boolean JBC_Issuer_status;

    public List<String> JBC_IssuerList = new ArrayList<>();

    public Boolean JBC_IssuerList_status;

}

public class Parser {

    public static String CharToString(Character input){
        int CodePoint = input.charValue();
        String unicodeString = "U+" + String.format("%04x", CodePoint);
        return unicodeString;
    }

    public static Set<String> CharToStringSet(Set<Character> input){
        Set<String> Save = new HashSet<>();
        for (Character item : input) {
            Save.add(CharToString(item));
        }
        return Save;
    }

    public static Set<Character> containsNonAllowedChars(String input) {
        Set<Character> nonAsciiCharacters = new HashSet<>();
        for (int i = 0; i < input.length(); i++) {
            char ch = input.charAt(i);
            if(ch <= '\u0020' || ch >= '\u007e'){
                    nonAsciiCharacters.add(ch);
            }
        }
        return nonAsciiCharacters;
    }

    public static void main(String[] args) {
        // The file path of the X509 certificates in PEM format
        Path filePath = Paths.get(args[0]);
        ObjectMapper mapper = new ObjectMapper();
        try {
            Files.lines(filePath).forEach(line -> {
                try {
                    JSONCert jsonCert = mapper.readValue(line, JSONCert.class);
                    String sha1 = jsonCert.getSha1();
                    String pem = jsonCert.getPem();
                    String FocusField = jsonCert.getFocusField();
                    String FocusFieldValue  = jsonCert.getFocusFieldValue();
                    String InsertValue = jsonCert.getInsertValue();
                    String description = jsonCert.getDescription();
                    X509CertDefine buffer = new X509CertDefine();
                    X509CertificateHolder certificate =null;

                    try{
                        buffer.sha1 = sha1;

                        buffer.description = description;
                        buffer.FocusField = FocusField;
                        buffer.FocusFieldValue = FocusFieldValue;
                        buffer.InsertValue = InsertValue;

                        //pem ->Base64 ->der ->X509Cert
                        String pemData = pem.replace("-----BEGIN CERTIFICATE-----", "")
                        .replace("-----END CERTIFICATE-----", "").replaceAll("\\s", "");
                        byte[] encodedCert = Base64.getDecoder().decode(pemData);
                        
                        certificate = new X509CertificateHolder(encodedCert);

                    }catch(Exception e){
                        buffer.JBC_errInfo.add(e.getMessage());
                        buffer.JBC_status = false;
                    }
                    
                    if(certificate!=null){
                        buffer.LoadCertStatus =true;
                        try{
                            buffer.JBC_Subject = certificate.getSubject().toString();
                            buffer.JBC_matchedUnicodes.addAll(CharToStringSet(containsNonAllowedChars(buffer.JBC_Subject)));
                            buffer.JBC_Subject_status = true;
                        }catch(Exception e){
                            buffer.JBC_errInfo.add(e.getMessage());
                            buffer.JBC_Subject_status = false;
                            buffer.JBC_status = false;
                        }
    
                        try{
                            buffer.JBC_Issuer = certificate.getIssuer().toString();
                            buffer.JBC_matchedUnicodes.addAll(CharToStringSet(containsNonAllowedChars(buffer.JBC_Issuer)));
                            buffer.JBC_Issuer_status = true;
                        }catch(Exception e){
                            buffer.JBC_errInfo.add(e.getMessage());
                            buffer.JBC_Issuer_status = false;
                            buffer.JBC_status = false;
                        }
                        
                        try{
                            RDN[] rdns = certificate.getSubject().getRDNs();
                            for(RDN rdn : rdns){
                                buffer.JBC_SubjectList.add(rdn.toASN1Primitive().toString());
                            }
                            buffer.JBC_SubjectList_status = true;
                        }catch(Exception e){
                            buffer.JBC_errInfo.add(e.getMessage());
                            buffer.JBC_SubjectList_status = false;
                            buffer.JBC_status = false;
                        }

                        try{
                            RDN[] rdns = certificate.getIssuer().getRDNs();
                            for(RDN rdn : rdns){
                                buffer.JBC_IssuerList.add(rdn.toASN1Primitive().toString());
                            }
                            buffer.JBC_IssuerList_status = true;
                        }catch(Exception e){
                            buffer.JBC_errInfo.add(e.getMessage());
                            buffer.JBC_status = false;
                            buffer.JBC_IssuerList_status = false;
                        }
                        
                        //The BouncyCastle parsing extension relies on its own ASN1 function, which will not be considered here
                    }else{
                        buffer.LoadCertStatus=false;
                    }
                    try{
                        ObjectMapper mapper1 = new ObjectMapper();
                        String json = mapper1.writeValueAsString(buffer);
                        try (FileOutputStream fos = new FileOutputStream(args[1], true); 
                        OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8)) {

                        osw.append(json).append("\n"); 

                        } catch (IOException e) {
                            System.err.println(sha1+","+"json:Parsing Cert success,json ser success,error:" + e.getMessage());
                        }
                    }catch(Exception e){
                        System.err.println(sha1+","+"json:Parsing Cert success,json ser failed,error:" + e.getMessage());
                    }
                } catch (IOException e) {
                    System.err.println("json:Processing line failed: " + e.getMessage());
                }
            });
        } catch (IOException e) {
            System.err.println("Read file("+args[0]+ ") failed : " + e.getMessage());
        }
    }
}





