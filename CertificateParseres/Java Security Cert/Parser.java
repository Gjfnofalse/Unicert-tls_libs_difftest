import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.security.cert.CertificateParsingException;
import javax.security.auth.x500.X500Principal;
import java.lang.Object;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

//REF https://docs.oracle.com/en/java/javase/21/docs/api//java.base/java/security/cert/X509Certificate.html

class JSONCert{
    public String sha1;
    public String pem;
    public String description;
    public String FocusField;
    public String FocusFieldValue;
    public String InsertValue;

    public String getSha1() { return sha1; }
    public void setSha1(String sha1) { this.sha1 = sha1;}

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

class GeneralName{
    public String type;
    public String value;
}

class X509CertDefine {
    public boolean J21_status = true;
    public List<String> J21_errInfo = new ArrayList<>();
    public Set<String> J21_matchedUnicodes = new HashSet<>();
    public String sha1;
    
    public String FocusField;
    public String FocusFieldValue;
    public String InsertValue;
    public String description;

    public Boolean LoadCertStatus = false;

    //@JsonProperty("J21_SubjectRFC2253")
    public String J21_SubjectDeprecated;
    public Boolean J21_SubjectDeprecated_status;

    //@JsonProperty("J21_SubjectRFC1779")
    public String J21_Subject2StringDeprecated;
    public Boolean J21_Subject2StringDeprecated_status;

    //@JsonProperty("J21_IssuerCanonical")
    public String J21_IssuerDeprecated;
    public Boolean J21_IssuerDeprecated_status;

    //@JsonProperty("J21_IssuerReadable")
    public String J21_Issuer2StringDeprecated;
    public Boolean J21_Issuer2StringDeprecated_status;

    //@JsonProperty("J21_SubjectRFC2253")
    public String J21_SubjectRFC2253;
    public Boolean J21_SubjectRFC2253_status;

    //@JsonProperty("J21_SubjectRFC1779")
    public String J21_SubjectRFC1779;
    public Boolean J21_SubjectRFC1779_status;

    //@JsonProperty("J21_SubjectCanonical")
    public String J21_SubjectCanonical;
    public Boolean J21_SubjectCanonical_status;

    //@JsonProperty("J21_SubjectReadable")
    public String J21_SubjectReadable;
    public Boolean J21_SubjectReadable_status;

    //@JsonProperty("J21_IssuerRFC2253")
    public String J21_IssuerRFC2253;
    public Boolean J21_IssuerRFC2253_status;

    //@JsonProperty("J21_IssuerRFC1779")
    public String J21_IssuerRFC1779;
    public Boolean J21_IssuerRFC1779_status;

    //@JsonProperty("J21_IssuerCanonical")
    public String J21_IssuerCanonical;
    public Boolean J21_IssuerCanonical_status;

    //@JsonProperty("J21_IssuerReadable")
    public String J21_IssuerReadable;
    public Boolean J21_IssuerReadable_status;

    //@JsonProperty("J21_SubjectAlternativeName")
    public List<GeneralName> J21_SAN = new ArrayList<>();

    //@JsonProperty("J21_IssuerAlternativeName")
    public List<GeneralName> J21_IAN = new ArrayList<>();
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
                    X509Certificate certificate =null;

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
                        
                        CertificateFactory cf = CertificateFactory.getInstance("X.509");
                        
                        certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(encodedCert));
                        
                    }catch(Exception e){
                        buffer.J21_errInfo.add(e.getMessage());
                        buffer.J21_status = false;
                    }
                    
                    if(certificate!=null){
                        buffer.LoadCertStatus = true;
                        try{
                            buffer.J21_Subject2StringDeprecated = certificate.getSubjectDN().toString();
                            buffer.J21_matchedUnicodes.addAll(CharToStringSet(containsNonAllowedChars(buffer.J21_Subject2StringDeprecated)));
                            buffer.J21_Subject2StringDeprecated_status =true;
                        }catch(Exception e){
                            buffer.J21_errInfo.add(e.getMessage());
                            buffer.J21_status = false;
                            buffer.J21_Subject2StringDeprecated_status =false;
                        }
    
                        try{
                            buffer.J21_SubjectDeprecated = certificate.getSubjectDN().getName();
                            buffer.J21_matchedUnicodes.addAll(CharToStringSet(containsNonAllowedChars(buffer.J21_SubjectDeprecated)));
                            buffer.J21_SubjectDeprecated_status = true;
                        }catch(Exception e){
                            buffer.J21_errInfo.add(e.getMessage());
                            buffer.J21_status = false;
                            buffer.J21_SubjectDeprecated_status = false;
                        }

                        try{
                            buffer.J21_IssuerDeprecated = certificate.getIssuerDN().getName();
                            buffer.J21_matchedUnicodes.addAll(CharToStringSet(containsNonAllowedChars(buffer.J21_IssuerDeprecated)));
                            buffer.J21_IssuerDeprecated_status = true;
                        }catch(Exception e){
                            buffer.J21_errInfo.add(e.getMessage());
                            buffer.J21_status = false;
                            buffer.J21_IssuerDeprecated_status = false;
                        }
                        try{
                            buffer.J21_Issuer2StringDeprecated = certificate.getIssuerDN().toString();
                            buffer.J21_matchedUnicodes.addAll(CharToStringSet(containsNonAllowedChars(buffer.J21_Issuer2StringDeprecated)));
                            buffer.J21_Issuer2StringDeprecated_status = true;
                        }catch(Exception e){
                            buffer.J21_errInfo.add(e.getMessage());
                            buffer.J21_status = false;
                            buffer.J21_Issuer2StringDeprecated_status = false;
                        }

                        try{
                            buffer.J21_SubjectRFC2253 = certificate.getSubjectX500Principal().getName();
                            buffer.J21_matchedUnicodes.addAll(CharToStringSet(containsNonAllowedChars(buffer.J21_SubjectRFC2253)));
                            buffer.J21_SubjectRFC2253_status =true;
                        }catch(Exception e){
                            buffer.J21_errInfo.add(e.getMessage());
                            buffer.J21_status = false;
                            buffer.J21_SubjectRFC2253_status = false;
                        }
    
                        try{
                            buffer.J21_SubjectRFC1779 = certificate.getSubjectX500Principal().getName(X500Principal.RFC1779);
                            buffer.J21_matchedUnicodes.addAll(CharToStringSet(containsNonAllowedChars(buffer.J21_SubjectRFC1779)));
                            buffer.J21_SubjectRFC1779_status = true;
                        }catch(Exception e){
                            buffer.J21_errInfo.add(e.getMessage());
                            buffer.J21_status = false;
                            buffer.J21_SubjectRFC1779_status = false;
                        }
    
                        try{
                            buffer.J21_SubjectCanonical = certificate.getSubjectX500Principal().getName("CANONICAL");
                            buffer.J21_matchedUnicodes.addAll(CharToStringSet(containsNonAllowedChars(buffer.J21_SubjectCanonical)));
                            buffer.J21_SubjectCanonical_status = true;
                        }catch(Exception e){
                            buffer.J21_errInfo.add(e.getMessage());
                            buffer.J21_status = false;
                            buffer.J21_SubjectCanonical_status = false;
                        }
    
                        try{
                            buffer.J21_SubjectReadable = certificate.getSubjectX500Principal().toString();
                            buffer.J21_matchedUnicodes.addAll(CharToStringSet(containsNonAllowedChars(buffer.J21_SubjectReadable)));
                            buffer.J21_SubjectReadable_status = true;
                        }catch(Exception e){
                            buffer.J21_errInfo.add(e.getMessage());
                            buffer.J21_status = false;
                            buffer.J21_SubjectReadable_status = false;
                        }
                        
                        try{
                            buffer.J21_IssuerRFC2253 = certificate.getIssuerX500Principal().getName();
                            buffer.J21_matchedUnicodes.addAll(CharToStringSet(containsNonAllowedChars(buffer.J21_IssuerRFC2253)));
                            buffer.J21_IssuerRFC2253_status = true;
                        }catch(Exception e){
                            buffer.J21_errInfo.add(e.getMessage());
                            buffer.J21_status = false;
                            buffer.J21_IssuerRFC2253_status = false;
                        }
    
                        try{
                            buffer.J21_IssuerRFC1779 = certificate.getIssuerX500Principal().getName(X500Principal.RFC1779);
                            buffer.J21_matchedUnicodes.addAll(CharToStringSet(containsNonAllowedChars(buffer.J21_IssuerRFC1779)));
                            buffer.J21_IssuerRFC1779_status = true;
                        }catch(Exception e){
                            buffer.J21_errInfo.add(e.getMessage());
                            buffer.J21_status = false;
                            buffer.J21_IssuerRFC1779_status = false;
                        }
    
                        try{
                            buffer.J21_IssuerCanonical = certificate.getIssuerX500Principal().getName("CANONICAL");
                            buffer.J21_matchedUnicodes.addAll(CharToStringSet(containsNonAllowedChars(buffer.J21_IssuerCanonical)));
                            buffer.J21_IssuerCanonical_status =true;
                        }catch(Exception e){
                            buffer.J21_errInfo.add(e.getMessage());
                            buffer.J21_status = false;
                            buffer.J21_IssuerCanonical_status =false;
                        }
    
                        try{
                            buffer.J21_IssuerReadable = certificate.getIssuerX500Principal().toString();
                            buffer.J21_matchedUnicodes.addAll(CharToStringSet(containsNonAllowedChars(buffer.J21_IssuerReadable)));
                            buffer.J21_IssuerReadable_status = true;
                        }catch(Exception e){
                            buffer.J21_errInfo.add(e.getMessage());
                            buffer.J21_status = false;
                            buffer.J21_IssuerReadable_status = false;
                        }
                        
                        // SAN
                        try{
                            Collection<List<?>> SAN = certificate.getSubjectAlternativeNames();
                        
                            if (SAN != null) {
                                for (List<?> outer : SAN) {
                                    Object tag = outer.get(0);
                                    if(tag instanceof Integer){
                                        switch ((Integer)tag) {
                                            case 0://OtherName
                                                GeneralName OName_save = new GeneralName();
                                                OName_save.type = "OtherName";
                                                OName_save.value = "Nothing";
                                                buffer.J21_SAN.add(OName_save);
                                                break;
                                            case 1://RFC822Name(email)
                                                GeneralName email_save = new GeneralName();
                                                email_save.type = "RFC822Name";
                                                email_save.value = (String)outer.get(1);
                                                buffer.J21_SAN.add(email_save);
                                                break;
                                            case 2:
                                                GeneralName dns_save = new GeneralName();
                                                dns_save.type = "DNSName";
                                                dns_save.value = (String)outer.get(1);
                                                buffer.J21_SAN.add(dns_save);
                                                break;
                                            case 3://x400Address
                                                GeneralName addr_save = new GeneralName();
                                                addr_save.type = "x400Address";
                                                addr_save.value = "Nothing";
                                                buffer.J21_SAN.add(addr_save);
                                                break;
                                            case 4://
                                                GeneralName dn_save = new GeneralName();
                                                dn_save.type = "DirectoryName";
                                                dn_save.value = (String)outer.get(1);
                                                buffer.J21_SAN.add(dn_save);
                                                break;
                                            case 5://ediPartyName
                                                GeneralName epn_save = new GeneralName();
                                                epn_save.type = "ediPartyName";
                                                epn_save.value = "Nothing";
                                                buffer.J21_SAN.add(epn_save);
                                                break;
                                            case 6:
                                                GeneralName uri_save = new GeneralName();
                                                uri_save.type = "URI";
                                                uri_save.value = (String)outer.get(1);
                                                buffer.J21_SAN.add(uri_save);
                                                break;
                                            case 7://iPAddress
                                                GeneralName ip_save = new GeneralName();
                                                ip_save.type = "iPAddress";
                                                ip_save.value = "Nothing";
                                                buffer.J21_SAN.add(ip_save);
                                                break;
                                            case 8://RegID
                                                GeneralName RID_save = new GeneralName();
                                                RID_save.type = "registeredID";
                                                RID_save.value = "Nothing";
                                                buffer.J21_SAN.add(RID_save);
                                                break;
                                        }
                                    }
                                }
                            }
                        }catch(CertificateParsingException e){
                            buffer.J21_errInfo.add(e.getMessage()); 
                            buffer.J21_status = false;
                        }
    
                        // IAN
                        try{
                            Collection<List<?>> IAN = certificate.getIssuerAlternativeNames();
                        
                            if (IAN != null) {
                                for (List<?> outer : IAN) {
                                    Object tag = outer.get(0);
                                    if(tag instanceof Integer){
                                        switch ((Integer)tag) {
                                            case 0://OtherName
                                                GeneralName OName_save = new GeneralName();
                                                OName_save.type = "OtherName";
                                                OName_save.value = "Nothing";
                                                buffer.J21_IAN.add(OName_save);
                                                break;
                                            case 1://RFC822Name(email)
                                                GeneralName email_save = new GeneralName();
                                                email_save.type = "RFC822Name";
                                                email_save.value = (String)outer.get(1);
                                                buffer.J21_IAN.add(email_save);
                                                break;
                                            case 2:
                                                GeneralName dns_save = new GeneralName();
                                                dns_save.type = "DNSName";
                                                dns_save.value = (String)outer.get(1);
                                                buffer.J21_IAN.add(dns_save);
                                                break;
                                            case 3://x400Address
                                                GeneralName addr_save = new GeneralName();
                                                addr_save.type = "x400Address";
                                                addr_save.value = "Nothing";
                                                buffer.J21_IAN.add(addr_save);
                                                break;
                                            case 4:
                                                GeneralName dn_save = new GeneralName();
                                                dn_save.type = "DirectoryName";
                                                dn_save.value = (String)outer.get(1);
                                                buffer.J21_IAN.add(dn_save);
                                                break;
                                            case 5://ediPartyName
                                                GeneralName epn_save = new GeneralName();
                                                epn_save.type = "ediPartyName";
                                                epn_save.value = "Nothing";
                                                buffer.J21_IAN.add(epn_save);
                                                break;
                                            case 6:
                                                GeneralName uri_save = new GeneralName();
                                                uri_save.type = "URI";
                                                uri_save.value = (String)outer.get(1);
                                                buffer.J21_IAN.add(uri_save);
                                                break;
                                            case 7://iPAddress
                                                GeneralName ip_save = new GeneralName();
                                                ip_save.type = "iPAddress";
                                                ip_save.value = "Nothing";
                                                buffer.J21_IAN.add(ip_save);
                                                break;
                                            case 8://RegID
                                                GeneralName RID_save = new GeneralName();
                                                RID_save.type = "registeredID";
                                                RID_save.value = "Nothing";
                                                buffer.J21_IAN.add(RID_save);
                                                break;
                                        }
                                    }
                                }
                            }
                        }catch(CertificateParsingException e){
                            buffer.J21_errInfo.add(e.getMessage()); 
                            buffer.J21_status = false;
                        }
                    }else{
                        buffer.LoadCertStatus = false;
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



