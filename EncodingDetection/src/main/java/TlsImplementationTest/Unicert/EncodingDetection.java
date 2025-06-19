package EncodingDetection.src.main.java.TlsImplementationTest.Unicert;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;


//Input format
class jEntry{
    public String sha1;
    public String pem;

    public jEntry() {}
}

class saveEntry{
    public String sha1;
    public String pem;
    public Set<String> SubjectViolations;
    public Set<String> IssuerViolations;
    public Set<String> SANViolations;
    public Set<String> IANViolations;
    public Set<String> AIAViolations;
    public Set<String> CRLViolations;
    public Set<String> CertPoliciesViolations;
    public saveEntry() {}
}

public class EncodingDetection {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static String removeFirstTwoAndLastOne(String str) {
        if (str == null || str.length() < 3) {
            return str; // If the string is empty or its length is less than 3, return the original string directly
        }
        return str.substring(2, str.length() - 1);
    }
    public static void main(String[] args) throws Exception {
        try(
                FileReader fileReader = new FileReader(args[0], StandardCharsets.UTF_8);
                BufferedReader bufferedReader = new BufferedReader(fileReader);
                FileWriter fileWriter = new FileWriter(args[1], StandardCharsets.UTF_8,true);
                BufferedWriter bufferedWriter = new BufferedWriter(fileWriter)
        ){
            String line;
            ObjectMapper mapper = new ObjectMapper();
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            while ((line = bufferedReader.readLine()) != null) {
                jEntry recv = mapper.readValue(line, jEntry.class);
                String sha1 = removeFirstTwoAndLastOne(recv.sha1);
                String pem = removeFirstTwoAndLastOne(recv.pem).replaceAll("\\\\n", "\n");
                X509Certificate certificate;

                Set<String> SubjectViolations = new HashSet<>();
                Set<String> IssuerViolations = new HashSet<>();
                Set<String> SANViolations = new HashSet<>();
                Set<String> IANViolations = new HashSet<>();
                Set<String> AIANViolations = new HashSet<>();
                Set<String> CRLViolations = new HashSet<>();
                Set<String> CertPoliciesViolations = new HashSet<>();
                try{
                    String pemData = pem.replace("-----BEGIN CERTIFICATE-----", "")
                            .replace("-----END CERTIFICATE-----", "").replaceAll("\\s", "");
                    byte[] encodedCert = Base64.getDecoder().decode(pemData);

                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(encodedCert));
                } catch (Exception e) {
                    System.out.println(e);
                    continue;
                }

                X500Name subject;
                X500Name issuer;
                try{
                    subject = X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
                    issuer = X500Name.getInstance(certificate.getIssuerX500Principal().getEncoded());
                }catch (Exception e) {
                    System.out.println(sha1+": Failed in Parsing Subject/Issuer.");
                    continue;
                }

                EncodingDetectionSubject(subject,SubjectViolations);
                EncodingDetectionIssuer(issuer,IssuerViolations);
                EncodingDetectionSAN(certificate,SANViolations);
                EncodingDetectionIAN(certificate,IANViolations);
                EncodingDetectionAIA(certificate,AIANViolations);
                EncodingDetectionCRLDistributionPoints(certificate,CRLViolations);
                EncodingDetectionCertPolicies(certificate,CertPoliciesViolations);

                if (!SubjectViolations.isEmpty() || !IssuerViolations.isEmpty() || !SANViolations.isEmpty() || !IANViolations.isEmpty() || !AIANViolations.isEmpty() || !CRLViolations.isEmpty() || !CertPoliciesViolations.isEmpty()) {
                    saveEntry entry = new saveEntry();

                    byte[] certBytes = certificate.getEncoded();
                    // Create SHA-1 digest
                    MessageDigest md = MessageDigest.getInstance("SHA-1");
                    byte[] sha11 = md.digest(certBytes);

                    // Convert to hex string (optional)
                    StringBuilder hexString = new StringBuilder();
                    for (byte b : sha11) {
                        hexString.append(String.format("%02x", b));
                    }

                    String sha1Fingerprint = hexString.toString();
                    entry.sha1 = sha1;
                    entry.pem = pem;
                    entry.IssuerViolations = IssuerViolations;
                    entry.SubjectViolations = SubjectViolations;
                    entry.SANViolations = SANViolations;
                    entry.IANViolations = IANViolations;
                    entry.AIAViolations = AIANViolations;
                    entry.CRLViolations = CRLViolations;
                    entry.CertPoliciesViolations = CertPoliciesViolations;

                    bufferedWriter.write(mapper.writeValueAsString(entry));
                    bufferedWriter.write("\n");
                }
            }
        }
    }

    private static void EncodingDetectionCRLDistributionPoints(X509Certificate certificate, Set<String> CRLViolations) {
        try {
            byte[] crldpExt = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());
            if (crldpExt != null) {
                ASN1OctetString oct = ASN1OctetString.getInstance(crldpExt);
                CRLDistPoint crldp = CRLDistPoint.getInstance(oct.getOctets());
                DistributionPoint[] points = crldp.getDistributionPoints();
                for (DistributionPoint dp : points) {
                    DistributionPointName dpName = dp.getDistributionPoint();
                    if (dpName != null && dpName.getType() == DistributionPointName.FULL_NAME) {//不处理DN
                        GeneralNames fullName = GeneralNames.getInstance(dpName.getName());
                        processGeneralNames(fullName, CRLViolations, "FullName ");
                    }

                    GeneralNames crlIssuer = dp.getCRLIssuer();
                    if (crlIssuer != null) {
                        processGeneralNames(crlIssuer, CRLViolations, "CRLIssuer ");
                    }
                }
            }
        } catch (Exception ignored) {
        }
    }

    private static void EncodingDetectionIAN(X509Certificate cert, Set<String> IANViolations) {
        try {
            byte[] ianExt = cert.getExtensionValue(Extension.issuerAlternativeName.getId());
            if (ianExt != null) {
                ASN1OctetString oct = ASN1OctetString.getInstance(ianExt);
                GeneralNames ian = GeneralNames.getInstance(oct.getOctets());
                processGeneralNames(ian, IANViolations,"");
            }
        } catch (Exception ignored) {
        }
    }

    private static void processGeneralName(GeneralName name, Set<String> violations, String prefix) {
        try {
            int tag = name.getTagNo();
            byte[] derBytes = name.toASN1Primitive().getEncoded();
            byte[] valueBytes = ExtractVavlueFromTLV(derBytes);

            switch (tag) {
                case GeneralName.rfc822Name:
                    if (!ASN1DecodingChecker.isValidIA5String(valueBytes)) {
                        violations.add(prefix + " RFC822Name");
                    }
                    break;
                case GeneralName.dNSName:
                    if (!ASN1DecodingChecker.isValidIA5String(valueBytes)) {
                        violations.add(prefix + " DNSName");
                    }
                    break;
                case GeneralName.uniformResourceIdentifier:
                    if (!ASN1DecodingChecker.isValidIA5String(valueBytes)) {
                        violations.add(prefix + " URI");
                    }
                    break;
                default:
                    break;
            }
        } catch (Exception ignored) {
        }
    }

    private static void EncodingDetectionAIA(X509Certificate cert, Set<String> AIAViolations) {
        try {
            byte[] aiaExt = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
            if (aiaExt != null) {
                ASN1OctetString oct = ASN1OctetString.getInstance(aiaExt);
                AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(oct.getOctets());
                AccessDescription[] descriptions = aia.getAccessDescriptions();
                for (AccessDescription desc : descriptions) {
                    ASN1ObjectIdentifier accessMethod = desc.getAccessMethod();
                    GeneralName accessLocation = desc.getAccessLocation();
                    processGeneralName(accessLocation, AIAViolations, accessMethod.getId());
                }
            }
        } catch (Exception e) {//Only check the ASN1String encoding error issue, and ignore all other problems
        }
    }

    private static void EncodingDetectionSAN(X509Certificate cert, Set<String> SANViolations) {
        try {
            byte[] sanExt = cert.getExtensionValue(Extension.subjectAlternativeName.getId());
            if (sanExt != null) {
                ASN1OctetString oct = ASN1OctetString.getInstance(sanExt);
                GeneralNames san = GeneralNames.getInstance(oct.getOctets());
                processGeneralNames(san, SANViolations,"");
            }
        } catch (Exception ignored) {
        }
    }

    private static boolean isValidDisplayText(byte tag, byte[] value) {
        return switch (tag) {
            case 0x16 -> ASN1DecodingChecker.isValidIA5String(value);
            case 0x1A -> ASN1DecodingChecker.isValidVisibleString(value);
            case 0x1E -> ASN1DecodingChecker.isValidBMPString(value);
            case 0x0C -> ASN1DecodingChecker.isValidUTF8String(value);
            default -> true;
        };
    }
    private static void EncodingDetectionCertPolicies(X509Certificate cert, Set<String> policyViolations) {
        try {
            byte[] policyExt = cert.getExtensionValue(Extension.certificatePolicies.getId());
            if (policyExt != null) {
                ASN1OctetString oct = ASN1OctetString.getInstance(policyExt);
                CertificatePolicies policies = CertificatePolicies.getInstance(oct.getOctets());
                PolicyInformation[] policyInfos = policies.getPolicyInformation();
                for (PolicyInformation info : policyInfos) {
                    ASN1Sequence qualifiers = info.getPolicyQualifiers();
                    if (qualifiers != null) {
                        for (int i = 0; i < qualifiers.size(); i++) {
                            PolicyQualifierInfo qualifier = PolicyQualifierInfo.getInstance(qualifiers.getObjectAt(i));
                            ASN1ObjectIdentifier qualifierId = qualifier.getPolicyQualifierId();
                            ASN1Encodable qualifierValue = qualifier.getQualifier();
                            byte[] derBytes = qualifierValue.toASN1Primitive().getEncoded();
                            byte[] valueBytes = ExtractVavlueFromTLV(derBytes);

                            if (qualifierId.equals(PolicyQualifierId.id_qt_cps)) {
                                if (!ASN1DecodingChecker.isValidIA5String(valueBytes)) {
                                    policyViolations.add("CPSURI");
                                }
                            } else if (qualifierId.equals(PolicyQualifierId.id_qt_unotice)) {
                                UserNotice userNotice = UserNotice.getInstance(qualifierValue);

                                // 检查 explicitText
                                if (userNotice.getExplicitText() != null) {
                                    byte[] explicitTextBytes = userNotice.getExplicitText().getEncoded();
                                    byte[] explicitTextValue = ExtractVavlueFromTLV(explicitTextBytes);

                                    if (!isValidDisplayText(explicitTextBytes[0], explicitTextValue)) {
                                        policyViolations.add("UserNotice ExplicitText "+ReflactByte2ASN1StringType(explicitTextBytes[0]));
                                    }
                                }

                                // Check noticeRef organization
                                NoticeReference noticeRef = userNotice.getNoticeRef();
                                if (noticeRef != null && noticeRef.getOrganization() != null) {
                                    byte[] orgBytes = noticeRef.getOrganization().getEncoded();
                                    byte[] orgValue = ExtractVavlueFromTLV(orgBytes);

                                    if (!isValidDisplayText(orgBytes[0], orgValue)) {
                                        policyViolations.add("UserNotice NoticeRef Organization "+ ReflactByte2ASN1StringType(orgBytes[0]));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception ignored) {
        }
    }

    private static void processGeneralNames(GeneralNames names, Set<String> violations,String prefix) {
        GeneralName[] nameArray = names.getNames();
        for (GeneralName name : nameArray) {
            int tag = name.getTagNo();
            try {
                byte[] derBytes = name.toASN1Primitive().getEncoded();

                // Only process RFC822Name DNSName URI
                switch (tag) {
                    case GeneralName.rfc822Name:
                        if (!ASN1DecodingChecker.isValidIA5String(ExtractVavlueFromTLV(derBytes))) {
                            violations.add(prefix + "RFC822Name");
                        }
                        break;
                    case GeneralName.dNSName:
                        if (!ASN1DecodingChecker.isValidIA5String(ExtractVavlueFromTLV(derBytes))) {
                            violations.add(prefix + "DNSName");
                        }
                        break;
                    case GeneralName.uniformResourceIdentifier:
                        if (!ASN1DecodingChecker.isValidIA5String(ExtractVavlueFromTLV(derBytes))) {
                            violations.add(prefix + "URI");
                        }
                        break;
                    default:
                        break;
                }
            } catch (Exception ignored) {
            }
        }
    }
    private static void EncodingDetectionSubject(X500Name subject,Set<String> SubjectViolations) {
        EncodingDetectionName(subject,SubjectViolations);
    }

    private static void EncodingDetectionIssuer(X500Name issuer, Set<String> IssuerViolations) {
        EncodingDetectionName(issuer,IssuerViolations);
    }

    private static void EncodingDetectionName(X500Name name,Set<String> Violations) {
        RDN[] rdns = name.getRDNs();
        for (RDN rdn : rdns) {
            AttributeTypeAndValue[] atvs = rdn.getTypesAndValues();
            for (AttributeTypeAndValue atv : atvs) {
                ASN1ObjectIdentifier oid = atv.getType();
                ASN1Encodable value = atv.getValue();
                String oidStr = oid.toString();
                byte[] derBytes;

                try {
                    derBytes = value.toASN1Primitive().getEncoded();//获取Value的原始DER字节
                } catch (Exception e) {//跳过当前DER bytes
                    continue;
                }

                String ASN1Type = ReflactByte2ASN1StringType(derBytes[0]);
                boolean isValid = isVaildASN1StringInName(derBytes);

                if (!isValid) {
                    Violations.add(oidStr+" "+ASN1Type);
                }
            }
        }
    }

    static byte[] ExtractVavlueFromTLV(byte[] tlv){
        int length = tlv[1]&0xff;
        if(length<128){
            return Arrays.copyOfRange(tlv, 2, tlv.length);
        }else{
            return Arrays.copyOfRange(tlv, 2+length-128, tlv.length);
        }
    }

    private static String ReflactByte2ASN1StringType(byte tlv){
        return switch (tlv) {
            case 0x0C -> "UTF8String";
            case 0x1E -> "BMPString";
            case 0x13 -> "PrintableString";
            case 0x16 -> "Ia5String";
            case 0x1A -> "VisibleString";
            default -> "Unknown";
        };
    }

    private static boolean isVaildASN1StringInName(byte[] value){
        byte[] v;
        return switch (value[0]) {
            case 0x0C -> {
                v = ExtractVavlueFromTLV(value);
                yield ASN1DecodingChecker.isValidUTF8String(v);
            }
            case 0x1E -> {
                v = ExtractVavlueFromTLV(value);
                yield ASN1DecodingChecker.isValidBMPString(v);
            }
            case 0x13 -> {
                v = ExtractVavlueFromTLV(value);
                yield ASN1DecodingChecker.isValidPrintableString(v);
            }
            case 0x16 -> {
                v = ExtractVavlueFromTLV(value);
                yield ASN1DecodingChecker.isValidIA5String(v);
            }
            default -> true;
        };
    }
}
