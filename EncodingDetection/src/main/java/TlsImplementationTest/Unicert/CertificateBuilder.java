package EncodingDetection.src.main.java.TlsImplementationTest.Unicert;

import java.io.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import com.fasterxml.jackson.databind.DeserializationFeature;
import okhttp3.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Security;
import java.time.Duration;
import java.util.*;

import static TlsImplementationTest.Unicert.EncodingDetection.ExtractVavlueFromTLV;

class CertInfo{
    public String NotBefore;
    public String NotAfter;
    public boolean isRevoked;
    public List<ChainResult> CertChainInfos ;
}

class ChainInfo {
    public Boolean isPublicRoot;
    public String sha1;
    public List<String> matchedRootStores;
}
class ChainResult {
    public String chainType;
    public ChainInfo chainInfo;
}

class AllInfo{
    public saveEntry CertWithViolations;
    public CertInfo certInfo;
}

public class CertificateBuilder {
    //GET Parameters
    private static final int MAX_RETRIES = 3;
    private static final int TIMEOUT_MS = 20000;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static String getCertFingerprint(X509Certificate cert) throws Exception {
        byte[] derBytes = cert.getEncoded();
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] hash = md.digest(derBytes);
        return bytesToHex(hash);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static List<X509Certificate> getSHA1ListFromJSON(String resourcePath) {

        ObjectMapper mapper = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        ArrayList<X509Certificate> res = new ArrayList<>();

        try(
                InputStream inputStream = CertificateBuilder.class.getResourceAsStream(resourcePath);
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream,StandardCharsets.UTF_8))
        ){
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                jEntry cert = mapper.readValue(line, jEntry.class);
                res.add(parsePemCertificate(cert.pem));
            }
        }catch (Exception ignored) {
        }
        return res;
    }

    public static Map<String, List<X509Certificate>> buildRootCertMap() {
        Map<String, List<X509Certificate>> root = new LinkedHashMap<>();
        try {
            root.put("360Brower", getSHA1ListFromJSON("/ROOT/360RootStore@latest.json"));
            root.put("Apple", getSHA1ListFromJSON("/ROOT/AppleRootStore@iso18_macos15.json"));
            root.put("Certifi", getSHA1ListFromJSON("/ROOT/CertifiRootStore@25_1_31.json"));
            root.put("Google", getSHA1ListFromJSON("/ROOT/GoogleRootStore@latest.json"));
            root.put("JAVA21", getSHA1ListFromJSON("/ROOT/Java21SecurityRootStore@latest.json"));
            root.put("MicroSoft", getSHA1ListFromJSON("/ROOT/MicroSoftRootStore@latest.json"));
            root.put("Mozilla", getSHA1ListFromJSON("/ROOT/MozillaRootStore@latest.json"));
            root.put("Ubuntu", getSHA1ListFromJSON("/ROOT/UbuntuRootStore@latest.json"));
        } catch (Exception ignored) {
            return null;//reload
        }
        return root;
    }

    private static X509Certificate parseDerCertificate(byte[] content) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(content));
        } catch (Exception e) {
            return null;
        }
    }

    public static X509Certificate parsePemCertificate(String content) {
        try{
            String pemData = content.replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "").replaceAll("[\\r\\n\\s]+", "");

            byte[] encodedCert = Base64.getDecoder().decode(pemData);

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(encodedCert));
        } catch (Exception e) {
            System.out.println(e);
            return null;
        }
    }

    public static X509Certificate fetchCertFromUri(String uri) {
        // http client
        OkHttpClient client = new OkHttpClient.Builder()
                .connectTimeout(Duration.ofMillis(5000))
                .readTimeout(Duration.ofMillis(3000))
                .build();

        // build request
        Request request;
        try{
             request= new Request.Builder()
                    .url(uri)
                    .get()
                    .build();
        }catch (Exception e){
            return null;
        }

        // request
        for (int i = 0; i < 5; i++) {
            try {
                Response response = client.newCall(request).execute();
                if (response.code() == 200 && response.body() != null) {
                    byte[] content = response.body().bytes();

                    X509Certificate derCert = parseDerCertificate(content);
                    if (derCert != null) {
                        response.close();
                        return derCert;
                    }

                    X509Certificate pemCert = parsePemCertificate(new String(content));
                    if (pemCert != null) {
                        response.close();
                        return pemCert;
                    }
                }
                response.close();
            } catch (Exception ignored) {}
        }
        return null;
    }

    //uri or null
    public static String getCaIssuersFromGN(GeneralName name) {
        try {
            byte[] derBytes = name.toASN1Primitive().getEncoded();
            byte[] valueBytes = ExtractVavlueFromTLV(derBytes);

            if (ASN1DecodingChecker.isValidIA5String(valueBytes)) {
                return new String(valueBytes, StandardCharsets.US_ASCII);
            }else{
                return null;
            }
        }catch(Exception ignored) {
            return null;
        }
    }

    public static List<String> getAiaIssuerUrl(X509Certificate certificate) {
        List<String> aiaIssuerUrls = new ArrayList<>();
        try {
            byte[] aiaExt = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
            if (aiaExt != null) {
                ASN1OctetString oct = ASN1OctetString.getInstance(aiaExt);
                AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(oct.getOctets());
                AccessDescription[] descriptions = aia.getAccessDescriptions();
                for (AccessDescription desc : descriptions) {
                    ASN1ObjectIdentifier accessMethod = desc.getAccessMethod();
                    GeneralName accessLocation = desc.getAccessLocation();

                    if(accessMethod.getId().equals("1.3.6.1.5.5.7.48.2") && accessLocation.getTagNo() == GeneralName.uniformResourceIdentifier){
                        aiaIssuerUrls.add(getCaIssuersFromGN(accessLocation));
                    }
                }
            }
        } catch (Exception e) {
            System.out.println(e);//Only check the ASN1String encoding error issue, and ignore all other problems
        }
        return aiaIssuerUrls;
    }

    public static boolean verifySignature(X509Certificate issuerCert, X509Certificate subjectCert) {
        try {
            X509CertificateHolder subjectCertHolder = new X509CertificateHolder(subjectCert.getEncoded());

            JcaContentVerifierProviderBuilder builder = new JcaContentVerifierProviderBuilder();
            ContentVerifierProvider verifierProvider = builder.build(issuerCert);

            return subjectCertHolder.isSignatureValid(verifierProvider);
        }catch (Exception ignored) {
            return false;
        }
    }

    public static List<List<X509Certificate>> findAllPaths(X509Certificate root) {
        List<List<X509Certificate>> result = new ArrayList<>();
        if (root == null) {
            return result;
        }

        List<X509Certificate> currentPath = new ArrayList<>();
        Set<String> visitedFingerprints = new HashSet<>();
        int maxDepth = 10;
        dfs(root, currentPath, result,visitedFingerprints, 0, maxDepth);
        return result;
    }

    private static void dfs(X509Certificate node, List<X509Certificate> currentPath, List<List<X509Certificate>> result,Set<String> visitedFingerprints,
                            int depth, int maxDepth) {
        if (depth > maxDepth) {
            result.add(new ArrayList<>(currentPath));
            return;
        }

        String fingerprint;
        try {
            fingerprint = getCertFingerprint(node);
        } catch (Exception e) {
            return;
        }

        if (visitedFingerprints.contains(fingerprint)) {
            result.add(new ArrayList<>(currentPath));
            return;
        }

        currentPath.add(node);
        visitedFingerprints.add(fingerprint);

        List<String> aiaIssuerUrl = getAiaIssuerUrl(node);

        if (aiaIssuerUrl.isEmpty()) {
            result.add(new ArrayList<>(currentPath));
        }else{
            List<String> sha1Index= new ArrayList<>();
            List<X509Certificate> children= new ArrayList<>();
            for (String aiaIssuer : aiaIssuerUrl) {
                X509Certificate child = fetchCertFromUri(aiaIssuer);
                if (child == null) {
                    continue;
                }
                String certFingerprint;
                try {
                     certFingerprint= getCertFingerprint(child);
                } catch (Exception e) {
                    continue;
                }
                if (!sha1Index.contains(certFingerprint) &&!visitedFingerprints.contains(certFingerprint)) {
                    sha1Index.add(certFingerprint);
                    children.add(child);
                }
            }

            if (children.isEmpty()) {
                result.add(new ArrayList<>(currentPath));
            } else {
                for (X509Certificate child : children) {
                    dfs(child, currentPath, result, visitedFingerprints, depth + 1, maxDepth);
                }
            }
        }

        currentPath.remove(currentPath.size() - 1);
        visitedFingerprints.remove(fingerprint);
    }

    public static boolean isSelfSigned(List<X509Certificate> certificates) {
        return verifySignature(certificates.getLast(), certificates.getLast());
    }

    public static ChainInfo isRootTrusted(X509Certificate certificate, Map<String, List<X509Certificate>> rootStores) {
        ChainInfo chainInfo = new ChainInfo();
        chainInfo.isPublicRoot = false;
        try{
            chainInfo.sha1 = getCertFingerprint(certificate);
        }catch (Exception ignored) {}

        chainInfo.matchedRootStores = new ArrayList<>();
        for (Map.Entry<String, List<X509Certificate>> entry : rootStores.entrySet()) {
            String key = entry.getKey();
            List<X509Certificate> certList = entry.getValue();

            for (X509Certificate cert : certList) {
                try {
                    if (getCertFingerprint(cert).equals(getCertFingerprint(certificate))) {
                        chainInfo.isPublicRoot = true;
                        chainInfo.matchedRootStores.add(key);
                        break;
                    }
                }catch (Exception ignored) {}
            }
        }
        return chainInfo;
    }

    public static boolean VerifySignature(List<X509Certificate> chain) {
        X509Certificate leaf = chain.getFirst();

        for (int i = 1; i < chain.size(); i++) {
            boolean b = verifySignature(chain.get(i), leaf);

            leaf = chain.get(i);
            if (!b){
                return false;
            }
        }
        return true;
    }

    public static ChainResult ClassifyChainType(List<X509Certificate> chain,Map<String, List<X509Certificate>> rootStores) {
        ChainResult chainResult = new ChainResult();
        if (!isSelfSigned(chain)) {
            chainResult.chainType = "BrokenChain";
            chainResult.chainInfo = null;
        }else if(!VerifySignature(chain)){
            chainResult.chainType = "FakeChain";
            chainResult.chainInfo = isRootTrusted(chain.getLast(), rootStores);
        }else if(!isRootTrusted(chain.getLast(), rootStores).isPublicRoot){
            chainResult.chainType = "PrivateCA";
            chainResult.chainInfo = isRootTrusted(chain.getLast(), rootStores);
        }else if(isRootTrusted(chain.getLast(), rootStores).isPublicRoot){
            chainResult.chainType = "TrustedCA";
            chainResult.chainInfo = isRootTrusted(chain.getLast(), rootStores);
        }else{
            chainResult.chainType = "Unknown";
            chainResult.chainInfo = null;
        }

        return chainResult;
    }

    public static String downloadPemCertFromSHA1(String sha1) {
        String searchUrl = "https://crt.sh/?q=" + sha1;
        for (int i = 0; i < 5; i++) {
            try {
                Document doc = Jsoup.connect(searchUrl)
                        .timeout(5000)
                        .get();

                Element certTable = doc.select("table").get(1);

                Elements certRows = certTable.select("tr");
                Element certRow = certRows.get(certRows.size() - 1);

                Element certTh = certRow.selectFirst("th");

                Element certSmall = certTh.selectFirst("span");

                Element link = certSmall.select("a").last();

                String attachedPath = link.attr("href");

                String pemUrl = "https://crt.sh/" + attachedPath;

                String pemDoc = Jsoup.connect(pemUrl)
                        .timeout(10000)
                        .ignoreContentType(true)
                        .execute()
                        .body();

                return pemDoc;
            } catch (Exception ignored) {
            }
        }
        return null;
    }

    public static String getURIForRevocation(String sha1) {
        String searchUrl = "https://crt.sh/?q=" + sha1;

        for (int i = 0; i < 6; i++) {
            try {
                Document doc = Jsoup.connect(searchUrl)
                        .timeout(5000)
                        .get();

                Elements tables = doc.select("table");
                if (tables.size() < 2) {
                    return null;
                }
                Element certTable = tables.get(1);

                Elements certRows = certTable.select("> tbody > tr");
                if (certRows.size() < 4) {
                    return null;
                }
                Element revokeTable = certRows.get(3);
                Elements revokeInfos = revokeTable.select("tr");
                if (revokeInfos.size() < 3) {
                    return null;
                }

                Elements revokeInfosSublist = new Elements();
                for (int j = 2; j < revokeInfos.size(); j++) {
                    revokeInfosSublist.add(revokeInfos.get(j));
                }
                try{
                    String attachedPath = revokeInfosSublist.getFirst().select("td").get(2).select("a").getFirst().attr("href");
                    String RealUri = "https://crt.sh/"+attachedPath;
                    return RealUri;
                }catch (Exception ignored) {
                }
            } catch (IOException ignored) {
            }
        }
        return null;
    }

    public static boolean isRevoked(String sha1) {
        String searchUrl = getURIForRevocation(sha1);
        if (searchUrl == null) {
           return false;
        }

        for (int i = 0; i < 5; i++) {
            try {
                Document doc = Jsoup.connect(searchUrl)
                        .timeout(5000)
                        .get();

                Elements tables = doc.select("table");
                if (tables.size() < 2) {
                    return false;
                }
                Element certTable = tables.get(1);

                Elements certRows = certTable.select("> tbody > tr");
                if (certRows.size() < 4) {
                    return false;
                }
                Element revokeTable = certRows.get(3);

                Elements revokeInfos = revokeTable.select("tr");
                if (revokeInfos.size() < 3) {
                    return false;
                }

                Elements revokeInfosSublist = new Elements();
                for (int j = 2; j < revokeInfos.size(); j++) {
                    revokeInfosSublist.add(revokeInfos.get(j));
                }

                for (Element revokeInfo : revokeInfosSublist) {
                    Elements tds = revokeInfo.select("td");
                    if (tds.size() >= 3 && tds.get(2).outerHtml().trim().contains("color:#CC0000")) {
                        return true;
                    }
                }
                return false;
            } catch (IOException ignored) {
            }
        }
        return false;
    }

    public static void getOtherInfos(X509Certificate cert,CertInfo certInfo) {
        certInfo.NotAfter = cert.getNotAfter().toString();
        certInfo.NotBefore = cert.getNotBefore().toString();
    }

    public static void main(String[] args) {
        Map<String, List<X509Certificate>> ROOT = buildRootCertMap();
        ObjectMapper mapper = new ObjectMapper();
        try(
                FileReader fileReader = new FileReader(args[0],StandardCharsets.UTF_8);
                FileWriter fileWriter = new FileWriter(args[1],true);
                BufferedReader bufferedReader = new BufferedReader(fileReader);
        ){
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                saveEntry cert = mapper.readValue(line, saveEntry.class);
                String pemstr = cert.pem;
                X509Certificate x509Certificate = parsePemCertificate(pemstr);

                if (x509Certificate == null) {
                    try(
                            FileWriter fileWriter1 = new FileWriter(args[2],true)
                    ){
                        fileWriter1.write(cert.sha1);
                        fileWriter1.write("\n");
                    }
                    continue;
                }
                List<List<X509Certificate>> lists = findAllPaths(x509Certificate);
                AllInfo allInfo = new AllInfo();
                allInfo.CertWithViolations = cert;
                allInfo.certInfo = new CertInfo();
                allInfo.certInfo.isRevoked = isRevoked(cert.sha1);
                getOtherInfos(lists.getFirst().getFirst(), allInfo.certInfo); //
                allInfo.certInfo.CertChainInfos = new ArrayList<>();
                for (List<X509Certificate> list : lists) {
                    ChainResult chainResult = ClassifyChainType(list,ROOT);
                    allInfo.certInfo.CertChainInfos.add(chainResult);
                }

                String jsonString = mapper.writeValueAsString(allInfo);
                fileWriter.write(jsonString+"\n");
            }
        }catch (Exception e) {
            System.out.println(e);
        }
    }
}



