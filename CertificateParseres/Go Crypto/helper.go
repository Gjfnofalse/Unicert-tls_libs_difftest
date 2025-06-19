package main

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
)

type CertType int8

const (
	DV CertType = iota
	IV
	OV
	EV
	UNKOWNEN
)

var KeyUsage = []int{2, 5, 29, 15}
var ExtKeyUsageOID = []int{2, 5, 29, 37}
var BasicConstaintsOID = []int{2, 5, 29, 19}
var AIAOID = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
var SANOID = []int{2, 5, 29, 17}
var NameConstaintsOID = []int{2, 5, 29, 30}
var CRLDistributionPointsOID = []int{2, 5, 29, 31}
var PolicyOID = []int{2, 5, 29, 32}
var SkidOID = []int{2, 5, 29, 14}
var AkidOID = []int{2, 5, 29, 35}

// oid used in subject and issuer
var Country = []int{2, 5, 4, 6}
var Organization = []int{2, 5, 4, 10}
var OrganizationalUnit = []int{2, 5, 4, 11}
var Locality = []int{2, 5, 4, 7}
var Province = []int{2, 5, 4, 8}
var StreetAddress = []int{2, 5, 4, 9}
var PostalCode = []int{2, 5, 4, 17}
var SerialNumber = []int{2, 5, 4, 5}
var CommonName = []int{2, 5, 4, 3}

// Policy OID
var DVcert = []int{2, 23, 140, 1, 2, 1}
var IVcert = []int{2, 23, 140, 1, 2, 3}
var OVcert = []int{2, 23, 140, 1, 2, 2}
var EVcert = []int{2, 23, 140, 1, 1}

// The OID slice of the field that golang can parse
var StandardExtensions = []asn1.ObjectIdentifier{ExtKeyUsageOID, BasicConstaintsOID,
	AIAOID, SANOID, NameConstaintsOID, CRLDistributionPointsOID, PolicyOID, SkidOID, AkidOID, KeyUsage}
var StanardNames = []asn1.ObjectIdentifier{Country, Organization, OrganizationalUnit,
	Locality, Province, StreetAddress, PostalCode, SerialNumber, CommonName}
var CertTypes map[string]asn1.ObjectIdentifier = map[string]asn1.ObjectIdentifier{
	"DV": DVcert,
	"IV": IVcert,
	"OV": OVcert,
	"EV": EVcert,
}

// Objective: Parse the certificate. If the parsing fails, record the failure information
// Success is divided into three parts:
// 1)parsedvalue of basic field
// 2)Extended fields parsed by golang crypto
// 3)Extended fields that golang does not parse, recording OID and btyes data

func PrasePemCertFromBytes(sha1Cert []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(sha1Cert)
	der := block.Bytes //der
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func PrasePemCert(CertStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(CertStr))
	der := block.Bytes //der
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func PrintSANBytes(cert *x509.Certificate) {
	extensions := cert.ExtraExtensions
	for _, v := range extensions {
		var san_oid asn1.ObjectIdentifier = []int{2, 5, 29, 17}
		if v.Id.Equal(san_oid) {
			fmt.Printf("bytes of SAN:%v\n", v.Value)
		}
	}
}

func PhraseUnhandledExtendedFileds(cert *x509.Certificate) ([]asn1.ObjectIdentifier, [][]byte, []bool) {
	var OID = []asn1.ObjectIdentifier{}
	var Value = []([]byte){}
	var Critical = []bool{}
	for _, v := range cert.Extensions {
		recordTag := 0
		for _, st := range StandardExtensions {
			if st.Equal(v.Id) {
				recordTag += 1
				break
			}
		}
		if recordTag == 0 {
			OID = append(OID, v.Id)
			Value = append(Value, v.Value)
			Critical = append(Critical, v.Critical)
		}
	}
	return OID, Value, Critical
}

func PhraseUnhandledExtendedKeyUsage(cert *x509.Certificate) []asn1.ObjectIdentifier {
	var OID = []asn1.ObjectIdentifier{}

	OID = append(OID, cert.UnknownExtKeyUsage...)
	return OID
}

func ContainsUnicode(d []byte, s rune) bool {
	flag := bytes.ContainsRune(d, s)
	if flag {
		return true
	} else {
		return false
	}
}

func PhraseUnhandledIssuer(cert *x509.Certificate) []asn1.ObjectIdentifier {
	//Return the OID of the Issuer that cannot be parsed
	OID := []asn1.ObjectIdentifier{}
	res := cert.Issuer.ExtraNames
	for _, v := range res {
		recordTag := 0
		for _, va := range StanardNames {
			if v.Type.Equal(va) {
				recordTag += 1
				break
			}
		}
		if recordTag == 0 {
			OID = append(OID, v.Type)
		}
	}
	return OID
}

func PhraseUnhandledSubject(cert *x509.Certificate) []asn1.ObjectIdentifier {
	//Return the OID of the Subject that cannot be parsed
	OID := []asn1.ObjectIdentifier{}
	res := cert.Subject.ExtraNames
	for _, v := range res {
		recordTag := 0
		for _, va := range StanardNames {
			if v.Type.Equal(va) {
				recordTag += 1
				break
			}
		}
		if recordTag == 0 {
			OID = append(OID, v.Type)
		}
	}
	return OID
}

func JudgeCertType(cert *x509.Certificate) string {
	policies := cert.PolicyIdentifiers
	for _, v := range policies {
		for k, va := range CertTypes {
			if v.Equal(va) {
				return k
			}
		}
	}
	return "UNKOWNEN"
}

func ReflectKeyUsage(num int) string {
	switch num {
	case 1:
		return "KeyUsageDigitalSignature"
	case 2:
		return "KeyUsageContentCommitment"
	case 4:
		return "KeyUsageKeyEncipherment"
	case 8:
		return "KeyUsageDataEncipherment"
	case 16:
		return "KeyUsageKeyAgreement"
	case 32:
		return "KeyUsageCertSign"
	case 64:
		return "KeyUsageCRLSign"
	case 128:
		return "KeyUsageEncipherOnly"
	case 256:
		return "KeyUsageDecipherOnly"
	default:
		return "UNDEFINED"
	}

}

func ReflectExtKeyUsage(num int) string {
	switch num {
	case 0:
		return "ExtKeyUsageAny"
	case 1:
		return "ExtKeyUsageServerAuth"
	case 2:
		return "ExtKeyUsageClientAuth"
	case 3:
		return "ExtKeyUsageCodeSigning"
	case 4:
		return "ExtKeyUsageEmailProtection"
	case 5:
		return "ExtKeyUsageIPSECEndSystem"
	case 6:
		return "ExtKeyUsageIPSECTunnel"
	case 7:
		return "ExtKeyUsageIPSECUser"
	case 8:
		return "ExtKeyUsageTimeStamping"
	case 9:
		return "ExtKeyUsageOCSPSigning"
	case 10:
		return "ExtKeyUsageMicrosoftServerGatedCrypto"
	case 11:
		return "ExtKeyUsageNetscapeServerGatedCrypto"
	case 12:
		return "ExtKeyUsageMicrosoftCommercialCodeSigning"
	case 13:
		return "ExtKeyUsageMicrosoftKernelCodeSigning"
	default:
		return "UNDEFINED"
	}

}

func containsNonAllowedChars(s string) []rune {
	tmp := []rune{}
	for _, v := range s {
		if v <= '\u0020' || v >= '\u007e' {
			tmp = append(tmp, v)
		}
	}
	return tmp
}

func removeDuplicates(numbers []rune) []rune {
	encountered := make(map[rune]bool)

	unique := []rune{}

	for _, number := range numbers {
		if !encountered[number] {
			encountered[number] = true
			unique = append(unique, number)
		}
	}

	return unique
}
