package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"
)

type JSONCert struct {
	SHA1            string `json:"sha1"`
	Pem             string `json:"pem"`
	FocusField      string `json:"FocusField"`
	FocusFieldValue string `json:"FocusFieldValue"`
	InsertValue     string `json:"InsertValue"`
	Des             string `json:"description"`
}

type Name struct {
	Country            []string `json:"Country"`
	Organization       []string `json:"Organization"`
	OrganizationalUnit []string `json:"OrganizationalUnit"`
	Locality           []string `json:"Locality"`
	Province           []string `json:"Province"`
	StreetAddress      []string `json:"StreetAddress"`
	PostalCode         []string `json:"PostalCode"`
	SerialNumber       string   `json:"SerialNumber"`
	CommonName         string   `json:"CommonName"`
	UnhandledOIDs      []string `json:"UnhandledOIDs"`
}

type Vaild struct {
	NotBefore time.Time `json:"NotBefore"`
	NotAfter  time.Time `json:"NotAfter"`
}

type ExtKU struct {
	ExtendedKeyUsage          []string `json:"ExtendedKeyUsage"`
	UnhandledExtendedKeyUsage []string `json:"UnhandledExtendedKeyUsage"`
}

type BasicCons struct {
	BasicConstraintsValid bool `json:"BasicConstraintsValid"`
	ISCA                  bool `json:"ISCA"`
	MaxPathLen            int  `json:"MaxPathLen"`
	MaxPathLenZero        bool `json:"MathPathZero"`
}

type AIA struct {
	OCSPServer            []string `json:"OCSPserver"`
	IssuingCertificateURL []string `json:"IssuingCertificateURL"`
}

type SAN struct {
	DNSNames       []string   `json:"DNSNames"`
	EmailAddresses []string   `json:"EmailAddresses"`
	IPAddresses    []net.IP   `json:"IPAddresses"`
	URIs           []*url.URL `json:"URIs"`
}
type NameCons struct {
	PermittedDNSDomainsCritical bool         `json:"PermittedDNSDomainsCritical"` // if true then the name constraints are marked critical.
	PermittedDNSDomains         []string     `json:"PermittedDNSDomains"`
	ExcludedDNSDomains          []string     `json:"ExcludedDNSDomains"`
	PermittedIPRanges           []*net.IPNet `json:"PermittedIPRanges"`
	ExcludedIPRanges            []*net.IPNet `json:"ExcludedIPRanges"`
	PermittedEmailAddresses     []string     `json:"PermittedEmailAddresses"`
	ExcludedEmailAddresses      []string     `json:"ExcludedEmailAddresses"`
	PermittedURIDomains         []string     `json:"PermittedURIDomains"`
	ExcludedURIDomains          []string     `json:"ExcludedURIDomains"`
}
type CertDefine struct {
	Sha1            string   `json:"sha1"`
	Status          bool     `json:"status"`
	Error_info      []string `json:"error_info"`
	Matched_unicode []string `json:"matched_unicode"`
	Cert_type       string   `json:"cert_type"` // DV IV OV EV UNKOWNEN
	Version         int8     `json:"Version"`
	SerialNumber    string   `json:"SerialNumber"`

	//subject和issuer Name
	Subject Name `json:"Subject"`
	Issuer  Name `json:"Issuer"`

	Vaildity Vaild `json:"Vaildity"`

	//Extensions
	KeyUsage    string `json:"KeyUsage"`
	ExtKeyUsage ExtKU  `json:"AllExtendedKeyUsage"`

	//BasicConstrains
	BasicConstains BasicCons `json:"BasicConstains"`

	SubjectKeyId   []byte `json:"skid"`
	AuthorityKeyId []byte `json:"akid"`

	//AIA
	AuthorityInfoAccess AIA `json:"AuthorityInfoAccess"`

	//SAN
	SubjectAlternativeName SAN `json:"SubjectAlternativeName"`

	//NameConstrains
	NameConstrains NameCons `json:"NameConstrains"`

	CRLDistributionPoints []string `json:"CRLDistributionPoints"`

	PolicyIdentifiers []string `json:"Policy"`

	UnhandledExtensionsOID []string `json:"UnhandledExtensionsOIDs"` //For extended fields that cannot be processed, only record the OID

	FocusField string `json:"FocusField"`

	FocusFieldValue string `json:"FocusFieldValue"`

	InsertValue string `json:"InsertValue"`

	Description string `json:"description"`
}

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage:./main InputFilePath OutputFilePath")
		os.Exit(1)
	}
	InputFilePath := os.Args[1]
	OutPutFilePath := os.Args[2]

	//open inputfile
	InputFile, err := os.Open(InputFilePath)
	if err != nil {
		fmt.Println("Error opening InputFile:", InputFilePath)
		os.Exit(1)
	}
	defer InputFile.Close()

	//open inputfile
	OutputFile, err := os.OpenFile(OutPutFilePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		fmt.Println("Error opening OutputFile:", OutPutFilePath)
		os.Exit(1)
	}
	defer OutputFile.Close()

	scanner := bufio.NewScanner(InputFile)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		line := scanner.Text()

		var mycert JSONCert
		err = json.Unmarshal([]byte(line), &mycert)
		if err != nil {
			fmt.Println("json:Error unmarshalling JsonStr:", err, "next JsonStr")
			continue
		}
		Gcert := CertDefine{}
		Gcert.Sha1 = mycert.SHA1
		Gcert.FocusField = mycert.FocusField
		Gcert.FocusFieldValue = mycert.FocusFieldValue
		Gcert.InsertValue = mycert.InsertValue
		Gcert.Description = mycert.Des

		Gcert.Status = true
		cert, err := PrasePemCert(mycert.Pem)
		if err != nil {
			Gcert.Status = false
			Gcert.Error_info = append(Gcert.Error_info, err.Error())

			JsonObj, err := json.Marshal(Gcert)
			if err != nil {
				fmt.Printf(mycert.SHA1, ",Parsing failed,json ser failed,next cert:%v", err.Error())
				continue
			}
			JsonObj = append(JsonObj, '\n')

			_, err1 := OutputFile.Write(JsonObj)

			if err1 != nil {
				fmt.Printf(mycert.SHA1, ",Parsing failed,json ser success,write to outputfile failed,next cert:%v", err1.Error())
			}

			continue
		}

		Gcert.Cert_type = JudgeCertType(cert)

		Gcert.Version = int8(cert.Version)
		Gcert.SerialNumber = (*cert.SerialNumber).Text(16)

		Gcert.Subject.CommonName = cert.Subject.CommonName
		Gcert.Subject.Country = cert.Subject.Country
		Gcert.Subject.Locality = cert.Subject.Locality
		Gcert.Subject.Organization = cert.Subject.Organization
		Gcert.Subject.OrganizationalUnit = cert.Subject.OrganizationalUnit
		Gcert.Subject.PostalCode = cert.Subject.PostalCode
		Gcert.Subject.Province = cert.Subject.Province
		Gcert.Subject.SerialNumber = cert.Subject.SerialNumber
		Gcert.Subject.StreetAddress = cert.Subject.StreetAddress

		Gcert.Issuer.CommonName = cert.Issuer.CommonName
		Gcert.Issuer.Country = cert.Issuer.Country
		Gcert.Issuer.Locality = cert.Issuer.Locality
		Gcert.Issuer.Organization = cert.Issuer.Organization
		Gcert.Issuer.OrganizationalUnit = cert.Issuer.OrganizationalUnit
		Gcert.Issuer.PostalCode = cert.Issuer.PostalCode
		Gcert.Issuer.Province = cert.Issuer.Province
		Gcert.Issuer.SerialNumber = cert.Issuer.SerialNumber
		Gcert.Issuer.StreetAddress = cert.Issuer.StreetAddress

		UnhandledIssuer := PhraseUnhandledIssuer(cert)
		for _, v := range UnhandledIssuer {
			Gcert.Issuer.UnhandledOIDs = append(Gcert.Issuer.UnhandledOIDs, v.String())
		}

		UnhandledSubject := PhraseUnhandledSubject(cert)
		for _, v := range UnhandledSubject {
			Gcert.Subject.UnhandledOIDs = append(Gcert.Subject.UnhandledOIDs, v.String())
		}

		Gcert.Vaildity.NotBefore = cert.NotBefore
		Gcert.Vaildity.NotAfter = cert.NotAfter

		Gcert.KeyUsage = ReflectKeyUsage(int(cert.KeyUsage))

		RecgExt := cert.ExtKeyUsage
		for _, v := range RecgExt {
			Gcert.ExtKeyUsage.ExtendedKeyUsage = append(Gcert.ExtKeyUsage.ExtendedKeyUsage, ReflectExtKeyUsage(int(v)))
		}

		UnhandledExt := PhraseUnhandledExtendedKeyUsage(cert)
		for _, v := range UnhandledExt {
			Gcert.ExtKeyUsage.UnhandledExtendedKeyUsage = append(Gcert.ExtKeyUsage.UnhandledExtendedKeyUsage, v.String())
		}

		Gcert.BasicConstains.BasicConstraintsValid = cert.BasicConstraintsValid
		Gcert.BasicConstains.ISCA = cert.IsCA
		Gcert.BasicConstains.MaxPathLen = cert.MaxPathLen
		Gcert.BasicConstains.MaxPathLenZero = cert.MaxPathLenZero

		Gcert.AuthorityKeyId = cert.AuthorityKeyId
		Gcert.SubjectKeyId = cert.SubjectKeyId

		//AIA
		Gcert.AuthorityInfoAccess.OCSPServer = cert.OCSPServer
		Gcert.AuthorityInfoAccess.IssuingCertificateURL = cert.IssuingCertificateURL

		PrintSANBytes(cert)
		//san
		Gcert.SubjectAlternativeName.DNSNames = cert.DNSNames
		Gcert.SubjectAlternativeName.IPAddresses = cert.IPAddresses
		Gcert.SubjectAlternativeName.EmailAddresses = cert.EmailAddresses
		Gcert.SubjectAlternativeName.URIs = cert.URIs

		Gcert.NameConstrains.PermittedDNSDomainsCritical = cert.PermittedDNSDomainsCritical
		Gcert.NameConstrains.PermittedDNSDomains = cert.PermittedDNSDomains
		Gcert.NameConstrains.ExcludedDNSDomains = cert.ExcludedDNSDomains
		Gcert.NameConstrains.PermittedEmailAddresses = cert.PermittedEmailAddresses
		Gcert.NameConstrains.ExcludedEmailAddresses = cert.ExcludedEmailAddresses
		Gcert.NameConstrains.PermittedIPRanges = cert.PermittedIPRanges
		Gcert.NameConstrains.ExcludedIPRanges = cert.ExcludedIPRanges
		Gcert.NameConstrains.PermittedURIDomains = cert.PermittedURIDomains
		Gcert.NameConstrains.ExcludedURIDomains = cert.ExcludedURIDomains

		Gcert.CRLDistributionPoints = cert.CRLDistributionPoints

		PolicyOIDs := cert.PolicyIdentifiers
		for _, v := range PolicyOIDs {
			Gcert.PolicyIdentifiers = append(Gcert.PolicyIdentifiers, v.String())
		}

		Unhandledexts, _, _ := PhraseUnhandledExtendedFileds(cert)
		for _, v := range Unhandledexts {
			Gcert.UnhandledExtensionsOID = append(Gcert.UnhandledExtensionsOID, v.String())
		}
		matched_unicode := []rune{}
		matched_unicode = append(matched_unicode, containsNonAllowedChars(Gcert.Issuer.CommonName)...)
		matched_unicode = append(matched_unicode, containsNonAllowedChars(Gcert.Issuer.SerialNumber)...)
		for _, v := range Gcert.Issuer.Country {
			matched_unicode = append(matched_unicode, containsNonAllowedChars(v)...)
		}
		for _, v := range Gcert.Issuer.Locality {
			matched_unicode = append(matched_unicode, containsNonAllowedChars(v)...)
		}
		for _, v := range Gcert.Issuer.Organization {
			matched_unicode = append(matched_unicode, containsNonAllowedChars(v)...)
		}
		for _, v := range Gcert.Issuer.OrganizationalUnit {
			matched_unicode = append(matched_unicode, containsNonAllowedChars(v)...)
		}
		for _, v := range Gcert.Issuer.PostalCode {
			matched_unicode = append(matched_unicode, containsNonAllowedChars(v)...)
		}
		for _, v := range Gcert.Issuer.Province {
			matched_unicode = append(matched_unicode, containsNonAllowedChars(v)...)
		}
		for _, v := range Gcert.Issuer.StreetAddress {
			matched_unicode = append(matched_unicode, containsNonAllowedChars(v)...)
		}

		matched_unicode = append(matched_unicode, containsNonAllowedChars(Gcert.Subject.CommonName)...)
		matched_unicode = append(matched_unicode, containsNonAllowedChars(Gcert.Subject.SerialNumber)...)
		for _, v := range Gcert.Subject.Country {
			matched_unicode = append(matched_unicode, containsNonAllowedChars(v)...)
		}
		for _, v := range Gcert.Subject.Locality {
			matched_unicode = append(matched_unicode, containsNonAllowedChars(v)...)
		}
		for _, v := range Gcert.Subject.Organization {
			matched_unicode = append(matched_unicode, containsNonAllowedChars(v)...)
		}
		for _, v := range Gcert.Subject.OrganizationalUnit {
			matched_unicode = append(matched_unicode, containsNonAllowedChars(v)...)
		}
		for _, v := range Gcert.Subject.PostalCode {
			matched_unicode = append(matched_unicode, containsNonAllowedChars(v)...)
		}
		for _, v := range Gcert.Subject.Province {
			matched_unicode = append(matched_unicode, containsNonAllowedChars(v)...)
		}
		for _, v := range Gcert.Subject.StreetAddress {
			matched_unicode = append(matched_unicode, containsNonAllowedChars(v)...)
		}

		for _, v := range Gcert.AuthorityInfoAccess.OCSPServer {
			matched_unicode = append(matched_unicode, containsNonAllowedChars(v)...)
		}
		for _, v := range Gcert.AuthorityInfoAccess.IssuingCertificateURL {
			matched_unicode = append(matched_unicode, containsNonAllowedChars(v)...)
		}

		for _, v := range Gcert.SubjectAlternativeName.DNSNames {
			matched_unicode = append(matched_unicode, containsNonAllowedChars(v)...)
		}
		for _, v := range Gcert.SubjectAlternativeName.EmailAddresses {
			matched_unicode = append(matched_unicode, containsNonAllowedChars(v)...)
		}
		for _, v := range Gcert.SubjectAlternativeName.IPAddresses {
			matched_unicode = append(matched_unicode, containsNonAllowedChars(v.String())...)
		}
		for _, v := range Gcert.SubjectAlternativeName.URIs {
			matched_unicode = append(matched_unicode, containsNonAllowedChars(v.String())...)
		}

		if Gcert.NameConstrains.PermittedDNSDomainsCritical {
			for _, v := range Gcert.NameConstrains.ExcludedDNSDomains {
				matched_unicode = append(matched_unicode, containsNonAllowedChars(v)...)
			}
			for _, v := range Gcert.NameConstrains.PermittedDNSDomains {
				matched_unicode = append(matched_unicode, containsNonAllowedChars(v)...)
			}
			for _, v := range Gcert.NameConstrains.ExcludedEmailAddresses {
				matched_unicode = append(matched_unicode, containsNonAllowedChars(v)...)
			}
			for _, v := range Gcert.NameConstrains.PermittedEmailAddresses {
				matched_unicode = append(matched_unicode, containsNonAllowedChars(v)...)
			}
			for _, v := range Gcert.NameConstrains.PermittedURIDomains {
				matched_unicode = append(matched_unicode, containsNonAllowedChars(v)...)
			}
			for _, v := range Gcert.NameConstrains.ExcludedURIDomains {
				matched_unicode = append(matched_unicode, containsNonAllowedChars(v)...)
			}
			for _, v := range Gcert.NameConstrains.PermittedIPRanges {
				matched_unicode = append(matched_unicode, containsNonAllowedChars(v.String())...)
			}
			for _, v := range Gcert.NameConstrains.ExcludedIPRanges {
				matched_unicode = append(matched_unicode, containsNonAllowedChars(v.String())...)
			}
		}

		for _, v := range Gcert.CRLDistributionPoints {
			matched_unicode = append(matched_unicode, containsNonAllowedChars(v)...)
		}

		matched_unicode = removeDuplicates(matched_unicode)
		for _, v := range matched_unicode {
			Gcert.Matched_unicode = append(Gcert.Matched_unicode, fmt.Sprintf("%U", v))
		}

		JsonObj, err := json.Marshal(Gcert)
		if err != nil {
			fmt.Printf(mycert.SHA1, ",Parsing success,json ser failed,next cert:%v", err.Error())
			continue
		}
		JsonObj = append(JsonObj, '\n')

		_, err1 := OutputFile.Write(JsonObj)

		if err1 != nil {
			fmt.Printf(mycert.SHA1, ",Parsing success,json ser success,write to outputfile failed,next cert:%v", err1.Error())
		}
	}
}
