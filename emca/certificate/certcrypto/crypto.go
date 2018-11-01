package certcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Constants for all key types we support.
const (
	EC256   = KeyType("P256")
	EC384   = KeyType("P384")
	RSA2048 = KeyType("2048")
	RSA4096 = KeyType("4096")
	RSA8192 = KeyType("8192")
)

const (
	// OCSPGood means that the certificate is valid.
	OCSPGood = ocsp.Good
	// OCSPRevoked means that the certificate has been deliberately revoked.
	OCSPRevoked = ocsp.Revoked
	// OCSPUnknown means that the OCSP responder doesn't know about the certificate.
	OCSPUnknown = ocsp.Unknown
	// OCSPServerFailed means that the OCSP responder failed to process the request.
	OCSPServerFailed = ocsp.ServerFailed
)

// Constants for OCSP must staple
var (
	tlsFeatureExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	ocspMustStapleFeature  = []byte{0x30, 0x03, 0x02, 0x01, 0x05}
)

// KeyType represents the key algo as well as the key size or curve to use.
type KeyType string

type DERCertificateBytes []byte

// FIXME move to Client?
// GetOCSPForCert takes a PEM encoded cert or cert bundle returning the raw OCSP response,
// the parsed response, and an error, if any.
// The returned []byte can be passed directly into the OCSPStaple property of a tls.Certificate.
// If the bundle only contains the issued certificate,
// this function will try to get the issuer certificate from the IssuingCertificateURL in the certificate.
// If the []byte and/or ocsp.Response return values are nil, the OCSP status may be assumed OCSPUnknown.
// func GetOCSPForCert(bundle []byte) ([]byte, *ocsp.Response, error) {
// 	certificates, err := ParsePEMBundle(bundle)
// 	if err != nil {
// 		return nil, nil, err
// 	}
//
// 	// We expect the certificate slice to be ordered downwards the chain.
// 	// SRV CRT -> CA. We need to pull the leaf and issuer certs out of it,
// 	// which should always be the first two certificates. If there's no
// 	// OCSP server listed in the leaf cert, there's nothing to do. And if
// 	// we have only one certificate so far, we need to get the issuer cert.
// 	issuedCert := certificates[0]
// 	if len(issuedCert.OCSPServer) == 0 {
// 		return nil, nil, errors.New("no OCSP server specified in cert")
// 	}
// 	if len(certificates) == 1 {
// 		// TODO: build fallback. If this fails, check the remaining array entries.
// 		if len(issuedCert.IssuingCertificateURL) == 0 {
// 			return nil, nil, errors.New("no issuing certificate URL")
// 		}
//
// 		resp, errC := httpGet(issuedCert.IssuingCertificateURL[0])
// 		if errC != nil {
// 			return nil, nil, errC
// 		}
// 		defer resp.Body.Close()
//
// 		issuerBytes, errC := ioutil.ReadAll(limitReader(resp.Body, maxBodySize))
// 		if errC != nil {
// 			return nil, nil, errC
// 		}
//
// 		issuerCert, errC := x509.ParseCertificate(issuerBytes)
// 		if errC != nil {
// 			return nil, nil, errC
// 		}
//
// 		// Insert it into the slice on position 0
// 		// We want it ordered right SRV CRT -> CA
// 		certificates = append(certificates, issuerCert)
// 	}
// 	issuerCert := certificates[1]
//
// 	// Finally kick off the OCSP request.
// 	ocspReq, err := ocsp.CreateRequest(issuedCert, issuerCert, nil)
// 	if err != nil {
// 		return nil, nil, err
// 	}
//
// 	resp, err := httpPost(issuedCert.OCSPServer[0], "application/ocsp-request", bytes.NewReader(ocspReq))
// 	if err != nil {
// 		return nil, nil, err
// 	}
// 	defer resp.Body.Close()
//
// 	ocspResBytes, err := ioutil.ReadAll(limitReader(resp.Body, maxBodySize))
// 	if err != nil {
// 		return nil, nil, err
// 	}
//
// 	ocspRes, err := ocsp.ParseResponse(ocspResBytes, issuerCert)
// 	if err != nil {
// 		return nil, nil, err
// 	}
//
// 	return ocspResBytes, ocspRes, nil
// }

// ParsePEMBundle parses a certificate bundle from top to bottom and returns
// a slice of x509 certificates. This function will error if no certificates are found.
func ParsePEMBundle(bundle []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	var certDERBlock *pem.Block

	for {
		certDERBlock, bundle = pem.Decode(bundle)
		if certDERBlock == nil {
			break
		}

		if certDERBlock.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(certDERBlock.Bytes)
			if err != nil {
				return nil, err
			}
			certificates = append(certificates, cert)
		}
	}

	if len(certificates) == 0 {
		return nil, errors.New("no certificates were found while parsing the bundle")
	}

	return certificates, nil
}

func ParsePEMPrivateKey(key []byte) (crypto.PrivateKey, error) {
	keyBlock, _ := pem.Decode(key)

	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(keyBlock.Bytes)
	default:
		return nil, errors.New("unknown PEM header value")
	}
}

func GeneratePrivateKey(keyType KeyType) (crypto.PrivateKey, error) {
	switch keyType {
	case EC256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case EC384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case RSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case RSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case RSA8192:
		return rsa.GenerateKey(rand.Reader, 8192)
	}

	return nil, fmt.Errorf("invalid KeyType: %s", keyType)
}

func GenerateCsr(privateKey crypto.PrivateKey, domain string, san []string, mustStaple bool) ([]byte, error) {
	template := x509.CertificateRequest{
		Subject: pkix.Name{CommonName: domain},
	}

	if len(san) > 0 {
		template.DNSNames = san
	}

	if mustStaple {
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:    tlsFeatureExtensionOID,
			Value: ocspMustStapleFeature,
		})
	}

	return x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
}

// TODO use crypto.PrivateKey?
func PEMEncode(data interface{}) []byte {
	var pemBlock *pem.Block
	switch key := data.(type) {
	case *ecdsa.PrivateKey:
		keyBytes, _ := x509.MarshalECPrivateKey(key)
		pemBlock = &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}
	case *rsa.PrivateKey:
		pemBlock = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	case *x509.CertificateRequest:
		pemBlock = &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: key.Raw}
	case DERCertificateBytes:
		pemBlock = &pem.Block{Type: "CERTIFICATE", Bytes: []byte(data.(DERCertificateBytes))}
	}

	return pem.EncodeToMemory(pemBlock)
}

func pemDecode(data []byte) (*pem.Block, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, fmt.Errorf("Pem decode did not yield a valid block. Is the certificate in the right format?")
	}

	return pemBlock, nil
}

func PemDecodeTox509CSR(pem []byte) (*x509.CertificateRequest, error) {
	pemBlock, err := pemDecode(pem)
	if pemBlock == nil {
		return nil, err
	}

	if pemBlock.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("PEM block is not a certificate request")
	}

	return x509.ParseCertificateRequest(pemBlock.Bytes)
}

// GetPEMCertExpiration returns the "NotAfter" date of a PEM encoded certificate.
// The certificate has to be PEM encoded. Any other encodings like DER will fail.
func GetPEMCertExpiration(cert []byte) (time.Time, error) {
	pemBlock, err := pemDecode(cert)
	if pemBlock == nil {
		return time.Time{}, err
	}

	return getCertExpiration(pemBlock.Bytes)
}

// getCertExpiration returns the "NotAfter" date of a DER encoded certificate.
func getCertExpiration(cert []byte) (time.Time, error) {
	pCert, err := x509.ParseCertificate(cert)
	if err != nil {
		return time.Time{}, err
	}

	return pCert.NotAfter, nil
}

func GeneratePemCert(privKey *rsa.PrivateKey, domain string, extensions []pkix.Extension) ([]byte, error) {
	derBytes, err := generateDerCert(privKey, time.Time{}, domain, extensions)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), nil
}

func generateDerCert(privKey *rsa.PrivateKey, expiration time.Time, domain string, extensions []pkix.Extension) ([]byte, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	if expiration.IsZero() {
		expiration = time.Now().Add(365)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "ACME Challenge TEMP",
		},
		NotBefore: time.Now(),
		NotAfter:  expiration,

		KeyUsage:              x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
		ExtraExtensions:       extensions,
	}

	return x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
}