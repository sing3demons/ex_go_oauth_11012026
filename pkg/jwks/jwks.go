package jwks

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
)

type JWTService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
}
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`

	// RSA
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	// EC
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func b64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
func RSAJWK(kid, alg string, pub *rsa.PublicKey) JWK {
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: alg,
		Kid: kid,
		N:   b64(pub.N.Bytes()),
		E:   b64(big.NewInt(int64(pub.E)).Bytes()),
	}
}
func ECJWK(kid, alg string, pub *ecdsa.PublicKey) JWK {
	return JWK{
		Kty: "EC",
		Use: "sig",
		Alg: alg,
		Kid: kid,
		Crv: "P-256",
		X:   b64(pub.X.Bytes()),
		Y:   b64(pub.Y.Bytes()),
	}
}
func ParsePrivateKeyFromPEM(pemData string) (any, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("invalid PEM")
	}

	switch block.Type {

	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)

	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)

	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)

	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}
}
func ParsePublicKeyFromPEM(pemData string) (any, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("invalid PEM")
	}

	return x509.ParsePKIXPublicKey(block.Bytes)
}
