package jwks

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
)

type JWK struct {
	Kty string `json:"kty"`
	E   string `json:"e"`
	N   string `json:"n"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	// Private key components (optional)
	D  string `json:"d,omitempty"`
	P  string `json:"p,omitempty"`
	Q  string `json:"q,omitempty"`
	DP string `json:"dp,omitempty"`
	DQ string `json:"dq,omitempty"`
	QI string `json:"qi,omitempty"`
}

// ExtraKey represents additional JWK fields
type ExtraKey struct {
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
}

// base64URLEncode encodes bytes to base64 URL encoding without padding
func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

// base64URLDecode decodes base64 URL encoded string
func base64URLDecode(data string) ([]byte, error) {
	if l := len(data) % 4; l > 0 {
		data += strings.Repeat("=", 4-l)
	}
	return base64.URLEncoding.DecodeString(data)
}

// generateJWK converts a PEM key to JWK format
func generateJWK(pemKey string, extraKey *ExtraKey, outputJWK string) (*JWK, error) {
	if pemKey == "" {
		return nil, fmt.Errorf("empty PEM key")
	}

	// Check PEM format
	if !strings.Contains(pemKey, "-----BEGIN") || !strings.Contains(pemKey, "-----END") {
		return nil, fmt.Errorf("invalid PEM format")
	}

	// Parse PEM block
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	jwkObject := &JWK{
		Kty: "RSA",
	}

	// Check if it's a private key
	isPrivate := strings.Contains(block.Type, "PRIVATE")

	if isPrivate {
		// Parse private key
		var privateKey *rsa.PrivateKey
		var err error

		// Try PKCS8 first
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			var ok bool
			privateKey, ok = key.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("not an RSA private key")
			}
		} else {
			// Try PKCS1
			privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse private key: %v", err)
			}
		}

		// Extract public key components
		publicKey := &privateKey.PublicKey
		jwkObject.E = base64URLEncode(big.NewInt(int64(publicKey.E)).Bytes())
		jwkObject.N = base64URLEncode(publicKey.N.Bytes())

		// If outputJWK is "private", include private key components
		if outputJWK == "private" {
			jwkObject.D = base64URLEncode(privateKey.D.Bytes())
			jwkObject.P = base64URLEncode(privateKey.Primes[0].Bytes())
			jwkObject.Q = base64URLEncode(privateKey.Primes[1].Bytes())
			jwkObject.DP = base64URLEncode(privateKey.Precomputed.Dp.Bytes())
			jwkObject.DQ = base64URLEncode(privateKey.Precomputed.Dq.Bytes())
			jwkObject.QI = base64URLEncode(privateKey.Precomputed.Qinv.Bytes())
		}
	} else {
		// Parse public key
		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %v", err)
		}

		rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA public key")
		}

		jwkObject.E = base64URLEncode(big.NewInt(int64(rsaPublicKey.E)).Bytes())
		jwkObject.N = base64URLEncode(rsaPublicKey.N.Bytes())
	}

	// Add extra key fields
	if extraKey != nil {
		if extraKey.Kid != "" {
			jwkObject.Kid = extraKey.Kid
		}
		if extraKey.Use != "" {
			jwkObject.Use = extraKey.Use
		}
		if extraKey.Alg != "" {
			jwkObject.Alg = extraKey.Alg
		}
	}

	return jwkObject, nil
}
