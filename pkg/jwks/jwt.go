package jwks

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/golang-jwt/jwt/v5"
)

func GenerateJWT(header map[string]interface{}, privateKeyPEM string, payload jwt.MapClaims) (string, error) {
	if header == nil || privateKeyPEM == "" || payload == nil {
		return "", fmt.Errorf("invalid input parameters")
	}

	// Parse private key
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to parse PEM block")
	}

	var privateKey *rsa.PrivateKey
	var err error

	// Try PKCS8 first
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("not an RSA private key")
		}
	} else {
		// Try PKCS1
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("failed to parse private key: %v", err)
		}
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, payload)

	// Set custom headers
	for k, v := range header {
		token.Header[k] = v
	}

	// Sign token
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %v", err)
	}

	return tokenString, nil
}

func VerifyPublicKeys(token string, jwks []JWK) (jwt.Claims, error) {
	var lastError []string

	for _, jwk := range jwks {
		// Convert JWK to RSA public key
		nBytes, err := base64URLDecode(jwk.N)
		if err != nil {
			lastError = append(lastError, err.Error())
			continue
		}

		eBytes, err := base64URLDecode(jwk.E)
		if err != nil {
			lastError = append(lastError, err.Error())
			continue
		}

		n := new(big.Int).SetBytes(nBytes)
		eInt := new(big.Int).SetBytes(eBytes)
		e := int(eInt.Int64())

		publicKey := &rsa.PublicKey{
			N: n,
			E: e,
		}

		// Parse and verify token
		parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
			// Verify signing method
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return publicKey, nil
		})

		if err == nil && parsedToken.Valid {
			fmt.Println("!!! VERIFY TOKEN IS SUCCESS !!!")
			return parsedToken.Claims, nil
		}

		if err != nil {
			lastError = append(lastError, err.Error())
		}
	}

	return nil, fmt.Errorf("failed to verify token: %v", lastError)
}
