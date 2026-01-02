package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWK represents a JSON Web Key
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

// Result represents a generic result structure
type Result struct {
	Err        bool        `json:"err"`
	ResultDesc string      `json:"result_desc"`
	JWKObject  *JWK        `json:"jwkObject,omitempty"`
	JWTCode    string      `json:"jwt_code,omitempty"`
	ResultData interface{} `json:"result_data,omitempty"`
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
func generateJWK(pemKey string, extraKey *ExtraKey, outputJWK string) Result {
	if pemKey == "" {
		return Result{
			Err:        true,
			ResultDesc: "missing_key_data",
		}
	}

	// Check PEM format
	if !strings.Contains(pemKey, "-----BEGIN") || !strings.Contains(pemKey, "-----END") {
		return Result{
			Err:        true,
			ResultDesc: "invalid_format",
		}
	}

	// Parse PEM block
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return Result{
			Err:        true,
			ResultDesc: "failed to parse PEM block",
		}
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
				return Result{
					Err:        true,
					ResultDesc: "not an RSA private key",
				}
			}
		} else {
			// Try PKCS1
			privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return Result{
					Err:        true,
					ResultDesc: fmt.Sprintf("failed to parse private key: %v", err),
				}
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
			return Result{
				Err:        true,
				ResultDesc: fmt.Sprintf("failed to parse public key: %v", err),
			}
		}

		rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return Result{
				Err:        true,
				ResultDesc: "not an RSA public key",
			}
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

	return Result{
		Err:        false,
		ResultDesc: "success",
		JWKObject:  jwkObject,
	}
}

// verifyPublicKeys verifies a JWT token using a list of JWKs
func verifyPublicKeys(token string, jwks []JWK) Result {
	var lastError string

	for _, jwk := range jwks {
		// Convert JWK to RSA public key
		nBytes, err := base64URLDecode(jwk.N)
		if err != nil {
			lastError = fmt.Sprintf("failed to decode N: %v", err)
			continue
		}

		eBytes, err := base64URLDecode(jwk.E)
		if err != nil {
			lastError = fmt.Sprintf("failed to decode E: %v", err)
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
			return Result{
				Err:        false,
				ResultDesc: "success",
				ResultData: parsedToken.Claims,
			}
		}

		if err != nil {
			lastError = err.Error()
		}
	}

	return Result{
		Err:        true,
		ResultDesc: lastError,
	}
}

// generateJWT generates a JWT token
func generateJWT(header map[string]interface{}, privateKeyPEM string, payload jwt.MapClaims) Result {
	if header == nil || privateKeyPEM == "" || payload == nil {
		return Result{
			Err:        true,
			ResultDesc: "cannot generateJWT",
		}
	}

	// Parse private key
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return Result{
			Err:        true,
			ResultDesc: "failed to parse PEM block",
		}
	}

	var privateKey *rsa.PrivateKey
	var err error

	// Try PKCS8 first
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return Result{
				Err:        true,
				ResultDesc: "not an RSA private key",
			}
		}
	} else {
		// Try PKCS1
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return Result{
				Err:        true,
				ResultDesc: fmt.Sprintf("failed to parse private key: %v", err),
			}
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
		return Result{
			Err:        true,
			ResultDesc: err.Error(),
		}
	}

	return Result{
		Err:        false,
		ResultDesc: "success",
		JWTCode:    tokenString,
	}
}

func generateKeyID(pemKey string) string {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return "default-key-id"
	}

	// Use SHA256 of DER bytes as kid
	hash := fmt.Sprintf("%x", block.Bytes[:8])
	return hash
}

type KeyManager struct {
	keys []JWK
	mu   sync.RWMutex
}

func (km *KeyManager) GetKeys() []JWK {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.keys
}

func (km *KeyManager) AddKey(jwk JWK) {
	km.mu.Lock()
	defer km.mu.Unlock()
	km.keys = append(km.keys, jwk)
}

func main() {
	// Read private key from file
	pemKey, err := os.ReadFile("./private.pem")
	if err != nil {
		fmt.Printf("Error reading private key: %v\n", err)
		return
	}

	extraKey := &ExtraKey{
		Kid: generateKeyID(string(pemKey)),
		Use: "sig",
		Alg: "RS256",
	}

	outputJWK := "public" // or "private"

	keyManager := &KeyManager{
		keys: []JWK{},
	}

	// Generate JWK
	jwkResult := generateJWK(string(pemKey), extraKey, outputJWK)
	if !jwkResult.Err {
		// jwkJSON, _ := json.MarshalIndent(jwkResult.JWKObject, "", "  ")
		// fmt.Printf("Generated JWK: %s\n", string(jwkJSON))

		keyManager.AddKey(*jwkResult.JWKObject)
	} else {
		fmt.Printf("Error generating JWK: %s\n", jwkResult.ResultDesc)
		return
	}

	// read public key from file
	publicPemKey, err := os.ReadFile("./public.pem")
	if err == nil {
		publicExtraKey := &ExtraKey{
			Kid: generateKeyID(string(publicPemKey)),
			Use: "sig",
			Alg: "RS256",
		}
		publicJwkResult := generateJWK(string(publicPemKey), publicExtraKey, "public")
		if !publicJwkResult.Err {
			if publicJwkResult.JWKObject.Alg == jwkResult.JWKObject.Alg && publicJwkResult.JWKObject.N == jwkResult.JWKObject.N && publicJwkResult.JWKObject.E == jwkResult.JWKObject.E && publicJwkResult.JWKObject.Kty == jwkResult.JWKObject.Kty && publicJwkResult.JWKObject.Use == jwkResult.JWKObject.Use {
				// keyManager.AddKey(*publicJwkResult.JWKObject)
				fmt.Println("Public key is identical to private key's public part; not adding duplicate.")
			}else{
				keyManager.AddKey(*publicJwkResult.JWKObject)
			}
		}
	}

	http.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"keys": keyManager.GetKeys(),
		})
	})

	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// JWT header
		headerJWT := map[string]interface{}{
			"alg": "RS256",
			"typ": "JWT",
			"kid": extraKey.Kid,
		}
		// Setup data
		now := time.Now()
		expireToken := now.Add(1 * time.Hour)

		// JWT payload
		payload := jwt.MapClaims{
			"iss": "http://localhost:8082",
			"sub": "idToken",
			"aud": "client123",
			"exp": expireToken.Unix(),
			"iat": now.Unix(),
		}

		// Generate JWT
		tokenResult := generateJWT(headerJWT, string(pemKey), payload)
		w.Header().Set("Content-Type", "application/json")

		if !tokenResult.Err {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]any{
				"error": tokenResult.ResultDesc,
			})
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"token": tokenResult.JWTCode,
		})
	})
	http.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		verifyResult := verifyPublicKeys(token, []JWK{*jwkResult.JWKObject})
		w.Header().Set("Content-Type", "application/json")

		if !verifyResult.Err {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]any{
				"error": verifyResult.ResultDesc,
			})
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"payload": verifyResult.ResultData,
		})
	})

	fmt.Println("Starting server at :8082")
	http.ListenAndServe(":8082", nil)
}
