package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"maps"
	"math/big"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sing3demons/oauth/kp/internal/config"
)

type JWTService struct {
	cfg  *config.AppConfig
	repo ISigningKeyRepository
}

func NewJWTService(cfg *config.AppConfig, repo ISigningKeyRepository) *JWTService {
	return &JWTService{
		cfg:  cfg,
		repo: repo,
	}
}

func (s *JWTService) GetJWKS() (JWKS, error) {
	sk, err := s.repo.LoadActiveKeyByAlgorithm()
	if err != nil {
		return JWKS{}, err
	}
	var keys []JWK
	for _, key := range sk {
		pubKeyAny, err := ParsePublicKeyFromPEM(key.PublicKey)
		if err != nil {
			return JWKS{}, err
		}
		switch key.Algorithm {
		case JWTAlgorithmRS256:
			pubKey, ok := pubKeyAny.(*rsa.PublicKey)
			if !ok {
				return JWKS{}, fmt.Errorf("invalid RSA public key")
			}
			jwk := RSAJWK(key.KID, string(key.Algorithm), pubKey)
			keys = append(keys, jwk)
		case JWTAlgorithmES256:
			pubKey, ok := pubKeyAny.(*ecdsa.PublicKey)
			if !ok {
				return JWKS{}, fmt.Errorf("invalid ECDSA public key")
			}
			jwk := ECJWK(key.KID, string(key.Algorithm), pubKey)
			keys = append(keys, jwk)
		default:
			return JWKS{}, fmt.Errorf("unsupported algorithm: %s", key.Algorithm)
		}
	}
	return JWKS{Keys: keys}, nil
}

func (s *JWTService) GenerateJwtToken(header, payload map[string]any, signature any) (string, error) {
	// validate header
	if _, ok := header["alg"]; !ok {
		return "", fmt.Errorf("missing alg in header")
	}
	if _, ok := header["typ"]; !ok {
		return "", fmt.Errorf("missing typ in header")
	}
	if _, ok := header["kid"]; !ok {
		return "", fmt.Errorf("missing kid in header")
	}

	var algorithm jwt.SigningMethod
	switch header["alg"] {
	case "RS256":
		algorithm = jwt.SigningMethodRS256
	case "ES256":
		algorithm = jwt.SigningMethodES256
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", header["alg"])
	}

	claims := jwt.MapClaims{}
	maps.Copy(claims, payload)

	token := jwt.NewWithClaims(algorithm, claims)
	token.Header["alg"] = header["alg"]
	token.Header["typ"] = header["typ"]
	token.Header["kid"] = header["kid"]

	// validate signature type
	var validSignature bool
	switch algorithm {
	case jwt.SigningMethodRS256:
		_, validSignature = signature.(*rsa.PrivateKey)
	case jwt.SigningMethodES256:
		_, validSignature = signature.(*ecdsa.PrivateKey)
	}
	if !validSignature {
		return "", fmt.Errorf("invalid signature type for algorithm: %s", header["alg"])
	}

	t, err := token.SignedString(signature)
	if err != nil {
		return "", err
	}

	parts := strings.Split(t, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid token format")
	}

	return t, nil
}

func (s *JWTService) GenerateJwtTokenWithAlg(ctx context.Context, payload map[string]any, alg string) (string, error) {
	signingKey, err := s.repo.FindByAlgorithm(ctx, alg)
	if err != nil {
		return "", err
	}
	// validate header
	var algorithm jwt.SigningMethod
	switch signingKey.Algorithm {
	case "RS256":
		algorithm = jwt.SigningMethodRS256
	case "ES256":
		algorithm = jwt.SigningMethodES256
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", signingKey.Algorithm)
	}

	if payload["iss"] == nil {
		payload["iss"] = s.cfg.OidcConfig.Issuer
	}
	if payload["jti"] == nil {
		payload["jti"] = uuid.New().String()
	}
	if payload["iat"] == nil {
		payload["iat"] = time.Now().Unix()
	}
	if payload["exp"] == nil {
		return "", fmt.Errorf("missing exp in payload")
	}

	claims := jwt.MapClaims{}
	maps.Copy(claims, payload)

	token := jwt.NewWithClaims(algorithm, claims)
	token.Header["alg"] = signingKey.Algorithm
	token.Header["typ"] = "JWT"
	token.Header["kid"] = signingKey.KID

	// validate signature type
	privateKeyAny, err := ParsePrivateKeyFromPEM(signingKey.PrivateKey)
	if err != nil {
		return "", err
	}

	t, err := token.SignedString(privateKeyAny)
	if err != nil {
		return "", err
	}

	parts := strings.Split(t, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid token format")
	}

	return t, nil
}

func (s *JWTService) ValidateJwksToken(ctx context.Context, tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}

		alg, ok := token.Header["alg"].(string)
		if !ok {
			return nil, fmt.Errorf("missing alg in token header")
		}

		signingKey, err := s.repo.FindByAlgorithm(ctx, alg)
		if err != nil {
			return nil, err
		}
		if signingKey.KID != kid {
			return nil, fmt.Errorf("kid mismatch")
		}

		publicKey, err := ParsePublicKeyFromPEM(signingKey.PublicKey)
		if err != nil {
			return nil, err
		}

		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return token, nil
}

func (s *JWTService) ParseAndValidateJwtToken(tokenString string, publicKey any) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return token, nil
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
