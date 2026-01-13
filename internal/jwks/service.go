package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"maps"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sing3demons/oauth/kp/internal/config"
	"github.com/sing3demons/oauth/kp/pkg/kp"
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

func (s *JWTService) GetJWKS(c context.Context) (JWKS, error) {
	sk, err := s.repo.FindKeyOidcByAlgorithm(c)
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
				return JWKS{}, &kp.Error{
					Message:    "server_error",
					StatusCode: http.StatusInternalServerError,
					Err:        fmt.Errorf("invalid RSA public key"),
				}
			}
			jwk := RSAJWK(key.KID, string(key.Algorithm), pubKey)
			keys = append(keys, jwk)
		case JWTAlgorithmES256:
			pubKey, ok := pubKeyAny.(*ecdsa.PublicKey)
			if !ok {
				return JWKS{}, &kp.Error{
					Message:    "server_error",
					StatusCode: http.StatusInternalServerError,
					Err:        fmt.Errorf("invalid EC public key"),
				}
			}
			jwk := ECJWK(key.KID, string(key.Algorithm), pubKey)
			keys = append(keys, jwk)
		default:
			return JWKS{}, &kp.Error{
				Message:    "server_error",
				StatusCode: http.StatusInternalServerError,
				Err:        fmt.Errorf("unsupported algorithm: %s", key.Algorithm),
			}
		}
	}
	return JWKS{Keys: keys}, nil
}

func (s *JWTService) GenerateJwtToken(signingKey SigningKey, payload map[string]any) (string, error) {
	var algorithm jwt.SigningMethod
	switch signingKey.Algorithm {
	case "RS256":
		algorithm = jwt.SigningMethodRS256
	case "ES256":
		algorithm = jwt.SigningMethodES256
	default:
		return "", &kp.Error{
			Message:    "server_error",
			StatusCode: http.StatusInternalServerError,
			Err:        fmt.Errorf("unsupported algorithm: %s", signingKey.Algorithm),
		}
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
		return "", &kp.Error{
			Message:    "server_error",
			StatusCode: http.StatusInternalServerError,
			Err:        fmt.Errorf("missing exp in payload"),
		}
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
		return "", &kp.Error{
			Message:    "server_error",
			StatusCode: http.StatusInternalServerError,
			Err:        err,
		}
	}

	t, err := token.SignedString(privateKeyAny)
	if err != nil {
		return "", &kp.Error{
			Message:    "server_error",
			StatusCode: http.StatusInternalServerError,
			Err:        err,
		}
	}

	parts := strings.Split(t, ".")
	if len(parts) != 3 {
		return "", &kp.Error{
			Message:    "server_error",
			StatusCode: http.StatusInternalServerError,
			Err:        fmt.Errorf("invalid token format"),
		}
	}

	return t, nil
}

func (s *JWTService) GetKey(ctx context.Context, alg string) (SigningKey, error) {
	return s.repo.FindByAlgorithm(ctx, alg)
}

func (s *JWTService) GenerateJwtTokenWithAlg(ctx context.Context, payload map[string]any, alg string) (string, error) {
	signingKey, err := s.repo.FindByAlgorithm(ctx, alg)
	if err != nil {
		return "", &kp.Error{
			Message:    "server_error",
			StatusCode: http.StatusInternalServerError,
			Err:        err,
		}
	}
	// validate header
	var algorithm jwt.SigningMethod
	switch signingKey.Algorithm {
	case "RS256":
		algorithm = jwt.SigningMethodRS256
	case "ES256":
		algorithm = jwt.SigningMethodES256
	default:
		return "", &kp.Error{
			Message:    "server_error",
			StatusCode: http.StatusInternalServerError,
			Err:        fmt.Errorf("unsupported algorithm: %s", signingKey.Algorithm),
		}
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
		return "", &kp.Error{
			Message:    "server_error",
			StatusCode: http.StatusInternalServerError,
			Err:        fmt.Errorf("missing exp in payload"),
		}
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
		return "", &kp.Error{
			Message:    "server_error",
			StatusCode: http.StatusInternalServerError,
			Err:        err,
		}
	}

	t, err := token.SignedString(privateKeyAny)
	if err != nil {
		return "", &kp.Error{
			Message:    "server_error",
			StatusCode: http.StatusInternalServerError,
			Err:        err,
		}
	}

	parts := strings.Split(t, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid token format")
	}

	return t, nil
}

func (s *JWTService) ValidateJwksToken(ctx context.Context, signingKey SigningKey, tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}

		alg, ok := token.Header["alg"].(string)
		if !ok {
			return nil, fmt.Errorf("missing alg in token header")
		}

		if alg != string(signingKey.Algorithm) {
			return nil, fmt.Errorf("alg mismatch")
		}

		// signingKey, err := s.repo.FindByAlgorithm(ctx, alg)
		// if err != nil {
		// 	return nil, err
		// }
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
		return nil, &kp.Error{
			Message:    "server_error",
			StatusCode: http.StatusInternalServerError,
			Err:        err,
		}
	}
	if !token.Valid {
		return nil, &kp.Error{
			Message:    "invalid_grant",
			StatusCode: http.StatusUnauthorized,
			Err:        fmt.Errorf("invalid token"),
		}
	}
	return token, nil
}
func (s *JWTService) DecodeJwtToken(tokenString string) (header, payload map[string]any, err error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, nil, &kp.Error{
			Message:    "invalid_grant",
			StatusCode: http.StatusUnauthorized,
			Err:        fmt.Errorf("invalid token"),
		}
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, &kp.Error{
			Message:    "invalid_grant",
			StatusCode: http.StatusUnauthorized,
			Err:        fmt.Errorf("invalid token"),
		}
	}

	err = json.Unmarshal(headerBytes, &header)
	if err != nil {
		return nil, nil, &kp.Error{
			Message:    "server_error",
			StatusCode: http.StatusInternalServerError,
			Err:        err,
		}
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, &kp.Error{
			Message:    "server_error",
			StatusCode: http.StatusInternalServerError,
			Err:        err,
		}
	}

	payload = make(map[string]any)

	err = json.Unmarshal(payloadBytes, &payload)
	if err != nil {
		return nil, nil, &kp.Error{
			Message:    "server_error",
			StatusCode: http.StatusInternalServerError,
			Err:        err,
		}
	}

	return header, payload, nil
}

func (s *JWTService) GetKeyByKID(ctx context.Context, kid string) (SigningKey, error) {
	return s.repo.FindByKID(ctx, kid)
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
