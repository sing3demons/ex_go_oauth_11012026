package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

func EncodeCodeVerifier(codeChallengeMethod, codeVerifier string) (string, error) {
	switch codeChallengeMethod {
	case "", "plain":
		// RFC: default = plain
		return codeVerifier, nil

	case "S256":
		sum := sha256.Sum256([]byte(codeVerifier))
		return base64.RawURLEncoding.EncodeToString(sum[:]), nil

	default:
		return "", fmt.Errorf("unsupported code_challenge_method: %s", codeChallengeMethod)
	}
}

func GenerateCodeVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
