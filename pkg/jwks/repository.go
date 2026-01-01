package jwks

import "time"

type ISigningKeyRepository interface {
	Find() ([]SigningKey, error)
	LoadActiveKeyByAlgorithm() ([]SigningKey, error)
	DeactivateKeyByKID(kid string) error
	CleanupOldInactiveKeys(olderThan time.Duration) error
}

type JWTAlgorithm string

const (
	JWTAlgorithmRS256    JWTAlgorithm = "RS256"
	JWTAlgorithmES256    JWTAlgorithm = "ES256"
	SigningKeyCollection              = "signing_keys"
)

type SigningKey struct {
	ID         string       `bson:"_id,omitempty"`
	KID        string       `bson:"kid"`
	Algorithm  JWTAlgorithm `bson:"algorithm"`
	PrivateKey string       `bson:"privateKey"`
	PublicKey  string       `bson:"publicKey"`
	Active     bool         `bson:"active"`
	CreatedAt  time.Time    `bson:"createdAt"`
	ExpiresAt  *time.Time   `bson:"expiresAt,omitempty"`
}
func IsValidAlgorithm(alg string) bool {
	switch JWTAlgorithm(alg) {
	case JWTAlgorithmRS256, JWTAlgorithmES256:
		return true
	default:
		return false
	}
}
func GetSupportedAlgorithms(alg []string) []JWTAlgorithm {
	var supported []JWTAlgorithm
	for _, a := range alg {
		if IsValidAlgorithm(a) {
			supported = append(supported, JWTAlgorithm(a))
		}
	}
	return supported
}