package jwks

import "time"

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
