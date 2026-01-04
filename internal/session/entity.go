package session

import "time"

// policy
type SessionCode struct {
	ID                  string `json:"id" bson:"_id,omitempty"`
	ClientID            string `json:"client_id" validate:"required" bson:"client_id"`
	RedirectURI         string `json:"redirect_uri" validate:"url" bson:"redirect_uri"`
	Scope               string `json:"scope,omitempty" bson:"scope"`
	State               string `json:"state,omitempty" bson:"state"`
	LoginHint           string `json:"login_hint,omitempty" bson:"login_hint,omitempty"`
	Nonce               string `json:"nonce,omitempty" bson:"nonce,omitempty"`
	CodeChallenge       string `json:"code_challenge,omitempty" bson:"code_challenge,omitempty"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty" bson:"code_challenge_method,omitempty"`
	Status              string `json:"status" bson:"status"`

	IDTokenAlg string `bson:"id_token_alg" json:"id_token_alg,omitempty"`

	CreatedAt time.Time `bson:"created_at" json:"-"`
	UpdatedAt time.Time `bson:"updated_at" json:"-"`
	ExpiresAt time.Time `bson:"expires_at" json:"-"`
}
