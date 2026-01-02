package token

import "time"

type AccessToken struct {
	AccessTokenId string `json:"access_token_id" bson:"access_token_id"` //jti
	AccessToken   string `json:"access_token" bson:"access_token"`
	ClientID      string `json:"client_id,omitempty"`

	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token,omitempty" bson:"refresh_token,omitempty"`
	IDToken      string    `json:"id_token,omitempty" bson:"id_token,omitempty"`
	CreatedAt    time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" bson:"updated_at"`
	ExpiresIn    int64     `json:"expires_in" bson:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at" bson:"expires_at"`
}
