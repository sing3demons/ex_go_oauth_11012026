package client

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/sing3demons/oauth/kp/pkg/pkce"
)

type OIDCClient struct {
	ClientID string `json:"client_id" bson:"client_id"`

	ClientName string `json:"client_name" bson:"app_name"`
	ClientType string `json:"client_type" bson:"client_type"`

	Status string `json:"status,omitempty" bson:"status,omitempty"`

	RedirectUris []string `json:"redirect_uris" bson:"redirect_uris"`
	GrantTypes   []string `json:"grant_types" bson:"grant_types"`
	Scopes       []string `json:"scopes,omitempty" bson:"scopes,omitempty"`

	ClientSecret            string    `bson:"client_secret" json:"client_secret,omitempty"`
	TokenEndpointAuthMethod string    `bson:"token_endpoint_auth_method" json:"token_endpoint_auth_method,omitempty"`
	RequirePKCE             bool      `bson:"require_pkce" json:"require_pkce,omitempty"`
	PKCECodeChallengeMethod string    `bson:"pkce_code_challenge_method" json:"pkce_code_challenge_method,omitempty"`
	IDTokenAlg              string    `bson:"id_token_alg" json:"id_token_alg"`
	SubjectType             string    `bson:"subject_type" json:"-"`
	AccessTokenTTL          int       `bson:"access_token_ttl" json:"-"`
	RefreshTokenTTL         int       `bson:"refresh_token_ttl" json:"-"`
	IDTokenTTL              int       `bson:"id_token_ttl" json:"-"`
	CreatedAt               time.Time `bson:"created_at" json:"-"`
}

var (
	ErrInvalidCodeChallengeMethod = errors.New("invalid_code_challenge_method")
)

func (c *OIDCClient) ValidatePKCE(codeChallenge, method string) error {
	if !c.RequirePKCE {
		return nil
	}

	if codeChallenge == "" {
		return ErrInvalidCodeChallengeMethod
	}

	if method != c.PKCECodeChallengeMethod {
		return ErrInvalidCodeChallengeMethod
	}

	if c.PKCECodeChallengeMethod == "" {
		return ErrInvalidCodeChallengeMethod
	}
	if c.PKCECodeChallengeMethod != "plain" && c.PKCECodeChallengeMethod != "S256" {
		return ErrInvalidCodeChallengeMethod
	}

	return nil
}
func (c *OIDCClient) IDTokenAlgOrDefault() string {
	if c.IDTokenAlg != "" {
		return c.IDTokenAlg
	}
	c.IDTokenAlg = "RS256"
	return c.IDTokenAlg
}
func (c *OIDCClient) DefaultsTTL() {
	if c.AccessTokenTTL == 0 {
		c.AccessTokenTTL = 3600 // 1 hour
	}
	if c.RefreshTokenTTL == 0 {
		c.RefreshTokenTTL = 7200 // 2 hours
	}
	if c.IDTokenTTL == 0 {
		c.IDTokenTTL = 3600 // 1 hour
	}
}

func (c *OIDCClient) IsPublic() bool {
	return c.ClientType == "public"
}

func (c *OIDCClient) GenClientSecret() bool {
	if c.ClientType == "confidential" {
		b := make([]byte, 32) // 256-bit
		if _, err := rand.Read(b); err != nil {
			return false
		}

		c.ClientSecret = base64.RawURLEncoding.EncodeToString(b)
		return true
	}
	return false
}

func (c *OIDCClient) ValidateClientType() error {
	switch c.ClientType {
	case "public":
		if c.TokenEndpointAuthMethod != "none" {
			return errors.New("public client must not use client authentication")
		}
		if !c.RequirePKCE {
			return errors.New("public client must require PKCE")
		}
	case "confidential":
		if c.TokenEndpointAuthMethod == "none" {
			return errors.New("confidential client must authenticate")
		}
	default:
		return errors.New("invalid client_type")
	}
	return nil
}

func (c *OIDCClient) ValidateRedirectURI(uri string) bool {
	for _, ruri := range c.RedirectUris {
		if ruri == uri {
			return true
		}
	}
	return false
}

func (c *OIDCClient) ValidateToken(clientSecret, codeVerifier string) error {
	if clientSecret == "" && codeVerifier == "" {
		return errors.New("either client_secret or code_verifier must be provided")
	}

	if clientSecret != "" {
		if c.ClientSecret != clientSecret {
			return errors.New("invalid client secret")
		}
	}
	// pkce
	if codeVerifier != "" {
		if !c.RequirePKCE {
			return errors.New("pkce not required for this client")
		}
		// no code challenge method stored in client, cannot verify
		if c.PKCECodeChallengeMethod == "" {
			return errors.New("pkce code challenge method not set for this client")
		}
		// verify code verifier

		pkced, err := pkce.EncodeCodeVerifier(c.PKCECodeChallengeMethod, codeVerifier)
		if err != nil {
			return err
		}
		// compare
		if pkced != codeVerifier {
			return errors.New("invalid code verifier")
		}
	}

	return nil
}
