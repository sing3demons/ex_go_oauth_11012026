package oauth

import (
	"errors"
	"net/url"
)

var (
	ErrInvalidCodeChallengeMethod = errors.New("invalid_code_challenge_method")
)

type AuthorizeRequest struct {
	ResponseType string `json:"response_type" validate:"required,oneof=code token id_token"`
	ClientID     string `json:"client_id" validate:"required"`
	RedirectURI  string `json:"redirect_uri" validate:"url"`
	Scope        string `json:"scope,omitempty"`
	State        string `json:"state,omitempty"`

	ResponseMode        string `json:"response_mode,omitempty" validate:"omitempty,oneof=query fragment form_post"`
	LoginHint           string `json:"login_hint,omitempty"`
	Nonce               string `json:"nonce,omitempty" validate:"required_if=response_type id_token"`
	CodeChallenge       string `json:"code_challenge,omitempty" validate:"omitempty,min=43,max=128,required_with=CodeChallengeMethod"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty" validate:"omitempty,oneof=plain S256,required_if=CodeChallenge"`

	SessionID string `json:"sid,omitempty"`
}

func (ar *AuthorizeRequest) IsPKCEEnabled() bool {
	return ar.CodeChallenge != "" && ar.CodeChallengeMethod != ""
}

func (ar *AuthorizeRequest) IsResponseTypeCode() bool {
	return ar.ResponseType == "code"
}

// RedirectURI
func (ar *AuthorizeRequest) IsRedirectURIPresent() bool {
	return ar.RedirectURI != ""
}

// Redirect set redirect uri
func (ar *AuthorizeRequest) BuildRedirectURI(key, value string) (string, error) {
	location, err := url.Parse(ar.RedirectURI)
	if err != nil {
		return "", err
	}
	query := location.Query()
	query.Set(key, value)
	if ar.State != "" {
		query.Set("state", ar.State)
	}
	location.RawQuery = query.Encode()
	return location.String(), nil
}

// pkce
func (ar *AuthorizeRequest) IsPKCERequired() bool {
	return ar.CodeChallenge != "" && ar.CodeChallengeMethod != ""
}

// pkce
func (ar *AuthorizeRequest) VerifyPKCE(verifier, method string) bool {
	if !ar.IsPKCERequired() {
		return true
	}
	if method != ar.CodeChallengeMethod {
		return false
	}
	if ar.CodeChallengeMethod == "plain" {
		return verifier == ar.CodeChallenge
	}
	return false
}

// pkce validator
func (ar *AuthorizeRequest) ValidatePKCE(method string) error {
	if !ar.IsPKCERequired() {
		return nil
	}

	if method != ar.CodeChallengeMethod {
		return ErrInvalidCodeChallengeMethod
	}

	if ar.CodeChallengeMethod == "" {
		return ErrInvalidCodeChallengeMethod
	}
	if ar.CodeChallengeMethod != "plain" && ar.CodeChallengeMethod != "S256" {
		return ErrInvalidCodeChallengeMethod
	}

	return nil
}

// encodeCodeVerifier
