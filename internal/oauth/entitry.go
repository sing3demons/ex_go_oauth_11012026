package oauth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sing3demons/oauth/kp/pkg/validate"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCodeChallengeMethod = errors.New("invalid_code_challenge_method")
)

type AuthorizeRequest struct {
	ResponseType string `json:"response_type" validate:"omitempty,oneof=code token id_token"`
	ClientID     string `json:"client_id" validate:"required"`
	RedirectURI  string `json:"redirect_uri,omitempty" validate:"omitempty,url"`
	Scope        string `json:"scope,omitempty"`
	State        string `json:"state,omitempty"`

	ResponseMode        string `json:"response_mode,omitempty" validate:"omitempty,oneof=query fragment form_post"`
	LoginHint           string `json:"login_hint,omitempty"`
	Nonce               string `json:"nonce,omitempty" validate:"omitempty,required_if=response_type id_token"`
	CodeChallenge       string `json:"code_challenge,omitempty" validate:"omitempty,min=43,max=128,required_with=CodeChallengeMethod"`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty" validate:"omitempty,oneof=plain S256,required_if=CodeChallenge"`

	SessionID string `json:"sid,omitempty"`
	Request   string `json:"request,omitempty"`
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
type LoginRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required_without=Pin"`
	Pin      string `json:"pin" validate:"required_without=Password"`

	ClientID    string `json:"client_id,omitempty"`
	RedirectURI string `json:"redirect_uri,omitempty"`
	Scope       string `json:"scope,omitempty"`
	State       string `json:"state,omitempty"`
	SessionID   string `json:"sid,omitempty"`
}

func (lr *LoginRequest) IsEmail() bool {
	return validate.IsEmail(lr.Username)
}

func (lr *LoginRequest) Update(client_id, redirect_uri, scope, state string) LoginRequest {
	lr.ClientID = client_id
	lr.RedirectURI = redirect_uri
	lr.Scope = scope
	lr.State = state
	return *lr
}

func (lr *LoginRequest) CheckPasswordLogin(hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(lr.Password))
}

func (lr *LoginRequest) RedirectToAuthorize(baseURL string, data ...map[string]string) string {
	location, err := url.Parse(strings.TrimSuffix(baseURL, "/") + "/oauth/authorize")
	if err != nil {
		return ""
	}
	params := location.Query()
	params.Set("client_id", lr.ClientID)
	if lr.RedirectURI != "" {
		params.Set("redirect_uri", lr.RedirectURI)
	}
	if lr.Scope != "" {
		params.Set("scope", lr.Scope)
	}
	if lr.State != "" {
		params.Set("state", lr.State)
	}
	if lr.SessionID != "" {
		params.Set("sid", lr.SessionID)
	}
	if len(data) > 0 {
		for k, v := range data[0] {
			params.Set(k, v)
		}
	}

	location.RawQuery = params.Encode()
	raw := location.String()
	fmt.Println("RedirectToAuthorize:", raw)
	return raw
}

type RegisterRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"min=6"`
	Pin      string `json:"pin" validate:"required,len=6"`

	ClientID    string `json:"client_id,omitempty"`
	RedirectURI string `json:"redirect_uri,omitempty"`
	Scope       string `json:"scope,omitempty"`
	State       string `json:"state,omitempty"`
	SessionID   string `json:"sid,omitempty"`
}

func (lr *RegisterRequest) Update(client_id, redirect_uri, scope, state string) RegisterRequest {
	lr.ClientID = client_id
	lr.RedirectURI = redirect_uri
	lr.Scope = scope
	lr.State = state
	return *lr
}
func (lr *RegisterRequest) RedirectToAuthorize(baseURL string, data ...map[string]string) string {
	location, err := url.Parse(strings.TrimSuffix(baseURL, "/") + "/oauth/authorize")
	if err != nil {
		return ""
	}
	params := location.Query()
	params.Set("client_id", lr.ClientID)
	if lr.RedirectURI != "" {
		params.Set("redirect_uri", lr.RedirectURI)
	}
	if lr.Scope != "" {
		params.Set("scope", lr.Scope)
	}
	if lr.State != "" {
		params.Set("state", lr.State)
	}
	if lr.SessionID != "" {
		params.Set("sid", lr.SessionID)
	}
	if len(data) > 0 {
		for k, v := range data[0] {
			params.Set(k, v)
		}
	}

	location.RawQuery = params.Encode()
	raw := location.String()
	fmt.Println("RedirectToAuthorize:", raw)
	return raw
}

func (rr *RegisterRequest) HashPassword() (string, error) {
	if rr.Password == "" {
		return "", nil
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(rr.Password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}
func (rr *RegisterRequest) HashPin() (string, error) {
	if rr.Pin == "" {
		return "", nil
	}
	hashedPin, err := bcrypt.GenerateFromPassword([]byte(rr.Pin), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPin), nil
}

type PublicID struct {
	Type  string `json:"type" bson:"type" validate:"required,oneof=email username phone"`
	Value string `json:"value" bson:"value" validate:"required"`
}
type AuthCode struct {
	ClientID             string   `json:"client_id" bson:"client_id"`
	SessionID            string   `json:"x_session_id" bson:"x_session_id"`
	TID                  string   `json:"x_tid" bson:"x_tid"`
	UserID               string   `json:"uid" bson:"uid"`
	AccessTokenLifetime  int      `json:"accesstoken_lifetime,omitempty" bson:"accesstoken_lifetime,omitempty"`
	RefreshTokenLifetime int      `json:"refreshtoken_lifetime,omitempty" bson:"refreshtoken_lifetime,omitempty"`
	PublicID             PublicID `json:"public_id,omitempty" bson:"public_id,omitempty"`
	RedirectURI          string   `json:"redirect_uri,omitempty" bson:"redirect_uri,omitempty"`
	Scope                string   `json:"scope,omitempty" bson:"scope,omitempty"`
	Nonce                string   `json:"nonce,omitempty" bson:"nonce,omitempty"`

	CodeChallenge       string         `json:"code_challenge,omitempty" bson:"code_challenge,omitempty"`
	CodeChallengeMethod string         `json:"code_challenge_method,omitempty" bson:"code_challenge_method,omitempty"`
	Info                map[string]any `json:"info,omitempty" bson:"info,omitempty"`
}

type AuthorizationCode struct {
	ID         string `json:"id" bson:"_id,omitempty"`
	AuthCodeId string `json:"auth_code_id" bson:"auth_code_id"`
	Used       bool   `json:"used" bson:"used"`

	// Issue time.Time `bson:"iss" json:"-"` // baseURL
	AuthCode AuthCode `bson:"auth_code" json:"auth_code"`

	CreatedAt time.Time `bson:"created_at" json:"-"`
	ExpiresAt time.Time `bson:"expires_at,omitempty" json:"-"`
}

func (ac *AuthorizationCode) generateAuthCode() string {
	// generate random string 8 + uuid(36)
	id := generateRandomString(8) + ac.AuthCode.SessionID
	ac.ID = id
	ac.AuthCodeId = id
	return ac.ID
}

var (
	ErrInvalidAuthCodeID = fmt.Errorf("invalid authorization code ID")
)

func (ac *AuthorizationCode) CheckAuthCodeId() error {
	// check 44
	if len(ac.AuthCodeId) != 44 {
		return ErrInvalidAuthCodeID
	}

	// check uuid 36
	uuidPart := ac.AuthCodeId[8:]

	return uuid.Validate(uuidPart)

}

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func generateRandomString(length int) string {
	result := make([]byte, length)

	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			panic(err) // หรือ handle error ตาม style ของคุณ
		}
		result[i] = letters[n.Int64()]
	}

	return string(result)
}
