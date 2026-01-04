package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/sing3demons/oauth/kp/internal/jwks"
	"github.com/sing3demons/oauth/kp/internal/session"
	"github.com/sing3demons/oauth/kp/internal/user"
)

type OAuthService struct {
	sessionRepository    session.ISessionCodeRepository
	userRepository       user.IUserRepository
	signingKeyRepository jwks.ISigningKeyRepository
	authCodeRepository   IAuthorizationCodeRepository
}

func NewOAuthService(sessionRepository session.ISessionCodeRepository, userRepository user.IUserRepository, signingKeyRepository jwks.ISigningKeyRepository, authCodeRepository IAuthorizationCodeRepository) *OAuthService {
	return &OAuthService{
		sessionRepository:    sessionRepository,
		userRepository:       userRepository,
		signingKeyRepository: signingKeyRepository,
		authCodeRepository:   authCodeRepository,
	}
}

// Add OAuth related business logic methods here
func (s *OAuthService) CreateSessionCode(ctx context.Context, sid, method string, data AuthorizeRequest) error {
	return s.sessionRepository.Create(ctx, &session.SessionCode{
		ID:                  sid,
		ClientID:            data.ClientID,
		RedirectURI:         data.RedirectURI,
		Scope:               data.Scope,
		State:               data.State,
		LoginHint:           data.LoginHint,
		Nonce:               data.Nonce,
		CodeChallenge:       data.CodeChallenge,
		CodeChallengeMethod: data.CodeChallengeMethod,
		IDTokenAlg:          method,
	})
}

func (s *OAuthService) GetSessionCodeByID(ctx context.Context, id string) (*session.SessionCode, error) {
	return s.sessionRepository.FindByID(ctx, id)
}

func (s *OAuthService) UpdateSessionState(ctx context.Context, id string, state, login_hint string) error {
	return s.sessionRepository.UpdateState(ctx, id, state, login_hint)
}

func (s *OAuthService) Login(ctx context.Context, body LoginRequest, alg string) (string, error) {
	user, err := s.userRepository.FindUserByUsername(ctx, body.Username)
	if err != nil {
		return "", err
	}

	if err := body.CheckPasswordLogin(user.Password); err != nil {
		return "", err
	}

	if err := s.sessionRepository.UpdateState(ctx, body.SessionID, "login", body.Username); err != nil {
		return "", err
	}

	data, err := s.Encrypt(ctx, alg, fmt.Sprintf("%s|%s|%s", body.SessionID, body.Username, user.ID))
	if err != nil {
		return "", err
	}

	return data, nil
}

func (s *OAuthService) Encrypt(ctx context.Context, alg, data string) (string, error) {
	sk, err := s.signingKeyRepository.FindByAlgorithm(ctx, alg)
	if err != nil {
		return "", err
	}

	publicKeyPem := sk.PublicKey // sk.PublicKey is a string (PEM or base64 encoded)
	block, _ := pem.Decode([]byte(publicKeyPem))
	if block == nil {
		return "", fmt.Errorf("failed to parse PEM block containing the public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse DER encoded public key: %v", err)
	}
	publicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("invalid public key type")
	}

	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, []byte(data))
	if err != nil {
		return "", fmt.Errorf("encryption failed: %v", err)
	}

	// encode for safe transport via URL/query
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func (s *OAuthService) Decrypt(ctx context.Context, alg, cipherText string) (string, error) {
	sk, err := s.signingKeyRepository.FindByAlgorithm(ctx, alg)
	if err != nil {
		return "", err
	}

	privateKeyPem := sk.PrivateKey // sk.PrivateKey is a string (PEM or base64 encoded)
	block, _ := pem.Decode([]byte(privateKeyPem))
	if block == nil {
		return "", fmt.Errorf("failed to parse PEM block containing the private key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse DER encoded private key: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed: %v", err)
	}

	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, decoded)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %v", err)
	}

	return string(plaintext), nil
}

func (s *OAuthService) RegisterUser(ctx context.Context, body RegisterRequest, alg string) (string, error) {
	userModel, err := s.userRepository.FindUserByUsername(ctx, body.Username)
	if err != nil && err.Error() != "not_found" {
		return "", err
	}
	if userModel == nil {
		hashedPassword, err := body.HashPassword()
		if err != nil {
			return "", err
		}
		hashPin, err := body.HashPin()
		if err != nil {
			return "", err
		}

		insertUser := user.ProfileModel{
			Username: body.Username,
			Password: hashedPassword,
			Email:    body.Username,
			Pin:      hashPin,
		}

		if err := s.userRepository.CreateUser(ctx, &insertUser); err != nil {
			return "", err
		}

		if err := s.sessionRepository.UpdateState(ctx, body.SessionID, "register", body.Username); err != nil {
			return "", err
		}
	}

	loginRequest := LoginRequest{
		Username:  body.Username,
		Password:  body.Password,
		SessionID: body.SessionID,
	}

	loginRequest.Update(body.ClientID, body.RedirectURI, body.Scope, body.State)
	loginRequest.SessionID = body.SessionID

	return s.Login(ctx, loginRequest, alg)
}

func (s *OAuthService) GenerateAuthorizationCode(ctx context.Context, code *AuthCode) (string, error) {
	return s.authCodeRepository.InsertAuthorizationCode(ctx, code)
}
