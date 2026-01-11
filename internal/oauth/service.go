package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sing3demons/oauth/kp/internal/client"
	"github.com/sing3demons/oauth/kp/internal/jwks"
	"github.com/sing3demons/oauth/kp/internal/session"
	"github.com/sing3demons/oauth/kp/internal/token"
	"github.com/sing3demons/oauth/kp/internal/user"
)

type OAuthService struct {
	sessionRepository    session.ISessionCodeRepository
	userRepository       user.IUserRepository
	signingKeyRepository jwks.ISigningKeyRepository
	authCodeRepository   IAuthorizationCodeRepository
	tokenRepository      token.ITokenRepository
	jwksService          *jwks.JWTService
	clientService        *client.ClientService
}

func NewOAuthService(sessionRepository session.ISessionCodeRepository, userRepository user.IUserRepository, signingKeyRepository jwks.ISigningKeyRepository, authCodeRepository IAuthorizationCodeRepository, tokenRepository token.ITokenRepository, jwksService *jwks.JWTService, clientService *client.ClientService) *OAuthService {
	return &OAuthService{
		sessionRepository:    sessionRepository,
		userRepository:       userRepository,
		signingKeyRepository: signingKeyRepository,
		authCodeRepository:   authCodeRepository,
		tokenRepository:      tokenRepository,
		jwksService:          jwksService,
		clientService:        clientService,
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

func (s *OAuthService) GenerateAuthorizationCode(ctx context.Context, idTokenAlg string, code *AuthCode) (string, error) {
	return s.authCodeRepository.InsertAuthorizationCode(ctx, idTokenAlg, code)
}

func (s *OAuthService) ValidateAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error) {
	return s.authCodeRepository.FindAuthorizationCodeByID(ctx, code)
}

// grant_type=authorization_code
func (s *OAuthService) ExchangeAuthorizationCode(ctx context.Context, body TokenRequest) (accessToken string, refreshToken string, idToken string, err error) {
	clientModel, err := s.clientService.ValidateClientToken(ctx, body.ClientID, body.ClientSecret, body.CodeVerifier)
	if err != nil {
		return "", "", "", err
	}

	// check if grant_type is allowed
	GRANT_TYPE_ALLOWED := slices.Contains(clientModel.GrantTypes, body.GrantType)
	if !GRANT_TYPE_ALLOWED {
		return "", "", "", fmt.Errorf("unauthorized_client: grant_type not allowed")
	}

	authCode, err := s.authCodeRepository.FindAuthorizationCodeByID(ctx, body.Code)
	if err != nil {
		return "", "", "", err
	}

	if body.ClientID != authCode.AuthCode.ClientID {
		return "", "", "", fmt.Errorf("invalid_client")
	}

	if authCode.Used {
		return "", "", "", fmt.Errorf("authorization code already used")
	}

	if authCode.ExpiresAt.Before(time.Now()) {
		return "", "", "", fmt.Errorf("authorization code expired")
	}

	if authCode.AuthCode.ClientID != body.ClientID {
		return "", "", "", fmt.Errorf("client ID mismatch")
	}

	if authCode.AuthCode.RedirectURI != body.RedirectURI {
		return "", "", "", fmt.Errorf("redirect URI mismatch")
	}

	signingKey, err := s.jwksService.GetKey(ctx, authCode.IDTokenAlg)
	if err != nil {
		return "", "", "", err
	}

	issuer := authCode.AuthCode.ISS // Replace with your actual issuer URL
	currentTime := time.Now()
	if authCode.AuthCode.Info != nil {
		idTokenPayload := map[string]any{
			"iss":   issuer,
			"sub":   authCode.AuthCode.UserID,
			"aud":   authCode.AuthCode.ClientID,
			"exp":   currentTime.Add(1 * time.Hour).Unix(),
			"iat":   currentTime.Unix(),
			"nonce": authCode.AuthCode.Nonce,
			"info":  authCode.AuthCode.Info,
			"uid":   authCode.AuthCode.UserID,
		}

		idToken, err = s.jwksService.GenerateJwtToken(signingKey, idTokenPayload)
		if err != nil {
			return "", "", "", err
		}
	}

	accessTokenExp := currentTime.Add(1 * time.Hour)
	accessTokenId := GenerateJti(authCode.AuthCode.SessionID)

	accessTokenPayload := map[string]any{
		"iss":       issuer,
		"jti":       accessTokenId,
		"sub":       "token_authentication_code",
		"aud":       authCode.AuthCode.ClientID,
		"exp":       accessTokenExp.Unix(),
		"iat":       time.Now().Unix(),
		"scope":     authCode.AuthCode.Scope,
		"client_id": authCode.AuthCode.ClientID,
	}

	accessToken, err = s.jwksService.GenerateJwtToken(signingKey, accessTokenPayload)
	if err != nil {
		return "", "", "", err
	}

	refreshTokenId := GenerateJti(authCode.AuthCode.SessionID)

	accessTokenRecord := &token.AccessToken{
		AccessTokenId:  accessTokenId,
		AccessToken:    accessToken,
		ClientID:       authCode.AuthCode.ClientID,
		UserID:         authCode.AuthCode.UserID,
		TokenType:      "Bearer",
		ExpiresAt:      accessTokenExp,
		ExpiresIn:      accessTokenExp.Unix(),
		IDToken:        idToken,
		RefreshTokenId: refreshTokenId,
	}

	refreshTokenPayload := map[string]any{
		"iss":       issuer,
		"jti":       refreshTokenId,
		"sub":       accessTokenPayload["sub"],
		"aud":       authCode.AuthCode.ClientID,
		"exp":       currentTime.Add(24 * time.Hour).Unix(),
		"iat":       currentTime.Unix(),
		"scope":     authCode.AuthCode.Scope,
		"client_id": authCode.AuthCode.ClientID,
	}
	refreshToken, err = s.jwksService.GenerateJwtToken(signingKey, refreshTokenPayload)
	if err != nil {
		return "", "", "", err
	}

	refreshTokenRecord := &token.RefreshToken{
		RefreshTokenId: refreshTokenId,
		RefreshToken:   refreshToken,

		AccessTokenId: accessTokenId,
		AccessToken:   accessToken,

		IDToken:  idToken,
		ClientID: authCode.AuthCode.ClientID,

		UserID:    authCode.AuthCode.UserID,
		ExpiresAt: currentTime.Add(24 * time.Hour),
		ExpiresIn: currentTime.Add(24 * time.Hour).Unix(),
	}

	// Mark the authorization code as used
	if err := s.authCodeRepository.MarkAuthorizationCodeAsUsed(ctx, body.Code); err != nil {
		return "", "", "", err
	}

	s.sessionRepository.DeleteByID(ctx, authCode.AuthCode.SessionID)

	if err := s.tokenRepository.UpsertTokens(ctx, accessTokenRecord, refreshTokenRecord); err != nil {
		return "", "", "", err
	}

	return accessToken, refreshToken, idToken, nil
}

func (s *OAuthService) RefreshToken(ctx context.Context, body TokenRequest) (accessToken string, refreshToken string, idToken string, err error) {
	// Implement refresh token logic here
	// validate the refresh token, generate new access token and refresh token
	if body.Code == "" {
		return "", "", "", fmt.Errorf("refresh_token is required")
	}
	id := body.Code
	kid := ""

	refreshTokenPayload := map[string]any{}
	if s.IsJwtToken(body.Code) {
		header, claims, err := s.jwksService.DecodeJwtToken(body.Code)
		if err != nil {
			return "", "", "", err
		}
		jti, ok := claims["jti"].(string)
		if !ok {
			return "", "", "", fmt.Errorf("invalid refresh token")
		}

		kid, ok = header["kid"].(string)
		if !ok {
			return "", "", "", fmt.Errorf("invalid refresh token header")
		}
		id = jti
		maps.Copy(refreshTokenPayload, claims)
	}

	currentTime := time.Now()
	expirationTime := currentTime.Add(1 * time.Hour).Unix()
	refreshTokenModel, err := s.tokenRepository.GetRefreshTokenById(ctx, id)
	if err != nil {
		return "", "", "", err
	}

	if refreshTokenModel.ClientID != body.ClientID {
		return "", "", "", fmt.Errorf("client ID mismatch")
	}

	if refreshTokenModel.ExpiresAt.Before(currentTime) {
		return "", "", "", fmt.Errorf("refresh token expired")
	}

	signingKey, err := s.jwksService.GetKeyByKID(ctx, kid)
	if err != nil {
		return "", "", "", err
	}

	_, err = s.jwksService.ValidateJwksToken(ctx, signingKey, body.Code)
	if err != nil {
		return "", "", "", err
	}

	clientModel, err := s.clientService.GetClientByID(ctx, body.ClientID)
	if err != nil {
		return "", "", "", err
	}
	if clientModel.ClientID != body.ClientID {
		return "", "", "", fmt.Errorf("invalid client credentials")
	}

	if refreshTokenModel.AccessToken != "" {
		_, claims, err := s.jwksService.DecodeJwtToken(refreshTokenModel.AccessToken)
		if err != nil {
			return "", "", "", err
		}
		claims["exp"] = expirationTime
		claims["iat"] = currentTime.Unix()
		accessToken, err = s.jwksService.GenerateJwtToken(signingKey, claims)
		if err != nil {
			return "", "", "", err
		}
	}

	if refreshTokenModel.IDToken != "" {
		_, claims, err := s.jwksService.DecodeJwtToken(refreshTokenModel.IDToken)
		if err != nil {
			return "", "", "", err
		}
		claims["exp"] = expirationTime
		claims["iat"] = currentTime.Unix()
		idToken, err = s.jwksService.GenerateJwtToken(signingKey, claims)
		if err != nil {
			return "", "", "", err
		}
	}

	newRefreshTokenId := uuid.NewString() + generateRandomString(8)
	refreshTokenPayload["jti"] = newRefreshTokenId
	refreshTokenPayload["exp"] = currentTime.Add(24 * time.Hour).Unix()
	refreshTokenPayload["iat"] = currentTime.Unix()
	refreshTokenPayload["sub"] = refreshTokenPayload["sub"]
	refreshToken, err = s.jwksService.GenerateJwtToken(signingKey, refreshTokenPayload)
	if err != nil {
		return "", "", "", err
	}

	accessTokenRecord := &token.AccessToken{
		AccessTokenId:  refreshTokenModel.AccessTokenId,
		AccessToken:    accessToken,
		ClientID:       refreshTokenModel.ClientID,
		UserID:         refreshTokenModel.UserID,
		TokenType:      "Bearer",
		ExpiresAt:      time.Unix(expirationTime, 0),
		ExpiresIn:      expirationTime,
		IDToken:        idToken,
		RefreshTokenId: newRefreshTokenId,
	}

	refreshTokenRecord := &token.RefreshToken{
		RefreshTokenId: newRefreshTokenId,
		RefreshToken:   refreshToken,

		AccessTokenId: accessTokenRecord.AccessTokenId,
		AccessToken:   accessToken,

		IDToken:  idToken,
		ClientID: refreshTokenModel.ClientID,

		UserID:    refreshTokenModel.UserID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		ExpiresIn: time.Now().Add(24 * time.Hour).Unix(),
	}

	s.tokenRepository.DeleteTokens(ctx, id)

	if err := s.tokenRepository.UpsertTokens(ctx, accessTokenRecord, refreshTokenRecord); err != nil {
		return "", "", "", err
	}

	return accessToken, refreshToken, idToken, nil
}

// jwt format xxx.yyy.zzz
func (s *OAuthService) IsJwtToken(token string) bool {
	parts := len(splitToken(token))
	return parts == 3
}
func (s *OAuthService) IsJwe(token string) bool {
	parts := len(splitToken(token))
	return parts == 5
}
func splitToken(token string) []string {
	return strings.Split(token, ".")
}

func (s *OAuthService) ValidateAccessToken(ctx context.Context, tokenString string) (map[string]any, error) {
	if !s.IsJwtToken(tokenString) {
		return nil, fmt.Errorf("invalid access token format")
	}

	result := map[string]any{}

	header, claims, err := s.jwksService.DecodeJwtToken(tokenString)
	if err != nil {
		return nil, err
	}

	kid, ok := header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid token header")
	}

	signingKey, err := s.jwksService.GetKeyByKID(ctx, kid)
	if err != nil {
		return nil, err
	}

	_, err = s.jwksService.ValidateJwksToken(ctx, signingKey, tokenString)
	if err != nil {
		return nil, err
	}
	// maps.Copy(result, claims)

	if exp, ok := claims["exp"].(float64); ok {
		if int64(exp) < time.Now().Unix() {
			return nil, fmt.Errorf("access token expired")
		}
	}

	return result, nil
}
