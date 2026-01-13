package oauth

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/sing3demons/oauth/kp/internal/client"
	"github.com/sing3demons/oauth/kp/internal/config"
	"github.com/sing3demons/oauth/kp/pkg/kp"
	"github.com/sing3demons/oauth/kp/pkg/logger"
	"github.com/sing3demons/oauth/kp/pkg/validate"
)

type AuthHandler struct {
	cfg           *config.AppConfig
	clientService *client.ClientService
	oauthService  *OAuthService
}

func NewAuthHandler(cfg *config.AppConfig, clientService *client.ClientService, oauthService *OAuthService) *AuthHandler {
	return &AuthHandler{
		cfg:           cfg,
		clientService: clientService,
		oauthService:  oauthService,
	}
}

// authorize
func (h *AuthHandler) AuthorizeHandler(ctx *kp.Ctx) {
	ctx.L("authorize")
	sessionId := ctx.SessionID()
	var customError *kp.Error

	// parse query params
	authorizeRequest := AuthorizeRequest{}
	if err := ctx.BindQuery(&authorizeRequest); err != nil {
		if !errors.As(err, &customError) {
			customError = &kp.Error{
				Message:    "invalid_request",
				StatusCode: http.StatusBadRequest,
				Err:        err,
			}
		}
		ctx.JSONError(customError)
		return
	}

	// check client existence
	clientModel, err := h.clientService.GetClientByID(ctx, authorizeRequest.ClientID)
	if err != nil {
		if !errors.As(err, &customError) {
			customError = &kp.Error{
				Message:    "server_error",
				StatusCode: http.StatusInternalServerError,
				Err:        err,
			}
		}
		ctx.JSONError(customError)
		return
	}
	if err := clientModel.ValidatePKCE(authorizeRequest.CodeChallenge, authorizeRequest.CodeChallengeMethod); err != nil {
		if !errors.As(err, &customError) {
			customError = &kp.Error{
				Message:    "invalid_request",
				StatusCode: http.StatusBadRequest,
				Err:        err,
			}
		}
		ctx.JSONError(customError)
		return
	}

	if authorizeRequest.RedirectURI != "" {
		if !clientModel.ValidateRedirectURI(authorizeRequest.RedirectURI) {
			customError = &kp.Error{
				Message:    "invalid_request",
				StatusCode: http.StatusBadRequest,
				Err:        errors.New("redirect URI mismatch"),
			}

			ctx.JSONError(customError)
			return
		}
	}

	if authorizeRequest.Request != "" {
		sessionCode, err := h.oauthService.GetSessionCodeByID(ctx, sessionId)
		if err != nil || sessionCode == nil {
			if err != nil {
				if !errors.As(err, &customError) {
					customError = &kp.Error{
						Message:    "invalid_request",
						StatusCode: http.StatusBadRequest,
						Err:        err,
					}
				}
			} else {
				customError = &kp.Error{
					Message:    "invalid_request",
					StatusCode: http.StatusBadRequest,
					Err:        errors.New("session code not found"),
				}
			}
			ctx.JSONError(customError)
			return
		}

		if sessionCode.ClientID != authorizeRequest.ClientID {
			customError = &kp.Error{
				Message:    "invalid_request",
				StatusCode: http.StatusBadRequest,
				Err:        errors.New("client ID mismatch"),
			}
			ctx.JSONError(customError)
			return
		}

		if sessionCode.Status != "login" {
			customError = &kp.Error{
				Message:    "invalid_request",
				StatusCode: http.StatusBadRequest,
				Err:        err,
			}
			ctx.JSONError(customError)
			return
		}

		// decrypt request object
		data, err := h.oauthService.Decrypt(ctx, clientModel.IDTokenAlg, authorizeRequest.Request)
		if err != nil {
			if !errors.As(err, &customError) {
				customError = &kp.Error{
					Message:    "invalid_request",
					StatusCode: http.StatusBadRequest,
					Err:        err,
				}
			}
			ctx.JSONError(customError)
			return
		}
		// split data to get sessionID, username, userID
		parts := strings.SplitN(data, "|", 3)
		if len(parts) != 3 {
			customError = &kp.Error{
				Message:    "invalid_request",
				StatusCode: http.StatusBadRequest,
				Err:        errors.New("invalid request object format"),
			}
			ctx.JSONError(customError)
			return
		}
		reqSessionID := parts[0]
		if reqSessionID != sessionId {
			customError = &kp.Error{
				Message:    "invalid_request",
				StatusCode: http.StatusBadRequest,
				Err:        errors.New("session ID mismatch"),
			}
			ctx.JSONError(customError)
			return
		}
		username := parts[1]
		if username != sessionCode.LoginHint {
			customError = &kp.Error{
				Message:    "invalid_request",
				StatusCode: http.StatusBadRequest,
				Err:        errors.New("username mismatch"),
			}
			ctx.JSONError(customError)
			return
		}
		userID := parts[2]
		// findUserByID
		userModel, err := h.oauthService.userRepository.FindUserByUsername(ctx, username)
		if err != nil || userModel.ID != userID {
			if err != nil {
				if !errors.As(err, &customError) {
					customError = &kp.Error{
						Message:    "invalid_request",
						StatusCode: http.StatusBadRequest,
						Err:        err,
					}
				}
			} else {
				customError = &kp.Error{
					Message:    "invalid_request",
					StatusCode: http.StatusBadRequest,
					Err:        errors.New("user ID mismatch"),
				}
			}
			ctx.JSONError(customError)

			return
		}

		publicID := PublicID{
			Type:  "username",
			Value: username,
		}
		if validate.IsEmail(username) {
			publicID.Type = "email"
		}
		info := map[string]any{
			"username": userModel.Username,
			"email":    userModel.Email,
			"phone":    userModel.Phone,
		}

		// generate authorization code and redirect
		authCodeId, err := h.oauthService.GenerateAuthorizationCode(ctx, clientModel.IDTokenAlg, &AuthCode{
			ClientID:            sessionCode.ClientID,
			SessionID:           sessionId,
			TID:                 ctx.TransactionID(),
			UserID:              userID,
			RedirectURI:         authorizeRequest.RedirectURI,
			Scope:               authorizeRequest.Scope,
			Nonce:               authorizeRequest.Nonce,
			CodeChallenge:       sessionCode.CodeChallenge,
			CodeChallengeMethod: sessionCode.CodeChallengeMethod,
			PublicID:            publicID,
			Info:                info,
			ISS:                 h.cfg.OidcConfig.Issuer,
		})
		if err != nil {
			if !errors.As(err, &customError) {
				customError = &kp.Error{
					Message:    "invalid_request",
					StatusCode: http.StatusBadRequest,
					Err:        err,
				}
			}
			ctx.JSONError(customError)
			return
		}

		// build redirect URL
		redirectURL := authorizeRequest.RedirectURI
		if strings.Contains(redirectURL, "?") {
			redirectURL += "&"
		} else {
			redirectURL += "?"
		}
		redirectURL += "code=" + authCodeId
		if authorizeRequest.State != "" {
			redirectURL += "&state=" + authorizeRequest.State
		}

		ctx.Redirect(redirectURL)
		return
	}

	// cookies or session management can be added here
	ck, err := ctx.Req.Cookie("session_id")
	if err == nil && ck.Value != "" && authorizeRequest.SessionID != "" {
		if ck.Value == authorizeRequest.SessionID {
			// user is logged in
		}
	}

	if authorizeRequest.LoginHint != "" {
	}

	if err := h.oauthService.CreateSessionCode(ctx, sessionId, clientModel.IDTokenAlg, authorizeRequest); err != nil {
		if err.Error() != "duplicate" {
			if !errors.As(err, &customError) {
				customError = &kp.Error{
					Message:    "server_error",
					StatusCode: http.StatusInternalServerError,
					Err:        err,
				}
			}
			ctx.JSONError(customError)
			return
		}
	}

	ctx.Render("login", map[string]any{
		"SessionID":   sessionId,
		"ClientID":    authorizeRequest.ClientID,
		"State":       authorizeRequest.State,
		"RedirectURI": authorizeRequest.RedirectURI,
	})
}

func (h *AuthHandler) Login(ctx *kp.Ctx) {
	maskingRule := []logger.MaskingRule{
		{
			Field: "body.password",
			Type:  logger.MaskingTypeFull,
		},
		{
			Field: "body.pin",
			Type:  logger.MaskingTypeFull,
		},
		{
			Field: "body.username",
			Type:  logger.MaskingTypePartial,
		}, {
			Field: "body.email",
			Type:  logger.MaskingTypeEmail,
		},
	}
	ctx.L("login", maskingRule...)

	var customError *kp.Error

	authorizeRequest := AuthorizeRequest{}
	if err := ctx.BindQuery(&authorizeRequest); err != nil {
		if !errors.As(err, &customError) {
			customError = &kp.Error{
				Message:    "invalid_request",
				StatusCode: http.StatusBadRequest,
				Err:        err,
			}
		}
		ctx.JSONError(customError)
		return
	}

	sessionId := authorizeRequest.SessionID

	// check client existence

	var body LoginRequest
	if err := ctx.Bind(&body); err != nil {
		if !errors.As(err, &customError) {
			customError = &kp.Error{
				Message:    "invalid_request",
				StatusCode: http.StatusBadRequest,
				Err:        err,
			}
		}
		ctx.JSONError(customError)
		return
	}

	sessionCode, err := h.oauthService.GetSessionCodeByID(ctx, sessionId)
	if err != nil {
		if !errors.As(err, &customError) {
			customError = &kp.Error{
				Message:    "invalid_request",
				StatusCode: http.StatusBadRequest,
				Err:        err,
			}
		}
		ctx.JSONError(customError)
		return
	}

	body.Update(authorizeRequest.ClientID, authorizeRequest.RedirectURI, authorizeRequest.Scope, authorizeRequest.State)
	body.SessionID = sessionId

	// check user credentials here
	request, err := h.oauthService.Login(ctx, body, sessionCode.IDTokenAlg) // not_found go to register
	if err != nil {
		if err.Error() == "not_found" {
			// Send redirect to register page with all OAuth params
			registerURL := "/oauth/register?client_id=" + authorizeRequest.ClientID +
				"&state=" + authorizeRequest.State +
				"&redirect_uri=" + authorizeRequest.RedirectURI +
				"&sid=" + sessionId

			ctx.JSON(http.StatusOK, map[string]string{
				"redirect_uri": registerURL,
			})
			return
		}

		if !errors.As(err, &customError) {
			customError = &kp.Error{
				Message:    "invalid_credentials",
				StatusCode: http.StatusUnauthorized,
				Err:        err,
			}
		}
		ctx.JSONError(customError)
		return
	}

	ctx.Redirect(body.RedirectToAuthorize(h.cfg.BaseURL, map[string]string{"request": request}))
}

func (h *AuthHandler) RenderLoginPage(ctx *kp.Ctx) {
	ctx.L("render_register_page")
	var customError *kp.Error

	authorizeRequest := AuthorizeRequest{}
	if err := ctx.BindQuery(&authorizeRequest); err != nil {
		if !errors.As(err, &customError) {
			customError = &kp.Error{
				Message:    "invalid_request",
				StatusCode: http.StatusBadRequest,
				Err:        err,
			}
		}
		ctx.JSONError(customError)
		return
	}

	ctx.Render("register", map[string]any{
		"SessionID":   authorizeRequest.SessionID,
		"ClientID":    authorizeRequest.ClientID,
		"State":       authorizeRequest.State,
		"RedirectURI": authorizeRequest.RedirectURI,
	})
}

func (h *AuthHandler) Register(ctx *kp.Ctx) {
	var customError *kp.Error

	ctx.L("register")
	sessionId := ctx.SessionID()

	authorizeRequest := AuthorizeRequest{}
	if err := ctx.BindQuery(&authorizeRequest); err != nil {
		if !errors.As(err, &customError) {
			customError = &kp.Error{
				Message:    "invalid_request",
				StatusCode: http.StatusBadRequest,
				Err:        err,
			}
		}
		ctx.JSONError(customError)
		return
	}

	// check client existence

	var body RegisterRequest
	if err := ctx.Bind(&body); err != nil {
		if !errors.As(err, &customError) {
			customError = &kp.Error{
				Message:    "invalid_request",
				StatusCode: http.StatusBadRequest,
				Err:        err,
			}
		}
		ctx.JSONError(customError)
		return
	}

	sessionCode, err := h.oauthService.GetSessionCodeByID(ctx, sessionId)
	if err != nil {
		if !errors.As(err, &customError) {
			customError = &kp.Error{
				Message:    "invalid_request",
				StatusCode: http.StatusBadRequest,
				Err:        err,
			}
		}
		ctx.JSONError(customError)
		return
	}

	body.Update(authorizeRequest.ClientID, authorizeRequest.RedirectURI, authorizeRequest.Scope, authorizeRequest.State)
	body.SessionID = sessionId

	// check user credentials here
	request, err := h.oauthService.RegisterUser(ctx, body, sessionCode.IDTokenAlg) // not_found go to register
	if err != nil {
		if !errors.As(err, &customError) {
			customError = &kp.Error{
				Message:    "invalid_credentials",
				StatusCode: http.StatusUnauthorized,
				Err:        err,
			}
		}
		ctx.JSONError(customError)
		return
	}

	ctx.Redirect(body.RedirectToAuthorize(h.cfg.BaseURL, map[string]string{"request": request}))
}

type TokenRequest struct {
	GrantType    string `form:"grant_type" json:"grant_type" validate:"required"`
	Code         string `form:"code" json:"code"`
	RedirectURI  string `form:"redirect_uri" json:"redirect_uri"`
	ClientID     string `form:"client_id" json:"client_id" validate:"required"`
	CodeVerifier string `form:"code_verifier" json:"code_verifier"`
	State        string `form:"state" json:"state"`
	ClientSecret string `form:"client_secret" json:"client_secret"`
}

// Token endpoint handler can be added here
func (h *AuthHandler) TokenHandler(ctx *kp.Ctx) {
	var customError *kp.Error
	method := ctx.Req.Method
	cmd := "token"
	// validate method here
	// [get,post]
	if method != http.MethodGet && method != http.MethodPost {
		ctx.L(cmd)
		customError = &kp.Error{
			Message:    "invalid_request",
			StatusCode: http.StatusBadRequest,
			Err:        errors.New("invalid method"),
		}
		ctx.JSONError(customError)
		return
	}

	// Implement token endpoint logic here
	var body TokenRequest
	switch method {
	case http.MethodPost:
		if err := ctx.Bind(&body); err != nil {
			ctx.L(cmd)
			if !errors.As(err, &customError) {
				customError = &kp.Error{
					Message:    "invalid_request",
					StatusCode: http.StatusBadRequest,
					Err:        err,
				}
			}
			ctx.JSONError(customError)
			return
		}
	case http.MethodGet:
		if err := ctx.BindQuery(&body); err != nil {
			ctx.L(cmd)
			if !errors.As(err, &customError) {
				customError = &kp.Error{
					Message:    "invalid_request",
					StatusCode: http.StatusBadRequest,
					Err:        err,
				}
			}
			ctx.JSONError(customError)
			return
		}
	default:
		ctx.L(cmd)
		ctx.JSON(http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}

	switch body.GrantType {
	case "authorization_code":
		cmd = "token_authcode"
	case "refresh_token":
		cmd = "token_refresh"
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		cmd = "token_exchange"
	}

	// req.header.Authorization
	if authHeader := ctx.Req.Header.Get("Authorization"); authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.ToLower(parts[0]) == "basic" {
			decoded, err := base64.StdEncoding.DecodeString(parts[1])
			if err != nil {
				ctx.L(cmd)
				if !errors.As(err, &customError) {
					customError = &kp.Error{
						Message:    "invalid_request",
						StatusCode: http.StatusBadRequest,
						Err:        err,
					}
				}
				ctx.JSONError(customError)
				return
			}
			credParts := strings.SplitN(string(decoded), ":", 2)
			if len(credParts) != 2 {
				if !errors.As(err, &customError) {
					customError = &kp.Error{
						Message:    "invalid_request",
						StatusCode: http.StatusBadRequest,
						Err:        errors.New("invalid authorization header format"),
					}
				}
				ctx.JSONError(customError)
				return
			}
			clientID := credParts[0]
			clientSecret := credParts[1]
			if body.ClientID != "" {
				if body.ClientID != clientID {
					ctx.L(cmd)
					customError = &kp.Error{
						Message:    "invalid_client",
						StatusCode: http.StatusBadRequest,
						Err:        errors.New("client ID mismatch"),
					}
					ctx.JSONError(customError)
					return
				}
			} else {
				body.ClientID = clientID
			}
			if body.ClientSecret != "" {
				if body.ClientSecret != clientSecret {
					ctx.L(cmd)
					if !errors.As(err, &customError) {
						customError = &kp.Error{
							Message:    "invalid_client",
							StatusCode: http.StatusBadRequest,
							Err:        errors.New("client secret mismatch"),
						}
					}
					ctx.JSONError(customError)
					return
				}
			} else {
				body.ClientSecret = clientSecret
			}
		}
	}

	// grant_type = authorization_code
	// client_id,code, redirect_uri, code_verifier
	switch body.GrantType {
	case "authorization_code":
		// support method get post
		accessToken, refreshToken, idToken, err := h.oauthService.ExchangeAuthorizationCode(ctx, cmd, body)
		if err != nil {
			if !errors.As(err, &customError) {
				customError = &kp.Error{
					Message:    "invalid_grant",
					StatusCode: http.StatusBadRequest,
					Err:        err,
				}
			}
			ctx.JSONError(customError)
			return
		}

		data := map[string]any{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
			// "refresh_token": refreshToken,
			// "id_token":      idToken,
		}
		if refreshToken != "" {
			data["refresh_token"] = refreshToken
		}
		if idToken != "" {
			data["id_token"] = idToken
		}

		ctx.JSON(http.StatusOK, data)
		return
	case "refresh_token":
		// implement refresh token flow here
		accessToken, refreshToken, idToken, err := h.oauthService.RefreshToken(ctx, cmd, body)
		if err != nil {
			if !errors.As(err, &customError) {
				customError = &kp.Error{
					Message:    "invalid_grant",
					StatusCode: http.StatusBadRequest,
					Err:        err,
				}
			}
			ctx.JSONError(customError)
			return
		}

		data := map[string]any{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		if refreshToken != "" {
			data["refresh_token"] = refreshToken
		}
		if idToken != "" {
			data["id_token"] = idToken
		}

		ctx.JSON(http.StatusOK, data)
		return
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		// support method post
		if method != http.MethodPost {
			customError = &kp.Error{
				Message:    "method_not_allowed",
				StatusCode: http.StatusMethodNotAllowed,
				Err:        errors.New("not allowed method for token exchange"),
			}
			ctx.JSONError(customError)
			return
		}
		// implement token exchange flow here
	default:
		customError = &kp.Error{
			Message:    "unsupported_grant_type",
			StatusCode: http.StatusBadRequest,
			Err:        errors.New("grant type not supported"),
		}
		ctx.JSONError(customError)
		return
	}
}
