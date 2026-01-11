package oauth

import (
	"encoding/base64"
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

	// parse query params
	authorizeRequest := AuthorizeRequest{}
	if err := ctx.BindQuery(&authorizeRequest); err != nil {
		ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_request"}, err)
		return
	}

	// check client existence
	clientModel, err := h.clientService.GetClientByID(ctx, authorizeRequest.ClientID)
	if err != nil {
		ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_client"}, err)
		return
	}
	if err := clientModel.ValidatePKCE(authorizeRequest.CodeChallenge, authorizeRequest.CodeChallengeMethod); err != nil {
		ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_request"}, err)
		return
	}

	if authorizeRequest.RedirectURI != "" {
		if !clientModel.ValidateRedirectURI(authorizeRequest.RedirectURI) {
			ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_redirect_uri"}, err)
			return
		}
	}

	if authorizeRequest.Request != "" {
		sessionCode, err := h.oauthService.GetSessionCodeByID(ctx, sessionId)
		if err != nil || sessionCode == nil {
			ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_session"}, err)
			return
		}

		if sessionCode.ClientID != authorizeRequest.ClientID {
			ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_request"}, err)
			return
		}

		if sessionCode.Status != "login" {
			ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_session_state"}, err)
			return
		}

		// decrypt request object
		data, err := h.oauthService.Decrypt(ctx, clientModel.IDTokenAlg, authorizeRequest.Request)
		if err != nil {
			ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_request_object"}, err)
			return
		}
		// split data to get sessionID, username, userID
		parts := strings.SplitN(data, "|", 3)
		if len(parts) != 3 {
			ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_request"}, err)
			return
		}
		reqSessionID := parts[0]
		if reqSessionID != sessionId {
			ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_session"}, err)
			return
		}
		username := parts[1]
		if username != sessionCode.LoginHint {
			ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_request"}, err)
			return
		}
		userID := parts[2]
		// findUserByID
		userModel, err := h.oauthService.userRepository.FindUserByUsername(ctx, username)
		if err != nil || userModel.ID != userID {
			ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_user"}, err)
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
			ctx.JSONError(http.StatusInternalServerError, map[string]string{"error": "server_error"}, err)
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
			ctx.JSONError(http.StatusInternalServerError, map[string]string{"error": "server_error"}, err)
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

	authorizeRequest := AuthorizeRequest{}
	if err := ctx.BindQuery(&authorizeRequest); err != nil {
		ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_request"}, err)
		return
	}

	sessionId := authorizeRequest.SessionID

	// check client existence

	var body LoginRequest
	if err := ctx.Bind(&body); err != nil {
		ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_request"}, err)
		return
	}

	sessionCode, err := h.oauthService.GetSessionCodeByID(ctx, sessionId)
	if err != nil {
		ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_session"}, err)
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

		ctx.JSONError(http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"}, err)
		return
	}

	ctx.Redirect(body.RedirectToAuthorize(h.cfg.BaseURL, map[string]string{"request": request}))
}

func (h *AuthHandler) RenderLoginPage(ctx *kp.Ctx) {
	ctx.L("render_register_page")

	authorizeRequest := AuthorizeRequest{}
	if err := ctx.BindQuery(&authorizeRequest); err != nil {
		ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_request"}, err)
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
	ctx.L("register")
	sessionId := ctx.SessionID()

	authorizeRequest := AuthorizeRequest{}
	if err := ctx.BindQuery(&authorizeRequest); err != nil {
		ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_request"}, err)
		return
	}

	// check client existence

	var body RegisterRequest
	if err := ctx.Bind(&body); err != nil {
		ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_request"}, err)
		return
	}

	sessionCode, err := h.oauthService.GetSessionCodeByID(ctx, sessionId)
	if err != nil {
		ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_session"}, err)
		return
	}

	body.Update(authorizeRequest.ClientID, authorizeRequest.RedirectURI, authorizeRequest.Scope, authorizeRequest.State)
	body.SessionID = sessionId

	// check user credentials here
	request, err := h.oauthService.RegisterUser(ctx, body, sessionCode.IDTokenAlg) // not_found go to register
	if err != nil {
		ctx.JSONError(http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"}, err)
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
	method := ctx.Req.Method
	cmd := "token"
	// validate method here
	// [get,post]
	if method != http.MethodGet && method != http.MethodPost {
		ctx.L(cmd)
		ctx.JSON(http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}

	// Implement token endpoint logic here
	var body TokenRequest
	switch method {
	case http.MethodPost:
		if err := ctx.Bind(&body); err != nil {
			ctx.L(cmd)
			ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_request"}, err)
			return
		}
	case http.MethodGet:
		if err := ctx.BindQuery(&body); err != nil {
			ctx.L(cmd)
			ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_request"}, err)
			return
		}
	default:
		ctx.L(cmd)
		ctx.JSONError(http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"}, nil)
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
				ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_authorization_header"}, err)
				return
			}
			credParts := strings.SplitN(string(decoded), ":", 2)
			if len(credParts) != 2 {
				ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_authorization_header"}, err)
				return
			}
			clientID := credParts[0]
			clientSecret := credParts[1]
			if body.ClientID != "" {
				if body.ClientID != clientID {
					ctx.L(cmd)
					ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_client"}, nil)
					return
				}
			} else {
				body.ClientID = clientID
			}
			if body.ClientSecret != "" {
				if body.ClientSecret != clientSecret {
					ctx.L(cmd)
					ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_client"}, nil)
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
			ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_grant"}, err)
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
			ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_grant"}, err)
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
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		// support method post
		if method != http.MethodPost {
			ctx.JSON(http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
			return
		}
		// implement token exchange flow here
	default:
		ctx.JSON(http.StatusNotImplemented, map[string]string{"error": "unsupported_grant_type"})
		return
	}
}
