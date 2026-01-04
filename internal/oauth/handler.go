package oauth

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/sing3demons/oauth/kp/internal/client"
	"github.com/sing3demons/oauth/kp/internal/config"
	"github.com/sing3demons/oauth/kp/pkg/kp"
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
	// /oauth/authorize?response_type=code&client_id=cd4e7670-5e96-4a3f-addb-51fa43db86fc&redirect_uri=http://localhost/callback&scope=openid%20profile&state=xyz&code_challenge=abc&code_challenge_method=S256

	// parse query params
	authorizeRequest := AuthorizeRequest{}
	if err := ctx.BindQuery(&authorizeRequest); err != nil {
		ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_request"}, err)
		return
	}

	// check client existence
	clientModel, err := h.clientService.GetClientByID(ctx.Context(), authorizeRequest.ClientID)
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
		sessionCode, err := h.oauthService.GetSessionCodeByID(ctx.Context(), sessionId)
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
		data, err := h.oauthService.Decrypt(ctx.Context(), clientModel.TokenEndpointAuthMethod, authorizeRequest.Request)
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
		userModel, err := h.oauthService.userRepository.FindUserByUsername(ctx.Context(), username)
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
		authCodeId, err := h.oauthService.GenerateAuthorizationCode(ctx.Context(), &AuthCode{
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

	if err := h.oauthService.CreateSessionCode(ctx.Context(), sessionId, clientModel.IDTokenAlg, authorizeRequest); err != nil {
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
	ctx.L("login")

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

	sessionCode, err := h.oauthService.GetSessionCodeByID(ctx.Context(), sessionId)
	if err != nil {
		ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_session"}, err)
		return
	}

	body.Update(authorizeRequest.ClientID, authorizeRequest.RedirectURI, authorizeRequest.Scope, authorizeRequest.State)
	body.SessionID = sessionId

	// check user credentials here
	request, err := h.oauthService.Login(ctx.Context(), body, sessionCode.IDTokenAlg) // not_found go to register
	if err != nil {
		if err.Error() == "not_found" {
			// ctx.Render("register", map[string]any{
			// 	"SessionID":   sessionId,
			// 	"ClientID":    authorizeRequest.ClientID,
			// 	"State":       authorizeRequest.State,
			// 	"RedirectURI": authorizeRequest.RedirectURI,
			// })
			uri, err := url.Parse(ctx.Cfg.BaseURL)
			if err != nil {
				ctx.JSONError(http.StatusInternalServerError, map[string]string{"error": "server_error"}, err)
				return
			}
			uri.Path = "/oauth/register"
			q := uri.Query()
			q.Set("client_id", authorizeRequest.ClientID)
			q.Set("state", authorizeRequest.State)
			q.Set("redirect_uri", authorizeRequest.RedirectURI)
			uri.RawQuery = q.Encode()

			ctx.Redirect(uri.String())
			return
		}

		ctx.JSONError(http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"}, err)
		return
	}

	ctx.Redirect(body.RedirectToAuthorize(h.cfg.BaseURL, map[string]string{"request": request}))
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

	sessionCode, err := h.oauthService.GetSessionCodeByID(ctx.Context(), sessionId)
	if err != nil {
		ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_session"}, err)
		return
	}

	body.Update(authorizeRequest.ClientID, authorizeRequest.RedirectURI, authorizeRequest.Scope, authorizeRequest.State)

	// check user credentials here
	request, err := h.oauthService.RegisterUser(ctx.Context(), body, sessionCode.IDTokenAlg) // not_found go to register
	if err != nil {
		ctx.JSONError(http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"}, err)
		return
	}

	ctx.Redirect(body.RedirectToAuthorize(h.cfg.BaseURL, map[string]string{"request": request}))
}
