package oauth

import (
	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/sing3demons/oauth/kp/internal/client"
	"github.com/sing3demons/oauth/kp/internal/config"
	"github.com/sing3demons/oauth/kp/pkg/mlog"
)

type AuthHandler struct {
	validate      *validator.Validate
	cfg           *config.AppConfig
	clientService *client.ClientService
}

func NewAuthHandler(cfg *config.AppConfig, clientService *client.ClientService) *AuthHandler {
	return &AuthHandler{
		validate:      validator.New(),
		cfg:           cfg,
		clientService: clientService,
	}
}

// authorize
func (h *AuthHandler) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	sessionId := r.Header.Get("x-session-id")

	// parse query params
	q := r.URL.Query()
	authorizeRequest := AuthorizeRequest{
		ResponseType:        q.Get("response_type"),
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		ResponseMode:        q.Get("response_mode"),
		LoginHint:           q.Get("login_hint"),
		Nonce:               q.Get("nonce"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		SessionID:           q.Get("sid"),
	}

	if sessionId == "" {
		sessionId = authorizeRequest.SessionID
	}
	response := mlog.NewResponseWithLogger(w, r, "authorize", sessionId)

	if err := h.validate.Struct(&authorizeRequest); err != nil {
		response.ResponseJsonError(http.StatusBadRequest, map[string]string{"error": "invalid_request"}, err)
		return
	}

	// check client existence
	clientModel, err := h.clientService.GetClientByID(r.Context(), authorizeRequest.ClientID)
	if err != nil {
		response.ResponseJsonError(http.StatusBadRequest, map[string]string{"error": "invalid_client"}, err)
		return
	}
	if err := clientModel.ValidatePKCE(authorizeRequest.CodeChallenge, authorizeRequest.CodeChallengeMethod); err != nil {
		response.ResponseJsonError(http.StatusBadRequest, map[string]string{"error": "invalid_request"}, err)
		return
	}

	if authorizeRequest.RedirectURI != "" {
		if !clientModel.ValidateRedirectURI(authorizeRequest.RedirectURI) {
			response.ResponseJsonError(http.StatusBadRequest, map[string]string{"error": "invalid_redirect_uri"}, err)
			return
		}
	}

	// cookies or session management can be added here
	ck, err := r.Cookie("session_id")
	if err == nil && ck.Value != "" && authorizeRequest.SessionID != "" {
		if ck.Value == authorizeRequest.SessionID {
			// user is logged in
		}
	}

	if authorizeRequest.LoginHint != "" {
	}

	// respond with redirect or json
	if authorizeRequest.IsRedirectURIPresent() {
		response.Redirect(authorizeRequest.RedirectURI)
	} else {
		response.ResponseJson(http.StatusOK, authorizeRequest)
	}
}
