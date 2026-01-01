package discover

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/sing3demons/oauth/kp/internal/config"
	"github.com/sing3demons/oauth/kp/internal/jwks"
	"github.com/sing3demons/oauth/kp/pkg/mlog"
)

type DiscoverHandler struct {
	cfg         *config.AppConfig
	jwksService *jwks.JWTService
}

func NewDiscoverHandler(cfg *config.AppConfig, jwksService *jwks.JWTService) *DiscoverHandler {
	return &DiscoverHandler{cfg: cfg, jwksService: jwksService}
}

func (h *DiscoverHandler) OIDCHandler(w http.ResponseWriter, r *http.Request) {
	response := mlog.NewResponseWithLogger(w, r, "discover", uuid.NewString())
	response.ResponseJson(http.StatusOK, h.cfg.OidcConfig)
}

func (h *DiscoverHandler) JwksHandler(w http.ResponseWriter, r *http.Request) {
	// /.well-known/jwks.json
	response := mlog.NewResponseWithLogger(w, r, "get_jwks", uuid.NewString())
	jwks, err := h.jwksService.GetJWKS()
	if err != nil {
		response.ResponseJsonError(http.StatusInternalServerError, map[string]string{
			"error": "server_error",
		}, err)
		return
	}

	response.ResponseJson(http.StatusOK, jwks)
}
