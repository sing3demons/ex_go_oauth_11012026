package discover

import (
	"encoding/json"
	"net/http"

	"github.com/sing3demons/oauth/kp/config"
	"github.com/sing3demons/oauth/kp/internal/jwks"
)

type DiscoverHandler struct {
	cfg         *config.AppConfig
	jwksService *jwks.JWTService
}

func NewDiscoverHandler(cfg *config.AppConfig, jwksService *jwks.JWTService) *DiscoverHandler {
	return &DiscoverHandler{cfg: cfg, jwksService: jwksService}
}

func (h *DiscoverHandler) OIDCHandler(w http.ResponseWriter, r *http.Request) {
	data := h.cfg.OidcConfig
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (h *DiscoverHandler) JwksHandler(w http.ResponseWriter, r *http.Request) {
	// /.well-known/jwks.json
	jwks, err := h.jwksService.GetJWKS()
	if err != nil {
		http.Error(w, "failed to get JWKS", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}
