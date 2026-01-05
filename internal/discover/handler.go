package discover

import (
	"net/http"

	"github.com/sing3demons/oauth/kp/internal/config"
	"github.com/sing3demons/oauth/kp/internal/jwks"
	"github.com/sing3demons/oauth/kp/pkg/kp"
)

type DiscoverHandler struct {
	cfg         *config.AppConfig
	jwksService *jwks.JWTService
}

func NewDiscoverHandler(cfg *config.AppConfig, jwksService *jwks.JWTService) *DiscoverHandler {
	return &DiscoverHandler{cfg: cfg, jwksService: jwksService}
}

func (h *DiscoverHandler) OIDCHandler(ctx *kp.Ctx) {
	ctx.L("discover")
	ctx.JSON(http.StatusOK, h.cfg.OidcConfig)
}

func (h *DiscoverHandler) JwksHandler(ctx *kp.Ctx) {
	// /.well-known/jwks.json
	ctx.L("get_jwks")
	// response := mlog.NewResponseWithLogger(w, r, "get_jwks", uuid.NewString())
	jwks, err := h.jwksService.GetJWKS(ctx)
	if err != nil {
		ctx.JSONError(http.StatusInternalServerError, map[string]string{
			"error": "server_error",
		}, err)
		return
	}

	ctx.JSON(http.StatusOK, jwks)
}
