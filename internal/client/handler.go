package client

import (
	"encoding/json"
	"net/http"

	"github.com/sing3demons/oauth/kp/pkg/kp"
)

type ClientHandler struct {
	service *ClientService
}

func NewClientHandler(service *ClientService) *ClientHandler {
	return &ClientHandler{service: service}
}

func (h *ClientHandler) CreateClientHandler(ctx *kp.Ctx) {
	ctx.L("create_client")

	body := OIDCClient{}

	if err := ctx.Bind(&body); err != nil {
		ctx.JSONError(http.StatusBadRequest, "invalid_request", err)
		return
	}

	body.GenClientSecret()

	if err := body.ValidateClientType(); err != nil {
		ctx.JSONError(http.StatusBadRequest, "invalid_request", err)
		return
	}

	if err := h.service.CreateClient(ctx.Context(), &body); err != nil {
		ctx.JSONError(http.StatusInternalServerError, "internal_server_error", err)
		return
	}

	ctx.JSON(http.StatusOK, map[string]any{
		"message": "success",
		"data":    body,
	})
}

func (h *ClientHandler) GetClientHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	client, err := h.service.GetClientByID(r.Context(), id)
	if err != nil {
		http.Error(w, "client not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(client)
}
