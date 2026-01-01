package client

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/sing3demons/oauth/kp/pkg/mlog"
)

type ClientHandler struct {
	service *ClientService
}

func NewClientHandler(service *ClientService) *ClientHandler {
	return &ClientHandler{service: service}
}

func (h *ClientHandler) CreateClientHandler(w http.ResponseWriter, r *http.Request) {
	response := mlog.NewResponseWithLogger(w, r, uuid.NewString())
	body := OIDCClient{}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.ResponseJsonError(http.StatusBadRequest, map[string]string{"error": "invalid_request"}, err)
		return
	}

	body.GenClientSecret()

	if err := body.ValidateClientType(); err != nil {
		response.ResponseJsonError(http.StatusBadRequest, map[string]string{"error": "invalid_request"}, err)
		return
	}

	if err := h.service.CreateClient(r.Context(), &body); err != nil {
		response.ResponseJsonError(http.StatusInternalServerError, map[string]string{"error": "internal_server_error"}, err)
		return
	}

	response.ResponseJson(http.StatusOK, map[string]any{
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
