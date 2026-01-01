package client

import (
	"encoding/json"
	"net/http"
)

type ClientHandler struct {
	service *ClientService
}

func NewClientHandler(service *ClientService) *ClientHandler {
	return &ClientHandler{service: service}
}

func (h *ClientHandler) CreateClientHandler(w http.ResponseWriter, r *http.Request) {
	body := OIDCClient{}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	body.GenClientSecret()

	if err := body.ValidateClientType(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.service.CreateClient(r.Context(), &body); err != nil {
		http.Error(w, "failed to create client", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]any{
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
