package client

import (
	"fmt"
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

	if err := h.service.CreateClient(ctx, &body); err != nil {
		ctx.JSONError(http.StatusInternalServerError, "internal_server_error", err)
		return
	}

	ctx.JSON(http.StatusOK, map[string]any{
		"message": "success",
		"data":    body,
	})
}

func (h *ClientHandler) GetClientHandler(ctx *kp.Ctx) {
	ctx.L("get_client")
	id := ctx.Params("id")
	fmt.Println("Getting client with ID:", id)
	client, err := h.service.GetClientByID(ctx, id)
	if err != nil {
		ctx.JSONError(http.StatusNotFound, "client_not_found", err)
		return
	}
	ctx.JSON(http.StatusOK, client)
}
