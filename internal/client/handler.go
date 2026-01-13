package client

import (
	"errors"
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
	var customError *kp.Error

	body := OIDCClient{}

	if err := ctx.Bind(&body); err != nil {
		if !errors.As(err, &customError) {
			customError = &kp.Error{
				Message:    "invalid_request",
				StatusCode: http.StatusBadRequest,
				Err:        err,
			}
		}
		ctx.JSONError(customError)
		return
	}

	body.GenClientSecret()

	if err := body.ValidateClientType(); err != nil {
		if !errors.As(err, &customError) {
			customError = &kp.Error{
				Message:    "invalid_request",
				StatusCode: http.StatusBadRequest,
				Err:        err,
			}
		}
		ctx.JSONError(customError)
		return
	}

	if err := h.service.CreateClient(ctx, &body); err != nil {
		if !errors.As(err, &customError) {
			customError = &kp.Error{
				Message:    "internal_server",
				StatusCode: http.StatusInternalServerError,
				Err:        err,
			}
		}
		ctx.JSONError(customError)
		return
	}

	ctx.JSON(http.StatusOK, map[string]any{
		"message": "success",
		"data":    body,
	})
}

func (h *ClientHandler) GetClientHandler(ctx *kp.Ctx) {
	ctx.L("get_client")
	var customError *kp.Error
	id := ctx.Params("id")
	fmt.Println("Getting client with ID:", id)
	client, err := h.service.GetClientByID(ctx, id)
	if err != nil {
		// ctx.JSONError(http.StatusNotFound, "client_not_found", err)
		if !errors.As(err, &customError) {
			customError = &kp.Error{
				Message:    "internal_server",
				StatusCode: http.StatusNotFound,
				Err:        err,
			}
		}
		ctx.JSONError(customError)
		return
	}
	ctx.JSON(http.StatusOK, client)
}
