package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/sing3demons/oauth/kp/internal/client"
	"github.com/sing3demons/oauth/kp/internal/config"
	mongodb "github.com/sing3demons/oauth/kp/internal/database"
	"github.com/sing3demons/oauth/kp/internal/discover"
	"github.com/sing3demons/oauth/kp/internal/jwks"
	"github.com/sing3demons/oauth/kp/pkg/kp"
	"github.com/sing3demons/oauth/kp/pkg/logger"
	"github.com/sing3demons/oauth/kp/pkg/mlog"
)

func main() {
	godotenv.Load()
	cfg := config.NewConfigManager()
	cfg.LoadDefaults()

	app := kp.NewMicroservice(cfg)

	app.Use(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pCtx := r.Context()
			csLog := logger.NewLoggerWithConfig("auth-server", "1.0.0", &cfg.LoggerConfig)
			csLog.StartTransaction(uuid.NewString(), "")
			pCtx = context.WithValue(pCtx, "logger", csLog)
			r = r.WithContext(pCtx)
			h.ServeHTTP(w, r)
		})
	})

	db, err := mongodb.NewDatabase(cfg.DatabaseURL, "oauth_kp")
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer db.Close()

	redis, err := mongodb.NewRedisConfig(&cfg.RedisConfig)
	if err != nil {
		log.Fatalf("failed to connect to redis: %v", err)
	}
	defer redis.Close()

	jwksRepository := jwks.NewSigningKeyRepository(db, redis)
	jwksRepository.LoadActiveKeyByAlgorithm()
	jwksService := jwks.NewJWTService(cfg, jwksRepository)

	clientRepository := client.NewClientRepository(db)
	clientService := client.NewClientService(clientRepository)
	clientHandler := client.NewClientHandler(clientService)

	app.POST("/clients", clientHandler.CreateClientHandler)
	app.GET("/clients/{id}", clientHandler.GetClientHandler)

	app.GET("/test", func(w http.ResponseWriter, r *http.Request) {
		session := r.Header.Get("x-session-id")
		response := mlog.NewResponseWithLogger(w, r, session)
		payload := map[string]interface{}{
			"sub": "token_authentication_code",
			"aud": "client-id",
			"uid": "user-12345",
			"exp": time.Now().Add(1 * time.Hour).Unix(),
		}
		token, err := jwksService.GenerateJwtTokenWithAlg(r.Context(), payload, "RS256")
		if err != nil {
			http.Error(w, "failed to generate token", http.StatusInternalServerError)
			return
		}
		response.ResponseJson(http.StatusOK, map[string]interface{}{
			"token": token,
		}, logger.MaskingRule{
			Field: "body.token",
			Type:  logger.MaskingTypeFull,
		})

	})

	discoverHandler := discover.NewDiscoverHandler(cfg, jwksService)
	app.GET("/.well-known/openid-configuration", discoverHandler.OIDCHandler)
	app.GET("/.well-known/jwks.json", discoverHandler.JwksHandler)

	app.Start()
}

type AccessTokenClaims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	Scope     string `json:"scope"`
	JTI       string `json:"jti"`
	ClientID  string `json:"client_id,omitempty"`
}

type IDTokenClaims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	AuthTime  int64  `json:"auth_time,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
}
