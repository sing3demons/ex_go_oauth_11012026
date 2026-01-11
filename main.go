package main

import (
	"log"
	"net/http"
	"time"

	"github.com/joho/godotenv"
	"github.com/sing3demons/oauth/kp/internal/client"
	"github.com/sing3demons/oauth/kp/internal/config"
	mongodb "github.com/sing3demons/oauth/kp/internal/database"
	"github.com/sing3demons/oauth/kp/internal/discover"
	"github.com/sing3demons/oauth/kp/internal/jwks"
	"github.com/sing3demons/oauth/kp/internal/oauth"
	"github.com/sing3demons/oauth/kp/internal/session"
	"github.com/sing3demons/oauth/kp/internal/token"
	"github.com/sing3demons/oauth/kp/internal/user"
	"github.com/sing3demons/oauth/kp/pkg/kp"
	"github.com/sing3demons/oauth/kp/pkg/logger"
)

func main() {
	godotenv.Load()
	cfg := config.NewConfigManager()
	cfg.LoadDefaults()

	// สร้าง parent logger แค่ครั้งเดียว
	parentLogger := logger.NewLoggerWithConfig(cfg.ServiceName, cfg.Version, &cfg.LoggerConfig)
	defer parentLogger.Close() // ปิด file writers ตอน shutdown

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

	clientRepository := client.NewClientRepository(db, redis)
	clientService := client.NewClientService(clientRepository)
	clientHandler := client.NewClientHandler(clientService)

	userRepository := user.NewUserRepository(db)
	oauthAuthCodeRepository := oauth.NewAuthorizationCodeRepository(db)
	sessionRepository := session.NewSessionCodeRepository(db)

	tokenRepository := token.NewMongoTokenRepository(db)

	oauthService := oauth.NewOAuthService(sessionRepository, userRepository, jwksRepository, oauthAuthCodeRepository, tokenRepository, jwksService, clientService)
	authHandler := oauth.NewAuthHandler(cfg, clientService, oauthService)

	app := kp.NewMicroservice(cfg, parentLogger)
	// Global panic recovery
	app.Use(kp.RecoverMiddleware)
	app.GET("/oauth/register", func(ctx *kp.Ctx) {
		ctx.L("render_register_page")

		authorizeRequest := oauth.AuthorizeRequest{}
		if err := ctx.BindQuery(&authorizeRequest); err != nil {
			ctx.JSONError(http.StatusBadRequest, map[string]string{"error": "invalid_request"}, err)
			return
		}

		ctx.Render("register", map[string]any{
			"SessionID":   authorizeRequest.SessionID,
			"ClientID":    authorizeRequest.ClientID,
			"State":       authorizeRequest.State,
			"RedirectURI": authorizeRequest.RedirectURI,
		})
	})

	app.GET("/oauth/authorize", authHandler.AuthorizeHandler)
	app.POST("/oauth/register", authHandler.Register)
	app.POST("/oauth/login", authHandler.Login)

	app.POST("/clients", clientHandler.CreateClientHandler)
	app.GET("/clients/{id}", clientHandler.GetClientHandler)
	discoverHandler := discover.NewDiscoverHandler(cfg, jwksService)
	app.GET("/.well-known/openid-configuration", discoverHandler.OIDCHandler)
	app.GET("/.well-known/jwks.json", discoverHandler.JwksHandler)

	// Token endpoint
	app.POST("/oauth/token", authHandler.TokenHandler)
	app.GET("/oauth/token", authHandler.TokenHandler)

	app.GET("/test", func(ctx *kp.Ctx) {
		ctx.L("test_handler")

		payload := map[string]interface{}{
			"sub": "token_authentication_code",
			"aud": "client-id",
			"uid": "user-12345",
			"exp": time.Now().Add(1 * time.Hour).Unix(),
		}
		token, err := jwksService.GenerateJwtTokenWithAlg(ctx.Context(), payload, "RS256")
		if err != nil {
			ctx.JSONError(http.StatusInternalServerError, "failed to generate token", err)
			return
		}

		ctx.JSON(http.StatusOK, map[string]interface{}{
			"token": token,
		}, logger.MaskingRule{
			Field: "body.token",
			Type:  logger.MaskingTypeFull,
		})
	})

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
