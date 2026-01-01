package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/sing3demons/oauth/kp/config"
	"github.com/sing3demons/oauth/kp/internal/client"
	mongodb "github.com/sing3demons/oauth/kp/internal/database"
	"github.com/sing3demons/oauth/kp/internal/discover"
	"github.com/sing3demons/oauth/kp/internal/jwks"
	"github.com/sing3demons/oauth/kp/pkg/logger"
	"github.com/sing3demons/oauth/kp/pkg/mlog"
)

type Microservice struct {
	config      *config.AppConfig
	mux         *http.ServeMux
	middlewares []func(http.Handler) http.Handler
}
type IMicroservice interface {
	Start()
	GET(path string, handler http.HandlerFunc)
	POST(path string, handler http.HandlerFunc)
	PUT(path string, handler http.HandlerFunc)
	DELETE(path string, handler http.HandlerFunc)
	PATCH(path string, handler http.HandlerFunc)
	Use(middleware func(http.Handler) http.Handler)
}

func (m *Microservice) Start() {
	var handler http.Handler = m.mux
	for _, mw := range m.middlewares {
		handler = mw(handler)
	}
	srv := http.Server{
		Addr:         ":" + m.config.Port,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// wg
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		log.Printf("starting server on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && errors.Is(err, http.ErrServerClosed) {
			log.Printf("server listen err: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("server forced to shutdown: %v", err)
		os.Exit(1)
	}
	wg.Wait()
	log.Println("server exited")
}

func (m *Microservice) preHandle(final http.HandlerFunc) http.HandlerFunc {
	// for i := len(m.middlewares) - 1; i >= 0; i-- {
	// 	final = m.middlewares[i](final).ServeHTTP
	// }
	return final
}
func (m *Microservice) GET(path string, handler http.HandlerFunc) {
	m.mux.HandleFunc("GET "+path, m.preHandle(handler))
}
func (m *Microservice) POST(path string, handler http.HandlerFunc) {
	m.mux.HandleFunc("POST "+path, m.preHandle(handler))
}
func (m *Microservice) PUT(path string, handler http.HandlerFunc) {
	m.mux.HandleFunc("PUT "+path, m.preHandle(handler))
}
func (m *Microservice) DELETE(path string, handler http.HandlerFunc) {
	m.mux.HandleFunc("DELETE "+path, m.preHandle(handler))
}
func (m *Microservice) PATCH(path string, handler http.HandlerFunc) {
	m.mux.HandleFunc("PATCH "+path, m.preHandle(handler))
}

func (m *Microservice) Use(middleware func(http.Handler) http.Handler) {
	m.middlewares = append(m.middlewares, middleware)
}

type Middleware func(HandleFunc) HandleFunc
type HandleFunc func(http.Handler) http.Handler

func main() {
	godotenv.Load()
	cfg := config.NewConfigManager()
	cfg.LoadDefaults()

	app := &Microservice{
		config: cfg,
		mux:    http.NewServeMux(),
	}

	app.Use(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pCtx := r.Context()
			csLog := logger.NewLoggerWithConfig("auth-server", "1.0.0",
				&logger.LoggerConfig{
					Detail: logger.LogOutputConfig{
						Path:    "logs/detail",
						Console: true,
						File:    true,
					},
					Summary: logger.LogOutputConfig{
						Path:    "logs/summary",
						Console: true,
						File:    true,
					},
				})
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

	jwksRepository := jwks.NewSigningKeyRepository(db)
	jwksRepository.LoadActiveKeyByAlgorithm()
	jwksService := jwks.NewJWTService(cfg, jwksRepository)

	clientRepository := client.NewClientRepository(db)
	clientService := client.NewClientService(clientRepository)
	clientHandler := client.NewClientHandler(clientService)

	app.POST("/clients", clientHandler.CreateClientHandler)
	app.GET("/clients/{id}", clientHandler.GetClientHandler)

	app.GET("/test", func(w http.ResponseWriter, r *http.Request) {
		response := mlog.NewResponseWithLogger(w, r, uuid.NewString())
		payload := map[string]interface{}{
			"sub": "token_authentication_code",
			"aud": "client-id",
			"uid": "user-12345",
			"exp": time.Now().Add(1 * time.Hour).Unix(),
		}
		token, err := jwksService.GenerateJwtTokenWithAlg(context.Background(), payload, "RS256")
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
