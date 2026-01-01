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

	"github.com/sing3demons/oauth/kp/internal/config"
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
func NewMicroservice(cfg *config.AppConfig) IMicroservice {
	return &Microservice{
		config: cfg,
		mux:    http.NewServeMux(),
	}
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
