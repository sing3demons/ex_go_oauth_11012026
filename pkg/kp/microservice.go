package kp

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sing3demons/oauth/kp/internal/config"
)

type MyHandler func(ctx *Ctx)
type HandleFunc func(http.Handler) http.Handler
type Middleware HandleFunc

type Microservice struct {
	config      *config.AppConfig
	mux         *http.ServeMux
	middlewares []Middleware
}
type IMicroservice interface {
	Start()
	// GET(path string, handler http.HandlerFunc, middlewares ...Middleware)
	GET(path string, handler MyHandler, middlewares ...Middleware)
	// POST(path string, handler http.HandlerFunc, middlewares ...Middleware)
	POST(path string, handler MyHandler, middlewares ...Middleware)
	// PUT(path string, handler http.HandlerFunc, middlewares ...Middleware)
	PUT(path string, handler MyHandler, middlewares ...Middleware)
	// DELETE(path string, handler http.HandlerFunc, middlewares ...Middleware)
	DELETE(path string, handler MyHandler, middlewares ...Middleware)
	// PATCH(path string, handler http.HandlerFunc, middlewares ...Middleware)
	PATCH(path string, handler MyHandler, middlewares ...Middleware)

	Use(middleware Middleware)
	// multiple methods (GET, POST, PUT, DELETE, PATCH)

}

func NewMicroservice(cfg *config.AppConfig) IMicroservice {
	return &Microservice{
		config: cfg,
		mux:    http.NewServeMux(),
	}
}

// func (m *Microservice) preHandle(final http.HandlerFunc, middlewares ...Middleware) http.HandlerFunc {
// 	for _, mw := range middlewares {
// 		fmt.Println("applying middleware")
// 		final = mw(final).ServeHTTP
// 	}
// 	return final
// }

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

//	func (m *Microservice) GET(path string, handler http.HandlerFunc, middlewares ...Middleware) {
//		m.mux.HandleFunc(fmt.Sprintf("%s %s", http.MethodGet, path), m.preHandle(handler, middlewares...))
//	}
// func (m *Microservice) Post(path string, handler http.HandlerFunc, middlewares ...Middleware) {
// 	m.mux.HandleFunc(fmt.Sprintf("%s %s", http.MethodPost, path), m.preHandle(handler, middlewares...))
// }
// func (m *Microservice) PUT(path string, handler http.HandlerFunc, middlewares ...Middleware) {
// 	m.mux.HandleFunc(fmt.Sprintf("%s %s", http.MethodPut, path), m.preHandle(handler, middlewares...))
// }
// func (m *Microservice) DELETE(path string, handler http.HandlerFunc, middlewares ...Middleware) {
// 	m.mux.HandleFunc(fmt.Sprintf("%s %s", http.MethodDelete, path), m.preHandle(handler, middlewares...))
// }
// func (m *Microservice) PATCH(path string, handler http.HandlerFunc, middlewares ...Middleware) {
// 	m.mux.HandleFunc(fmt.Sprintf("%s %s", http.MethodPatch, path), m.preHandle(handler, middlewares...))
// }

func (m *Microservice) Use(middleware Middleware) {
	m.middlewares = append(m.middlewares, middleware)
}

func (m *Microservice) preHandle(handler MyHandler, middlewares ...Middleware) http.HandlerFunc {
	// Wrap MyHandler into http.HandlerFunc
	final := func(w http.ResponseWriter, r *http.Request) {
		handler(newMuxContext(w, r, m.config))
	}
	// Apply middlewares in reverse order (so the first is outermost)
	for i := len(middlewares) - 1; i >= 0; i-- {
		final = middlewares[i](http.HandlerFunc(final)).ServeHTTP
	}
	return final
}

func (m *Microservice) GET(path string, handler MyHandler, middlewares ...Middleware) {
	m.mux.HandleFunc(fmt.Sprintf("%s %s", http.MethodGet, path), m.preHandle(handler, middlewares...))
}

func (m *Microservice) POST(path string, handler MyHandler, middlewares ...Middleware) {
	m.mux.HandleFunc(fmt.Sprintf("%s %s", http.MethodPost, path), m.preHandle(handler, middlewares...))
}

func (m *Microservice) PUT(path string, handler MyHandler, middlewares ...Middleware) {
	m.mux.HandleFunc(fmt.Sprintf("%s %s", http.MethodPut, path), m.preHandle(handler, middlewares...))
}

func (m *Microservice) DELETE(path string, handler MyHandler, middlewares ...Middleware) {
	m.mux.HandleFunc(fmt.Sprintf("%s %s", http.MethodDelete, path), m.preHandle(handler, middlewares...))
}

func (m *Microservice) PATCH(path string, handler MyHandler, middlewares ...Middleware) {
	m.mux.HandleFunc(fmt.Sprintf("%s %s", http.MethodPatch, path), m.preHandle(handler, middlewares...))
}

func (m *Microservice) Methods(methods, path string, handler MyHandler, middlewares ...Middleware) {
	for _, method := range []string{methods} {
		m.mux.HandleFunc(fmt.Sprintf("%s %s", strings.ToUpper(method), path), m.preHandle(handler, middlewares...))
	}
}
