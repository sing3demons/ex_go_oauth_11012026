package kp

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sing3demons/oauth/kp/internal/config"
	"github.com/sing3demons/oauth/kp/pkg/logAction"
	"github.com/sing3demons/oauth/kp/pkg/logger"
)

const MaxBodySize = 10 << 20 // 10 MB
type ContentType string

const (
	ContentTypeJSON          ContentType = "application/json"
	ContentTypeXML           ContentType = "application/xml"
	ContentTypeForm          ContentType = "application/x-www-form-urlencoded"
	ContentTypeMultipartForm ContentType = "multipart/form-data"
	ContentTypePlainText     ContentType = "text/plain"
)

type CtxKey string

const (
	SessionID     CtxKey = "x-session-id"
	TransactionID CtxKey = "x-transaction-id"
	LoggerKey     CtxKey = "logger"
)

type Ctx struct {
	Res http.ResponseWriter
	Req *http.Request
	Cfg *config.AppConfig
	Log *logger.Logger
}

// NewTransactionID generates or retrieves a transaction ID with proper priority:
// 1. Existing context value (already set)
// 2. HTTP Header (x-transaction-id)
// 3. Query parameter (tid)
// 4. Generate new UUID
func (c *Ctx) TransactionID() string {
	// 1. Check if already set in context (highest priority)
	if ctxTID, ok := c.Req.Context().Value(TransactionID).(string); ok && ctxTID != "" {
		return ctxTID
	}

	// 2. Get from header and query
	headerTID := strings.TrimSpace(c.Req.Header.Get(string(TransactionID)))
	queryTID := strings.TrimSpace(c.Req.URL.Query().Get("tid"))

	var tid string

	// Validate if both are provided
	if headerTID != "" && queryTID != "" {
		if headerTID != queryTID {
			tid = fmt.Sprintf("%s:%s", headerTID, queryTID)
		} else {
			tid = headerTID // Both are same
		}
	} else if headerTID != "" {
		tid = headerTID // Only header
	} else if queryTID != "" {
		tid = queryTID // Only query
	}

	// 3. Generate new if none provided
	if tid == "" {
		tid = uuid.NewString()
	}

	// 4. Store in context and logger
	c.Req = c.Req.WithContext(context.WithValue(c.Req.Context(), TransactionID, tid))
	c.Log.SetTransactionID(tid)

	return tid
}

// NewSessionID generates or retrieves a session ID with proper priority
func (c *Ctx) SessionID() string {
	// 1. Check context first
	if ctxSID, ok := c.Req.Context().Value(SessionID).(string); ok && ctxSID != "" {
		return ctxSID
	}

	// 2. Get from header and query
	headerSID := strings.TrimSpace(c.Req.Header.Get(string(SessionID)))
	querySID := strings.TrimSpace(c.Req.URL.Query().Get("sid"))

	var sid string

	// Validate if both are provided
	if headerSID != "" && querySID != "" {
		if headerSID != querySID {
			sid = fmt.Sprintf("%s:%s", headerSID, querySID)
		} else {
			sid = headerSID
		}
	} else if headerSID != "" {
		sid = headerSID
	} else if querySID != "" {
		sid = querySID
	}

	// 3. Generate new if none provided
	if sid == "" {
		sid = uuid.NewString()
	}

	// 4. Store in context and logger
	c.Req = c.Req.WithContext(context.WithValue(c.Req.Context(), SessionID, sid))
	c.Log.SetSessionID(sid)

	return sid
}
func (c *Ctx) genTransactionID() string {
	tid, ok := c.Req.Context().Value(TransactionID).(string)
	if !ok || tid == "" {
		tid = uuid.NewString()
	}
	c.Req = c.Req.WithContext(context.WithValue(c.Req.Context(), TransactionID, tid))
	c.Log.SetTransactionID(tid)
	return tid
}

func newMuxContext(w http.ResponseWriter, r *http.Request, cfg *config.AppConfig) *Ctx {
	start := time.Now()

	pCtx := r.Context()
	csLog := logger.NewLoggerWithConfig(cfg.ServiceName, cfg.Version, &cfg.LoggerConfig)
	pCtx = context.WithValue(pCtx, LoggerKey, csLog)
	r = r.WithContext(pCtx)

	myCtx := &Ctx{
		Res: w,
		Req: r,
		Cfg: cfg,
		Log: logger.NewLogger(cfg.ServiceName, cfg.Version),
	}
	myCtx.genTransactionID()

	defer func() {
		fmt.Println("defer recover")
		if rec := recover(); rec != nil {
			// default
			status := http.StatusInternalServerError
			msg := "internal_server_error"

			// convert panic → error
			var err error
			switch v := rec.(type) {
			case error:
				err = v
			default:
				err = fmt.Errorf("%v", v)
			}

			// log panic
			csLog.Error(
				logAction.EXCEPTION("panic recovered"),
				map[string]any{
					"method":   r.Method,
					"path":     r.URL.Path,
					"panic":    err.Error(),
					"duration": time.Since(start).Milliseconds(),
					"stack":    string(debug.Stack()),
				},
			)

			// response
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(map[string]any{
				"error": msg,
			})
			csLog.FlushError(status, msg)
		}
	}()

	return myCtx
}
func (c *Ctx) Context() context.Context {
	if c.Req == nil {
		return context.Background()
	}

	return c.Req.Context()
}
func (c *Ctx) Params(name string) string {
	return c.Req.PathValue(name)
}
func (c *Ctx) Query(name string) string {
	return c.Req.URL.Query().Get(name)
}
func (c *Ctx) Bind(v any) error {
	// Only parse body for non-GET requests
	if c.Req.Method == http.MethodGet || c.Req.Method == http.MethodHead {
		return nil
	}

	// Get Content-Type header
	contentType := c.Req.Header.Get("Content-Type")
	if contentType == "" {
		// Default to JSON if not specified
		contentType = string(ContentTypeJSON)
	}

	// Extract base content type (remove charset, boundary, etc.)
	baseContentType := strings.Split(contentType, ";")[0]
	baseContentType = strings.TrimSpace(baseContentType)

	// Limit body size to prevent DoS
	limitedReader := io.LimitReader(c.Req.Body, MaxBodySize)
	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}

	// Check if body exceeded limit
	if int64(len(bodyBytes)) >= MaxBodySize {
		return fmt.Errorf("request body too large (max %d bytes)", MaxBodySize)
	}

	// Restore body for potential re-reads (e.g., logging middleware)
	c.Req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Parse based on content type
	switch ContentType(baseContentType) {
	case ContentTypeJSON:
		return c.parseJSON(bodyBytes, v)

	case ContentTypeXML:
		return c.parseXML(bodyBytes, v)

	case ContentTypeForm:
		return c.parseFormURLEncoded(bodyBytes, v)

	case ContentTypeMultipartForm:
		return c.parseMultipartForm(v)

	case ContentTypePlainText:
		return c.parsePlainText(bodyBytes, v)

	default:
		return fmt.Errorf("unsupported content type: %s", contentType)
	}
}

func (c *Ctx) L(userCase string, masking ...logger.MaskingRule) *logger.Logger {
	c.Log.SetUseCase(userCase)
	c.SessionID()
	body := make(map[string]any)
	c.Bind(&body)

	headers := c.Headers()
	params := c.ParamsMap()
	queries := c.QueryString()

	c.Log.Info(logAction.INBOUND(fmt.Sprintf("client %s %s server", c.Req.Method, c.Req.URL.String())), map[string]any{
		"method":  c.Req.Method,
		"url":     c.Req.URL.String(),
		"headers": headers,
		"query":   queries,
		"body":    body,
		"params":  params,
		"remote":  c.Req.RemoteAddr,
	}, masking...)
	return c.Log
}
func (c *Ctx) Headers() map[string]string {
	headers := make(map[string]string)
	for key, values := range c.Req.Header {
		if len(values) > 0 {
			headers[key] = strings.Join(values, ", ")
		} else {
			headers[key] = ""
		}
	}
	return headers
}
func (c *Ctx) ParamsMap() map[string]string {
	params := make(map[string]string)

	// pattern := r.PathPattern() // "/users/{id}/orders/{orderId}"
	// Since http.Request does not have PathPattern, set pattern to r.URL.Path or another available value
	pattern := c.Req.URL.Path
	re := regexp.MustCompile(`\{(\w+)\}`)
	matches := re.FindAllStringSubmatch(pattern, -1)

	// PathValue is also not available on *http.Request, so this section is commented out or needs to be replaced with custom logic if needed
	for _, m := range matches {
		key := m[1]
		params[key] = c.Req.PathValue(key)
	}
	return params
}
func (c *Ctx) QueryString() map[string]string {
	queries := make(map[string]string)
	for key, values := range c.Req.URL.Query() {
		if len(values) > 0 {
			queries[key] = values[0]
		} else {
			queries[key] = ""
		}
	}
	return queries
}

func (c *Ctx) JSON(code int, v any, masking ...logger.MaskingRule) {
	c.Res.Header().Set("Content-Type", "application/json")
	c.Res.Header().Set("x-session-id", c.Log.SessionID())
	c.Res.WriteHeader(code)
	json.NewEncoder(c.Res).Encode(v)

	c.Log.Info(logAction.OUTBOUND("server response to client"), map[string]any{
		"status":  code,
		"headers": c.Res.Header(),
		"body":    v,
	}, masking...)

	c.Log.Flush(code, c.statusMessage(code))
}
func (c *Ctx) Redirect(urlStr string) {
	fullUrl := urlStr
	location, err := url.Parse(urlStr)
	if err == nil {
		q := location.Query()
		q.Add("sid", c.Log.SessionID())
		location.RawQuery = q.Encode()
		fullUrl = location.String()
	}
	http.Redirect(c.Res, c.Req, fullUrl, http.StatusFound)
	c.Log.Info(logAction.OUTBOUND("server redirect to client"), map[string]any{
		"status":  http.StatusFound,
		"headers": c.Res.Header(),
		"url":     fullUrl,
	})

	msg := fmt.Sprintf("redirect to %s", urlStr)
	c.Log.Flush(http.StatusFound, msg)
}

func (c *Ctx) JSONError(code int, v any, err error) {
	c.Res.Header().Set("Content-Type", "application/json")
	c.Res.Header().Set("x-session-id", c.Log.SessionID())
	c.Res.WriteHeader(code)
	json.NewEncoder(c.Res).Encode(v)

	c.Log.Info(logAction.OUTBOUND("server response to client"), map[string]any{
		"status":  code,
		"headers": c.Res.Header(),
		"body":    v,
	})
	c.Log.AddMetadata("ErrorCode", err.Error())
	c.Log.FlushError(code, c.statusMessage(code))
}
func (c *Ctx) statusMessage(code int) string {
	msg := http.StatusText(code)
	if msg == "" {
		return "unknown_status"
	}
	return strings.ToLower(strings.ReplaceAll(msg, " ", "_"))
}

// parseJSON parses JSON content
func (c *Ctx) parseJSON(bodyBytes []byte, v any) error {
	if len(bodyBytes) == 0 {
		return fmt.Errorf("empty JSON body")
	}

	if err := json.Unmarshal(bodyBytes, v); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}
	return nil
}

// parseXML parses XML content
func (c *Ctx) parseXML(bodyBytes []byte, v any) error {
	if len(bodyBytes) == 0 {
		return fmt.Errorf("empty XML body")
	}

	if err := xml.Unmarshal(bodyBytes, v); err != nil {
		return fmt.Errorf("failed to unmarshal XML: %w", err)
	}
	return nil
}

// parseFormURLEncoded parses application/x-www-form-urlencoded content
func (c *Ctx) parseFormURLEncoded(bodyBytes []byte, v any) error {
	if len(bodyBytes) == 0 {
		return fmt.Errorf("empty form body")
	}

	values, err := url.ParseQuery(string(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to parse form data: %w", err)
	}

	// Convert url.Values to the target type
	// If v is map[string]string or map[string][]string
	switch target := v.(type) {
	case *map[string]string:
		result := make(map[string]string)
		for key, vals := range values {
			if len(vals) > 0 {
				result[key] = vals[0]
			}
		}
		*target = result

	case *map[string][]string:
		*target = values

	case *map[string]any:
		result := make(map[string]any)
		for key, vals := range values {
			if len(vals) == 1 {
				result[key] = vals[0]
			} else {
				result[key] = vals
			}
		}
		*target = result

	default:
		// Try to convert to JSON first, then unmarshal
		jsonData, err := json.Marshal(values)
		if err != nil {
			return fmt.Errorf("failed to convert form data: %w", err)
		}
		if err := json.Unmarshal(jsonData, v); err != nil {
			return fmt.Errorf("failed to unmarshal form data to struct: %w", err)
		}
	}

	return nil
}

// parseMultipartForm parses multipart/form-data content
func (c *Ctx) parseMultipartForm(v any) error {
	// Parse multipart form (max 32MB in memory)
	if err := c.Req.ParseMultipartForm(32 << 20); err != nil {
		return fmt.Errorf("failed to parse multipart form: %w", err)
	}

	switch target := v.(type) {
	case *map[string]string:
		result := make(map[string]string)
		for key, vals := range c.Req.MultipartForm.Value {
			if len(vals) > 0 {
				result[key] = vals[0]
			}
		}
		*target = result

	case *map[string][]string:
		*target = c.Req.MultipartForm.Value

	case *map[string]any:
		result := make(map[string]any)
		// Add form values
		for key, vals := range c.Req.MultipartForm.Value {
			if len(vals) == 1 {
				result[key] = vals[0]
			} else {
				result[key] = vals
			}
		}
		// Add file info
		if c.Req.MultipartForm.File != nil {
			files := make(map[string]any)
			for key, fileHeaders := range c.Req.MultipartForm.File {
				if len(fileHeaders) == 1 {
					files[key] = map[string]any{
						"filename": fileHeaders[0].Filename,
						"size":     fileHeaders[0].Size,
						"header":   fileHeaders[0].Header,
					}
				} else {
					fileList := make([]map[string]any, len(fileHeaders))
					for i, fh := range fileHeaders {
						fileList[i] = map[string]any{
							"filename": fh.Filename,
							"size":     fh.Size,
							"header":   fh.Header,
						}
					}
					files[key] = fileList
				}
			}
			result["_files"] = files
		}
		*target = result

	default:
		return fmt.Errorf("unsupported type for multipart form data")
	}

	return nil
}

// parsePlainText parses plain text content
func (c *Ctx) parsePlainText(bodyBytes []byte, v any) error {
	switch target := v.(type) {
	case *string:
		*target = string(bodyBytes)
	case *[]byte:
		*target = bodyBytes
	default:
		return fmt.Errorf("plain text can only be parsed into *string or *[]byte")
	}
	return nil
}

// GetFile retrieves a file from multipart form
func (c *Ctx) GetFile(name string) (*multipart.FileHeader, error) {
	if c.Req.MultipartForm == nil {
		if err := c.Req.ParseMultipartForm(32 << 20); err != nil {
			return nil, fmt.Errorf("failed to parse multipart form: %w", err)
		}
	}

	files := c.Req.MultipartForm.File[name]
	if len(files) == 0 {
		return nil, fmt.Errorf("file %s not found", name)
	}

	return files[0], nil
}

// GetFiles retrieves all files from multipart form with the given name
func (c *Ctx) GetFiles(name string) ([]*multipart.FileHeader, error) {
	if c.Req.MultipartForm == nil {
		if err := c.Req.ParseMultipartForm(32 << 20); err != nil {
			return nil, fmt.Errorf("failed to parse multipart form: %w", err)
		}
	}

	files := c.Req.MultipartForm.File[name]
	if len(files) == 0 {
		return nil, fmt.Errorf("files %s not found", name)
	}

	return files, nil
}

func XMicroservice(cfg *config.AppConfig) *Microservice {
	return &Microservice{
		config: cfg,
		mux:    http.NewServeMux(),
	}
}
func (m *Microservice) Run() {
	srv := &http.Server{
		Addr:    ":" + m.config.Port,
		Handler: m.mux,
	}

	fmt.Printf("Starting server on port %s\n", m.config.Port)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}

}

type MyHandler func(ctx *Ctx)

func (m *Microservice) Get(path string, handler MyHandler) {
	m.mux.HandleFunc(fmt.Sprintf("%s %s", http.MethodGet, path), func(w http.ResponseWriter, r *http.Request) {
		ctx := newMuxContext(w, r, m.config)
		handler(ctx)
	})
}
