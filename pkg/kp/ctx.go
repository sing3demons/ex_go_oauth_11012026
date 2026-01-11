package kp

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"io"
	"maps"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
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
)

type Ctx struct {
	Res      http.ResponseWriter
	Req      *http.Request
	Cfg      *config.AppConfig
	Log      logger.ILogger
	validate *validator.Validate
}

type ICtx interface {
	context.Context

	TransactionID() string
	SessionID() string
	SetSessionID(sid string)

	Params(name string) string
	Query(name string) string
	Bind(v any) error
	BindQuery(v any) error

	L(userCase string, masking ...logger.MaskingRule) logger.ILogger

	Headers() map[string]string
	ParamsMap() map[string]string
	QueryString() map[string]string

	JSON(code int, v any, masking ...logger.MaskingRule)
	Redirect(urlStr string)
	RedirectWithError(rawURL string, code int, v any, err error)
	Render(path string, data map[string]any)
	JSONError(code int, v any, err error)

	GetFile(name string) (*multipart.FileHeader, error)
	GetFiles(name string) ([]*multipart.FileHeader, error)
}

// context.Context interface methods
func (c *Ctx) Done() <-chan struct{} {
	return c.Context().Done()
}
func (c *Ctx) Err() error {
	return c.Context().Err()
}
func (c *Ctx) Deadline() (time.Time, bool) {
	return c.Context().Deadline()
}
func (c *Ctx) Value(key any) any {
	return c.Context().Value(key)
}

//

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
func (c *Ctx) SetSessionID(sid string) {
	c.Req = c.Req.WithContext(context.WithValue(c.Req.Context(), SessionID, sid))
	c.Log.SetSessionID(sid)
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

func newMuxContext(w http.ResponseWriter, r *http.Request, cfg *config.AppConfig, csLog logger.ILogger) ICtx {
	start := time.Now()
	myCtx := &Ctx{
		Res:      w,
		Req:      r,
		Cfg:      cfg,
		Log:      csLog.Clone(),
		validate: validator.New(),
	}
	myCtx.genTransactionID()

	defer func() {
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
		ctx := context.Background()
		return ctx
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
func (c *Ctx) checkStructValidation(v any) error {
	ptrVal := reflect.ValueOf(v)
	if ptrVal.Kind() != reflect.Ptr || ptrVal.IsNil() {
		return nil
	}

	if ptrVal.Elem().Kind() == reflect.Struct {
		// Convert url.Values to map[string]string (pick first value)
		jsonData, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("failed to convert query params: %w", err)
		}
		if err := json.Unmarshal(jsonData, v); err != nil {
			return fmt.Errorf("failed to unmarshal query params to struct: %w", err)
		}

		// Validate struct
		if c.validate == nil {
			c.validate = validator.New()
		}
		return c.validate.Struct(v)
	}

	return nil
}
func (c *Ctx) BindQuery(v any) error {
	values := c.Req.URL.Query()
	ptrVal := reflect.ValueOf(v)

	if ptrVal.Kind() != reflect.Ptr || ptrVal.IsNil() {
		return fmt.Errorf("BindQuery requires a non-nil pointer")
	}

	if ptrVal.Kind() == reflect.Map && ptrVal.Type().Key().Kind() == reflect.String {
		return setFormMap(v, values)
	}

	// For struct types, convert query values to struct
	if ptrVal.Elem().Kind() == reflect.Struct {
		// Convert url.Values to map[string]string (pick first value)
		data := make(map[string]string)
		for key, vals := range values {
			if len(vals) > 0 {
				data[key] = vals[0]
			}
		}

		jsonData, err := json.Marshal(data)
		if err != nil {
			return fmt.Errorf("failed to convert query params: %w", err)
		}
		if err := json.Unmarshal(jsonData, v); err != nil {
			return fmt.Errorf("failed to unmarshal query params to struct: %w", err)
		}

		// Validate struct
		if c.validate == nil {
			c.validate = validator.New()
		}
		err = c.validate.Struct(v)
		if err != nil {
			fmt.Println("BindQuery validation error:", err.Error())
		}
		return err
	}

	return nil
}

func (c *Ctx) L(userCase string, masking ...logger.MaskingRule) logger.ILogger {
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
	http.Redirect(c.Res, c.Req, urlStr, http.StatusFound)
	c.Log.Info(logAction.OUTBOUND("server redirect to client"), map[string]any{
		"status":  http.StatusFound,
		"headers": c.Res.Header(),
		"url":     urlStr,
	})

	msg := fmt.Sprintf("redirect to %s", urlStr)
	c.Log.Flush(http.StatusFound, msg)
}

func (c *Ctx) RedirectWithError(rawURL string, code int, v any, err error) {
	c.Res.Header().Set("x-session-id", c.Log.SessionID())

	location, pErr := url.Parse(rawURL)
	if pErr != nil {
		c.Res.Header().Set("Content-Type", "application/json")
		c.Res.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(c.Res).Encode(map[string]any{
			"error": err.Error(),
		})
		c.Log.Error(logAction.OUTBOUND("server render to client"), map[string]any{
			"status":  http.StatusInternalServerError,
			"headers": c.Res.Header(),
			"error":   err.Error(),
		})
		c.Log.FlushError(http.StatusInternalServerError, pErr.Error())
		return
	}
	query := location.Query()
	dataMap, ok := v.(map[string]string)
	if ok {
		for key, value := range dataMap {
			if key == "error" {
				query.Set(key, value)
			}
		}
		location.RawQuery = query.Encode()
	}

	http.Redirect(c.Res, c.Req, location.String(), http.StatusFound)
	c.Log.Error(logAction.OUTBOUND("server render to client"), map[string]any{
		"status":  http.StatusInternalServerError,
		"headers": c.Res.Header(),
		"body":    v,
	})
	c.Log.FlushError(http.StatusInternalServerError, "redirect to "+location.String())

}

func (c *Ctx) Render(path string, data map[string]any) {
	c.Res.Header().Set("x-session-id", c.Log.SessionID())
	c.Res.Header().Set("Content-Type", "text/html; charset=utf-8")
	// check if file exists
	templates := "templates/"
	if strings.HasSuffix(path, ".html") {
		templates += path
	} else {
		templates += path + ".html"
	}

	if _, err := os.Stat(templates); errors.Is(err, os.ErrNotExist) {
		// redirect_uri
		if v, ok := data["redirect_uri"]; ok {
			redirectURI, ok := v.(string)
			if ok && redirectURI != "" {
				http.Redirect(c.Res, c.Req, redirectURI, http.StatusFound)
				c.Log.Error(logAction.OUTBOUND("server render to client"), map[string]any{
					"status":  http.StatusInternalServerError,
					"headers": c.Res.Header(),
					"error":   "template file not found",
				})
				c.Log.FlushError(http.StatusInternalServerError, "template file not found")
				return
			}
		}

		c.Res.Header().Set("Content-Type", "application/json")
		c.Res.WriteHeader(http.StatusInternalServerError)

		json.NewEncoder(c.Res).Encode(map[string]any{
			"error": "template file not found",
		})
		c.Log.Error(logAction.OUTBOUND("server render to client"), map[string]any{
			"status":  http.StatusInternalServerError,
			"headers": c.Res.Header(),
			"error":   "template file not found",
		})
		c.Log.FlushError(http.StatusInternalServerError, "template file not found")
		return
	}

	tmpl, err := template.ParseFiles(templates)
	if err != nil {
		// redirect_uri
		if v, ok := data["redirect_uri"]; ok {
			redirectURI, ok := v.(string)
			if ok && redirectURI != "" {
				http.Redirect(c.Res, c.Req, redirectURI, http.StatusFound)
				c.Log.Error(logAction.OUTBOUND("server render to client"), map[string]any{
					"status":  http.StatusInternalServerError,
					"headers": c.Res.Header(),
					"error":   "template file not found",
				})
				c.Log.FlushError(http.StatusInternalServerError, "template file not found")
				return
			}
		}
		c.Res.Header().Set("Content-Type", "application/json")
		c.Res.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(c.Res).Encode(map[string]any{
			"error": "template file not found",
		})
		c.Log.Error(logAction.OUTBOUND("server render to client"), map[string]any{
			"status": http.StatusInternalServerError,
			"error":  err.Error(),
		})
		c.Log.FlushError(http.StatusInternalServerError, "template parse error")
		return
	}

	// Execute template to buffer first to catch errors before writing headers
	if err := tmpl.Execute(c.Res, data); err != nil {
		// redirect_uri
		if v, ok := data["redirect_uri"]; ok {
			redirectURI, ok := v.(string)
			if ok && redirectURI != "" {
				http.Redirect(c.Res, c.Req, redirectURI, http.StatusFound)
				c.Log.Error(logAction.OUTBOUND("server render to client"), map[string]any{
					"status":  http.StatusInternalServerError,
					"headers": c.Res.Header(),
					"error":   "template file not found",
				})
				c.Log.FlushError(http.StatusInternalServerError, "template file not found")
				return
			}
		}

		c.Res.Header().Set("Content-Type", "application/json")
		c.Res.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(c.Res).Encode(map[string]any{
			"error": "template file not found",
		})
		c.Log.Error(logAction.OUTBOUND("server render to client"), map[string]any{
			"status": http.StatusInternalServerError,
			"error":  err.Error(),
		})
		c.Log.FlushError(http.StatusInternalServerError, "template execution error")
		return
	}

	c.Log.Info(logAction.OUTBOUND("server render to client"), map[string]any{
		"status":  http.StatusOK,
		"headers": c.Res.Header(),
		"body":    data,
	})
	c.Log.Flush(http.StatusOK, "success")
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

	// err may be nil in some call sites; avoid panic on err.Error()
	if err != nil {
		c.Log.AddMetadata("ErrorCode", err.Error())
		c.Log.FlushError(code, c.statusMessage(code))
		return
	}

	// Fallback when no error object provided
	c.Log.AddMetadata("ErrorCode", "unknown")
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

var (
	errUnknownType = errors.New("unknown type")

	// ErrConvertMapStringSlice can not convert to map[string][]string
	ErrConvertMapStringSlice = errors.New("can not convert to map slices of strings")

	// ErrConvertToMapString can not convert to map[string]string
	ErrConvertToMapString = errors.New("can not convert to map of strings")
)

func setFormMap(ptr any, form map[string][]string) error {
	el := reflect.TypeOf(ptr).Elem()

	if el.Kind() == reflect.Slice {
		ptrMap, ok := ptr.(map[string][]string)
		if !ok {
			return ErrConvertMapStringSlice
		}
		maps.Copy(ptrMap, form)

		return nil
	}

	ptrMap, ok := ptr.(map[string]string)
	if !ok {
		return ErrConvertToMapString
	}
	for k, v := range form {
		ptrMap[k] = v[len(v)-1] // pick last
	}

	return nil
}
