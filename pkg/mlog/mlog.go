package mlog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/sing3demons/oauth/kp/pkg/logAction"
	"github.com/sing3demons/oauth/kp/pkg/logger"
)

func L(ctx context.Context) *logger.Logger {
	if ctx == nil {
		return logger.NewLogger("", "")
	}
	l, ok := ctx.Value("logger").(*logger.Logger)
	if !ok || l == nil {
		return logger.NewLogger("", "")
	}

	return l
}

type ResponseWithLogger struct {
	w      http.ResponseWriter
	r      *http.Request
	logger *logger.Logger
}

func NewResponseWithLogger(w http.ResponseWriter, r *http.Request, userCase, xSid string, masking ...logger.MaskingRule) *ResponseWithLogger {
	if xSid == "" {
		xSid = uuid.NewString()
	}
	rwl := &ResponseWithLogger{
		w:      w,
		r:      r,
		logger: InitLog(r, userCase, xSid, masking...),
	}

	return rwl
}

func StatusMessage(status int) string {
	msg := http.StatusText(status)
	if msg == "" {
		return "unknown_status"
	}
	return strings.ToLower(strings.ReplaceAll(msg, " ", "_"))
}

func (rwl *ResponseWithLogger) ResponseJson(status int, data any, masking ...logger.MaskingRule) {
	rwl.w.Header().Set("Content-Type", "application/json")
	rwl.w.Header().Set("x-session-id", rwl.logger.SessionID())
	rwl.w.WriteHeader(status)
	json.NewEncoder(rwl.w).Encode(data)

	rwl.logger.Info(logAction.OUTBOUND("server response to client"), map[string]any{
		"status":  status,
		"headers": rwl.w.Header(),
		"body":    data,
	}, masking...)

	rwl.logger.Flush(status, StatusMessage(status))
}

func (rwl *ResponseWithLogger) Redirect(urlStr string) {
	fullUrl := urlStr
	location, err := url.Parse(urlStr)
	if err == nil {
		q := location.Query()
		q.Add("sid", rwl.logger.SessionID())
		location.RawQuery = q.Encode()
		fullUrl = location.String()
	}
	http.Redirect(rwl.w, rwl.r, fullUrl, http.StatusFound)

	rwl.logger.Info(logAction.OUTBOUND("server redirect to client"), map[string]any{
		"status":  http.StatusFound,
		"headers": rwl.w.Header(),
		"url":     fullUrl,
	})

	msg := fmt.Sprintf("redirect to %s", urlStr)
	rwl.logger.Flush(http.StatusFound, msg)
}

func (rwl *ResponseWithLogger) ResponseJsonError(status int, data any, err error) {
	rwl.w.Header().Set("Content-Type", "application/json")
	rwl.w.WriteHeader(status)
	json.NewEncoder(rwl.w).Encode(data)

	rwl.logger.Info(logAction.OUTBOUND("server response to client"), map[string]any{
		"status":  status,
		"headers": rwl.w.Header(),
		"body":    data,
	})

	rwl.logger.AddMetadata("ErrorCode", err.Error())

	rwl.logger.FlushError(status, StatusMessage(status))
}

func InitLog(r *http.Request, userCase, xSid string, masking ...logger.MaskingRule) *logger.Logger {
	l := L(r.Context())
	l.SetSessionID(xSid)
	l.SetUseCase(userCase)

	headers := make(map[string]string)
	for key, values := range r.Header {
		if len(values) > 0 {
			headers[key] = strings.Join(values, ", ")
		} else {
			headers[key] = ""
		}
	}

	body := new(map[string]any)
	if r.Method != http.MethodGet {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			body = nil
		}

		// Restore the request body so it can be read again later
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		json.Unmarshal(bodyBytes, &body)
	}
	params := make(map[string]string)

	// pattern := r.PathPattern() // "/users/{id}/orders/{orderId}"
	// Since http.Request does not have PathPattern, set pattern to r.URL.Path or another available value
	pattern := r.URL.Path
	re := regexp.MustCompile(`\{(\w+)\}`)
	matches := re.FindAllStringSubmatch(pattern, -1)

	// PathValue is also not available on *http.Request, so this section is commented out or needs to be replaced with custom logic if needed
	for _, m := range matches {
		key := m[1]
		params[key] = r.PathValue(key)
	}

	l.Info(logAction.INBOUND(fmt.Sprintf("client %s %s server", r.Method, r.URL.String())), map[string]any{
		"method":  r.Method,
		"url":     r.URL.String(),
		"headers": headers,
		"query":   r.URL.Query(),
		"body":    body,
		"params":  params,
		"remote":  r.RemoteAddr,
	}, masking...)
	return l
}
