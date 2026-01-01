package mlog

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/sing3demons/oauth/kp/pkg/logAction"
	"github.com/sing3demons/oauth/kp/pkg/logger"
)

func L(r *http.Request) *logger.Logger {
	if r == nil || r.Context() == nil {
		return logger.NewLogger("", "")
	}
	l, ok := r.Context().Value("logger").(*logger.Logger)
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

func NewResponseWithLogger(w http.ResponseWriter, r *http.Request, xSid string, masking ...logger.MaskingRule) *ResponseWithLogger {
	rwl := &ResponseWithLogger{
		w:      w,
		r:      r,
		logger: InitLog(r, xSid, masking...),
	}

	return rwl
}
func (rwl *ResponseWithLogger) ResponseJson(status int, data any, masking ...logger.MaskingRule) {
	rwl.w.WriteHeader(status)
	rwl.w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rwl.w).Encode(data)

	rwl.logger.Info(logAction.OUTBOUND(rwl.r.Method+" -> "+rwl.r.URL.RawPath+" response"), map[string]any{
		"status":  status,
		"headers": rwl.w.Header(),
		"body":    data,
	}, masking...)

	msg := http.StatusText(status)

	rwl.logger.Flush(status, msg)
}

func InitLog(r *http.Request, xSid string, masking ...logger.MaskingRule) *logger.Logger {
	l := L(r)
	l.SetSessionID(xSid)

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

	l.Info(logAction.INBOUND(r.Method+" -> "+r.URL.RawPath), map[string]any{
		"method":  r.Method,
		"url":     r.URL.String(),
		"headers": headers,
		"query":   r.URL.Query(),
		"body":    body,
	}, masking...)
	return l
}
