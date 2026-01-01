package logger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/sing3demons/oauth/kp/pkg/logAction"
)

type LogLevel string

const (
	LevelDebug LogLevel = "debug"
	LevelInfo  LogLevel = "info"
	LevelWarn  LogLevel = "warn"
	LevelError LogLevel = "error"
)

type LogType string

const (
	TypeDetail  LogType = "detail"
	TypeSummary LogType = "summary"
)

type DetailLog struct {
	Timestamp         string         `json:"timestamp"`
	Level             LogLevel       `json:"level"`
	Type              LogType        `json:"type"`
	Service           string         `json:"service"`
	Version           string         `json:"version"`
	TransactionID     string         `json:"transactionId,omitempty"`
	SessionID         string         `json:"sessionId,omitempty"`
	Action            string         `json:"action,omitempty"`
	ActionDescription string         `json:"actionDescription,omitempty"`
	SubAction         string         `json:"subAction,omitempty"`
	Message           string         `json:"message,omitempty"`
	Result            string         `json:"result,omitempty"`
	UserID            string         `json:"userId,omitempty"`
	ClientID          string         `json:"clientId,omitempty"`
	Email             string         `json:"email,omitempty"`
	IPAddress         string         `json:"ipAddress,omitempty"`
	UserAgent         string         `json:"userAgent,omitempty"`
	Duration          int64          `json:"duration,omitempty"`
	StatusCode        int            `json:"statusCode,omitempty"`
	Error             string         `json:"error,omitempty"`
	ErrorCode         string         `json:"errorCode,omitempty"`
	Metadata          map[string]any `json:"metadata,omitempty"`
}

type LogOutputConfig struct {
	Path    string
	Console bool
	File    bool
}

type LoggerConfig struct {
	Summary LogOutputConfig
	Detail  LogOutputConfig
}

type Logger struct {
	service       string
	version       string
	config        *LoggerConfig
	transactionID string
	sessionID     string
	detailLogs    []DetailLog
	startTime     time.Time
	metadata      map[string]any
}

type ActionInfo struct {
	Action            string
	ActionDescription string
	SubAction         string
}

func DefaultConfig() *LoggerConfig {
	return &LoggerConfig{
		Summary: LogOutputConfig{
			Path:    "./logs/summary/",
			Console: true,
			File:    false,
		},
		Detail: LogOutputConfig{
			Path:    "./logs/detail/",
			Console: true,
			File:    false,
		},
	}
}

func NewLogger(service, version string) *Logger {
	return &Logger{
		service:    service,
		version:    version,
		config:     DefaultConfig(),
		detailLogs: make([]DetailLog, 0),
		startTime:  time.Now(),
		metadata:   make(map[string]any),
	}
}

func NewLoggerWithConfig(service, version string, config *LoggerConfig) *Logger {
	return &Logger{
		service:    service,
		version:    version,
		config:     config,
		detailLogs: make([]DetailLog, 0),
		startTime:  time.Now(),
		metadata:   make(map[string]any),
	}
}
func (l *Logger) SetSessionID(sessionID string) {
	l.sessionID = sessionID
}

func (l *Logger) SetTransactionID(transactionID string) {
	l.transactionID = transactionID
}

func (l *Logger) write(log DetailLog) {
	log.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	log.Service = l.service
	log.Version = l.version

	jsonLog, err := json.Marshal(log)
	if err != nil {
		return
	}

	jsonLog = append(jsonLog, '\n')

	var outputConfig LogOutputConfig
	if log.Type == TypeSummary {
		outputConfig = l.config.Summary
	} else {
		outputConfig = l.config.Detail
	}

	// Write to console
	if outputConfig.Console {
		os.Stdout.Write(jsonLog)
	}

	// Write to file
	if outputConfig.File {
		l.writeToFile(outputConfig.Path, log.Timestamp, jsonLog)
	}
}

func (l *Logger) writeToFile(basePath, timestamp string, data []byte) {
	// Create directory if not exists
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return
	}

	// Generate filename based on date (YYYY-MM-DD.log)
	date := timestamp[:10] // Extract date from ISO8601 timestamp
	//
	fullPath := filepath.Join(basePath, date)
	filename := fullPath + ".log"

	// Append to file
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	f.Write(data)
}

// Detail logs detailed information with optional data masking
func (l *Logger) Detail(level LogLevel, actionInfo logAction.LoggerAction, data any, maskingRules ...MaskingRule) {
	var maskedData any
	if len(maskingRules) > 0 {
		maskedData = MaskData(data, maskingRules)
	} else {
		maskedData = data
	}

	log := DetailLog{
		Level:             level,
		Type:              TypeDetail,
		Action:            actionInfo.Action,
		ActionDescription: actionInfo.ActionDescription,
		SubAction:         actionInfo.SubAction,
		Message:           dataToString(maskedData),
		TransactionID:     l.transactionID,
		SessionID:         l.sessionID,
	}

	l.write(log)
}

// Summary logs summary information
func (l *Logger) Summary(level LogLevel, actionInfo logAction.LoggerAction, summary map[string]any) {
	log := DetailLog{
		Level:             level,
		Type:              TypeSummary,
		Action:            actionInfo.Action,
		ActionDescription: actionInfo.ActionDescription,
		SubAction:         actionInfo.SubAction,
		Message:           actionInfo.ActionDescription,
		Metadata:          summary,
	}

	l.write(log)
}

// Helper methods for common log levels
func (l *Logger) InfoDetail(actionInfo logAction.LoggerAction, data any, maskingRules ...MaskingRule) {
	l.Detail(LevelInfo, actionInfo, data, maskingRules...)
}

func (l *Logger) DebugDetail(actionInfo logAction.LoggerAction, data any, maskingRules ...MaskingRule) {
	l.Detail(LevelDebug, actionInfo, data, maskingRules...)
}

func (l *Logger) WarnDetail(actionInfo logAction.LoggerAction, data any, maskingRules ...MaskingRule) {
	l.Detail(LevelWarn, actionInfo, data, maskingRules...)
}

func (l *Logger) ErrorDetail(actionInfo logAction.LoggerAction, data any, maskingRules ...MaskingRule) {
	l.Detail(LevelError, actionInfo, data, maskingRules...)
}

func (l *Logger) InfoSummary(actionInfo logAction.LoggerAction, summary map[string]any) {
	l.Summary(LevelInfo, actionInfo, summary)
}

func (l *Logger) ErrorSummary(actionInfo logAction.LoggerAction, summary map[string]any) {
	l.Summary(LevelError, actionInfo, summary)
}

// Simple logging for backward compatibility
func (l *Logger) Info(action logAction.LoggerAction, data any, maskingRules ...MaskingRule) {
	l.Detail("info", action, data, maskingRules...)
}

func (l *Logger) Debug(action, message string, opts ...LogOption) {
	log := DetailLog{
		Level:         LevelDebug,
		Type:          TypeDetail,
		Action:        action,
		Message:       message,
		TransactionID: l.transactionID,
		SessionID:     l.sessionID,
	}

	for _, opt := range opts {
		opt(&log)
	}

	l.write(log)
}

func (l *Logger) Warn(action, message string, opts ...LogOption) {
	log := DetailLog{
		Level:         LevelWarn,
		Type:          TypeDetail,
		Action:        action,
		Message:       message,
		TransactionID: l.transactionID,
		SessionID:     l.sessionID,
	}

	for _, opt := range opts {
		opt(&log)
	}

	l.write(log)
}

func (l *Logger) Error(action, message string, opts ...LogOption) {
	log := DetailLog{
		Level:         LevelError,
		Type:          TypeDetail,
		Action:        action,
		Message:       message,
		TransactionID: l.transactionID,
		SessionID:     l.sessionID,
	}

	for _, opt := range opts {
		opt(&log)
	}

	l.write(log)
}

// Flush writes a summary log with success status and cleans up accumulated logs
func (l *Logger) Flush(statusCode int, message string) {
	duration := time.Since(l.startTime).Milliseconds()

	// Use accumulated metadata
	summaryMetadata := l.metadata

	log := DetailLog{
		Level:         LevelInfo,
		Type:          TypeSummary,
		Message:       message,
		TransactionID: l.transactionID,
		SessionID:     l.sessionID,
		StatusCode:    statusCode,
		Duration:      duration,
		Metadata:      summaryMetadata,
	}

	l.write(log)
	l.cleanup()
}

// FlushError writes a summary log with error status and cleans up accumulated logs
func (l *Logger) FlushError(statusCode int, message string) {
	duration := time.Since(l.startTime).Milliseconds()

	// Use accumulated metadata
	summaryMetadata := l.metadata

	log := DetailLog{
		Level:         LevelError,
		Type:          TypeSummary,
		Message:       message,
		TransactionID: l.transactionID,
		SessionID:     l.sessionID,
		StatusCode:    statusCode,
		Duration:      duration,
		Metadata:      summaryMetadata,
	}

	l.write(log)
	l.cleanup()
}

// cleanup resets the logger state for next transaction
func (l *Logger) cleanup() {
	l.detailLogs = make([]DetailLog, 0)
	l.metadata = make(map[string]any)
	l.startTime = time.Now()
}

// StartTransaction initializes a new transaction with IDs
func (l *Logger) StartTransaction(transactionID, sessionID string) {
	l.transactionID = transactionID
	l.sessionID = sessionID
	l.startTime = time.Now()
	l.metadata = make(map[string]any)
}

// AddMetadata adds or overwrites a metadata key-value pair
func (l *Logger) AddMetadata(key string, value any) {
	l.metadata[key] = value
}

// AddSuccess adds a value to metadata, creating an array if the key already exists
// This is useful for accumulating multiple values for the same key
func (l *Logger) AddSuccess(key string, value any) {
	existing, exists := l.metadata[key]
	if !exists {
		// First value - store as single value
		l.metadata[key] = value
		return
	}

	// Check if existing value is already an array
	if arr, isArray := existing.([]any); isArray {
		// Append to existing array
		l.metadata[key] = append(arr, value)
		return
	}

	// Convert single value to array with both old and new values
	l.metadata[key] = []any{existing, value}
}

func dataToString(data any) string {
	if data == nil {
		return ""
	}

	if str, ok := data.(string); ok {
		return str
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return ""
	}

	return string(jsonBytes)
}

type LogOption func(*DetailLog)

func WithTransactionID(id string) LogOption {
	return func(l *DetailLog) {
		l.TransactionID = id
	}
}

func WithSessionID(id string) LogOption {
	return func(l *DetailLog) {
		l.SessionID = id
	}
}

func WithActionDescription(desc string) LogOption {
	return func(l *DetailLog) {
		l.ActionDescription = desc
	}
}

func WithSubAction(subAction string) LogOption {
	return func(l *DetailLog) {
		l.SubAction = subAction
	}
}

func WithUserID(id string) LogOption {
	return func(l *DetailLog) {
		l.UserID = id
	}
}

func WithClientID(id string) LogOption {
	return func(l *DetailLog) {
		l.ClientID = id
	}
}

func WithEmail(email string) LogOption {
	return func(l *DetailLog) {
		l.Email = email
	}
}

func WithIPAddress(ip string) LogOption {
	return func(l *DetailLog) {
		l.IPAddress = ip
	}
}

func WithUserAgent(ua string) LogOption {
	return func(l *DetailLog) {
		l.UserAgent = ua
	}
}

func WithDuration(ms int64) LogOption {
	return func(l *DetailLog) {
		l.Duration = ms
	}
}

func WithStatusCode(code int) LogOption {
	return func(l *DetailLog) {
		l.StatusCode = code
	}
}

func WithError(err string) LogOption {
	return func(l *DetailLog) {
		l.Error = err
	}
}

func WithErrorCode(code string) LogOption {
	return func(l *DetailLog) {
		l.ErrorCode = code
	}
}

func WithMetadata(key string, value any) LogOption {
	return func(l *DetailLog) {
		if l.Metadata == nil {
			l.Metadata = make(map[string]any)
		}
		l.Metadata[key] = value
	}
}

func WithMetadataMap(metadata map[string]any) LogOption {
	return func(l *DetailLog) {
		l.Metadata = metadata
	}

}
