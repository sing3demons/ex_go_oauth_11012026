package logger

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	configs "github.com/sing3demons/oauth/kp/internal/config"
	"github.com/sing3demons/oauth/kp/pkg/logAction"
)

type LogLevel string

const (
	LevelDebug LogLevel = "debug"
	LevelInfo  LogLevel = "info"
	LevelWarn  LogLevel = "warn"
	LevelError LogLevel = "error"

	ErrorSourceKey = "errorSource"
)

type LogType string
type CtxKey string

const (
	TypeDetail  LogType = "detail"
	TypeSummary LogType = "summary"
	LoggerKey   CtxKey  = "logger"
)

type DetailLog struct {
	Timestamp         string         `json:"timestamp"`
	Level             LogLevel       `json:"level"`
	Type              LogType        `json:"type"`
	Service           string         `json:"service"`
	UseCase           string         `json:"useCase,omitempty"`
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
	Stack             string         `json:"stack,omitempty"` //Use when error
	ErrorCode         string         `json:"errorCode,omitempty"`
	Metadata          map[string]any `json:"metadata,omitempty"`
	Dependency        string         `json:"dependency,omitempty"`
	ResponseTime      int64          `json:"responseTime,omitempty"`
	ResultCode        string         `json:"resultCode,omitempty"`
	ResultFlag        string         `json:"resultFlag,omitempty"`
	AdditionalInfo    map[string]any `json:"additionalInfo,omitempty"`
}

type ErrorSource struct {
	Node        string `json:"node,omitempty"`
	Description string `json:"description,omitempty"`
	Code        string `json:"code,omitempty"`
}
type DependencyMetadata struct {
	Dependency   string `json:"dependency,omitempty"`
	ResponseTime int64  `json:"responseTime,omitempty"`
	ResultCode   string `json:"resultCode,omitempty"`
	ResultFlag   string `json:"resultFlag,omitempty"`
}

// fileWriter manages buffered file writing with rotation
type fileWriter struct {
	mu          sync.Mutex
	file        *os.File
	writer      *bufio.Writer
	path        string
	currentDate string
	currentSize int64
	config      configs.RotationConfig
}

type Logger struct {
	mu            sync.RWMutex
	service       string
	version       string
	config        *configs.LoggerConfig
	transactionID string
	sessionID     string
	UseCase       string
	detailLogs    []DetailLog
	startTime     time.Time
	metadata      map[string]any
	fileWriters   map[string]*fileWriter // cached file writers by path
	writersMu     sync.RWMutex
}

type ILogger interface {
	SetSessionID(sessionID string)
	SetTransactionID(transactionID string)
	SetUseCase(useCase string)
	Close() error

	Info(action logAction.LoggerAction, data any, maskingRules ...MaskingRule)
	Debug(action logAction.LoggerAction, data any, maskingRules ...MaskingRule)
	Warn(action logAction.LoggerAction, data any, maskingRules ...MaskingRule)
	Error(action logAction.LoggerAction, data any, maskingRules ...MaskingRule)

	Flush(statusCode int, message string)
	FlushError(statusCode int, message string)

	AddMetadata(key string, value any)
	SetDependencyMetadata(metadata DependencyMetadata) ILogger
	SessionID() string
	TransactionID() string
	LogWithContext(ctx context.Context) ILogger
}

func NewLogger(service, version string) ILogger {
	return &Logger{
		service:     service,
		version:     version,
		config:      configs.DefaultConfig(),
		detailLogs:  make([]DetailLog, 0),
		startTime:   time.Now(),
		metadata:    make(map[string]any),
		fileWriters: make(map[string]*fileWriter),
	}
}

func NewLoggerWithConfig(service, version string, config *configs.LoggerConfig) ILogger {
	// Ensure rotation config has defaults if not set
	if config.Rotation.MaxSize == 0 {
		config.Rotation = configs.DefaultRotationConfig()
	}
	return &Logger{
		service:     service,
		version:     version,
		config:      config,
		detailLogs:  make([]DetailLog, 0),
		startTime:   time.Now(),
		metadata:    make(map[string]any),
		fileWriters: make(map[string]*fileWriter),
	}
}

func (l *Logger) LogWithContext(ctx context.Context) ILogger {
	if ctx == nil {
		return NewLogger("", "")
	}
	logger, ok := ctx.Value(LoggerKey).(ILogger)
	if !ok || logger == nil {
		return NewLogger("", "")
	}

	return logger
}

func (l *Logger) SetSessionID(sessionID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sessionID = sessionID
}

func (l *Logger) SetTransactionID(transactionID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.transactionID = transactionID
}

func (l *Logger) SetUseCase(useCase string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.UseCase = useCase
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

	var outputConfig configs.LogOutputConfig
	if log.Type == TypeSummary {
		outputConfig = l.config.Summary
	} else {
		outputConfig = l.config.Detail
	}

	// Write to console (thread-safe via os.Stdout)
	if outputConfig.Console {
		os.Stdout.Write(jsonLog)
	}

	// Write to file with rotation support
	if outputConfig.File {
		l.writeToFileBuffered(outputConfig.Path, log.Timestamp, jsonLog)
	}
}

// getOrCreateWriter gets or creates a buffered file writer for the given path
func (l *Logger) getOrCreateWriter(basePath, date string) (*fileWriter, error) {
	key := basePath + "/" + date

	l.writersMu.RLock()
	fw, exists := l.fileWriters[key]
	l.writersMu.RUnlock()

	if exists && fw.currentDate == date {
		return fw, nil
	}

	l.writersMu.Lock()
	defer l.writersMu.Unlock()

	// Double-check after acquiring write lock
	fw, exists = l.fileWriters[key]
	if exists && fw.currentDate == date {
		return fw, nil
	}

	// Create directory if not exists
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, err
	}

	filename := filepath.Join(basePath, date+".log")

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	// Get current file size
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}

	// Close old writer if exists
	if oldFw, exists := l.fileWriters[key]; exists {
		oldFw.Close()
	}

	fw = &fileWriter{
		file:        f,
		writer:      bufio.NewWriterSize(f, 64*1024), // 64KB buffer
		path:        basePath,
		currentDate: date,
		currentSize: info.Size(),
		config:      l.config.Rotation,
	}

	l.fileWriters[key] = fw
	return fw, nil
}

func (l *Logger) writeToFileBuffered(basePath, timestamp string, data []byte) {
	date := timestamp[:10] // Extract date from ISO8601 timestamp

	fw, err := l.getOrCreateWriter(basePath, date)
	if err != nil {
		return
	}

	fw.Write(data)
}

// Write writes data to the file with rotation check
func (fw *fileWriter) Write(data []byte) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	// Check if rotation is needed (size-based)
	if fw.config.MaxSize > 0 && fw.currentSize+int64(len(data)) > fw.config.MaxSize {
		if err := fw.rotate(); err != nil {
			return err
		}
	}

	n, err := fw.writer.Write(data)
	if err != nil {
		return err
	}
	fw.currentSize += int64(n)

	// Flush periodically or on error logs
	fw.writer.Flush()

	return nil
}

// rotate performs log rotation
func (fw *fileWriter) rotate() error {
	// Flush and close current file
	fw.writer.Flush()
	fw.file.Close()

	// Generate rotated filename with timestamp
	currentFile := filepath.Join(fw.path, fw.currentDate+".log")
	rotatedFile := filepath.Join(fw.path, fmt.Sprintf("%s.%s.log", fw.currentDate, time.Now().Format("150405")))

	// Rename current file
	if err := os.Rename(currentFile, rotatedFile); err != nil {
		return err
	}

	// Compress rotated file if enabled
	if fw.config.Compress {
		go fw.compressFile(rotatedFile)
	}

	// Open new file
	f, err := os.OpenFile(currentFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	fw.file = f
	fw.writer = bufio.NewWriterSize(f, 64*1024)
	fw.currentSize = 0

	// Cleanup old files
	go fw.cleanupOldFiles()

	return nil
}

// compressFile compresses a log file using gzip
func (fw *fileWriter) compressFile(filename string) {
	src, err := os.Open(filename)
	if err != nil {
		return
	}
	defer src.Close()

	dst, err := os.Create(filename + ".gz")
	if err != nil {
		return
	}
	defer dst.Close()

	gz := gzip.NewWriter(dst)
	defer gz.Close()

	if _, err := io.Copy(gz, src); err != nil {
		os.Remove(filename + ".gz")
		return
	}

	// Remove original file after successful compression
	os.Remove(filename)
}

// cleanupOldFiles removes old log files based on MaxAge and MaxBackups
func (fw *fileWriter) cleanupOldFiles() {
	files, err := filepath.Glob(filepath.Join(fw.path, "*.log*"))
	if err != nil {
		return
	}

	type fileInfo struct {
		path    string
		modTime time.Time
	}

	var logFiles []fileInfo
	cutoff := time.Now().AddDate(0, 0, -fw.config.MaxAge)

	for _, f := range files {
		info, err := os.Stat(f)
		if err != nil {
			continue
		}

		// Remove files older than MaxAge
		if fw.config.MaxAge > 0 && info.ModTime().Before(cutoff) {
			os.Remove(f)
			continue
		}

		// Skip current day's main log file
		if strings.HasSuffix(f, fw.currentDate+".log") {
			continue
		}

		logFiles = append(logFiles, fileInfo{path: f, modTime: info.ModTime()})
	}

	// Keep only MaxBackups files
	if fw.config.MaxBackups > 0 && len(logFiles) > fw.config.MaxBackups {
		sort.Slice(logFiles, func(i, j int) bool {
			return logFiles[i].modTime.After(logFiles[j].modTime)
		})

		for i := fw.config.MaxBackups; i < len(logFiles); i++ {
			os.Remove(logFiles[i].path)
		}
	}
}

// Close closes the file writer
func (fw *fileWriter) Close() error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if fw.writer != nil {
		fw.writer.Flush()
	}
	if fw.file != nil {
		return fw.file.Close()
	}
	return nil
}

// Close closes all file writers and flushes buffers
func (l *Logger) Close() error {
	l.writersMu.Lock()
	defer l.writersMu.Unlock()

	var lastErr error
	for _, fw := range l.fileWriters {
		if err := fw.Close(); err != nil {
			lastErr = err
		}
	}
	l.fileWriters = make(map[string]*fileWriter)
	return lastErr
}

// Flush flushes all buffered data to files
func (l *Logger) FlushBuffers() {
	l.writersMu.RLock()
	defer l.writersMu.RUnlock()

	for _, fw := range l.fileWriters {
		fw.mu.Lock()
		if fw.writer != nil {
			fw.writer.Flush()
		}
		fw.mu.Unlock()
	}
}

// Detail logs detailed information with optional data masking
func (l *Logger) Detail(level LogLevel, actionInfo logAction.LoggerAction, data any, maskingRules ...MaskingRule) {
	var maskedData any
	if len(maskingRules) > 0 {
		maskedData = MaskData(data, maskingRules)
	} else {
		maskedData = data
	}

	l.mu.RLock()
	transactionID := l.transactionID
	sessionID := l.sessionID
	l.mu.RUnlock()

	log := DetailLog{
		Level:             level,
		Type:              TypeDetail,
		Action:            actionInfo.Action,
		ActionDescription: actionInfo.ActionDescription,
		SubAction:         actionInfo.SubAction,
		Message:           dataToString(maskedData),
		TransactionID:     transactionID,
		SessionID:         sessionID,
		UseCase:           l.UseCase,
	}

	if len(l.metadata) > 0 {
		if l.metadata["dependency"] != nil {
			log.Dependency = l.metadata["dependency"].(string)
			// Remove dependency from metadata to avoid duplication
			delete(l.metadata, "dependency")
		}
		if l.metadata["responseTime"] != nil {
			log.ResponseTime = l.metadata["responseTime"].(int64)
			// Remove responseTime from metadata to avoid duplication
			delete(l.metadata, "responseTime")
		}
		if l.metadata["resultCode"] != nil {
			log.ResultCode = l.metadata["resultCode"].(string)
			// Remove resultCode from metadata to avoid duplication
			delete(l.metadata, "resultCode")
		}
		if l.metadata["resultFlag"] != nil {
			log.ResultFlag = l.metadata["resultFlag"].(string)
			// Remove resultFlag from metadata to avoid duplication
			delete(l.metadata, "resultFlag")
		}
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

func (l *Logger) Debug(action logAction.LoggerAction, data any, maskingRules ...MaskingRule) {
	l.DebugDetail(action, data, maskingRules...)
}

func (l *Logger) Warn(action logAction.LoggerAction, data any, maskingRules ...MaskingRule) {
	l.WarnDetail(action, data, maskingRules...)
}

func (l *Logger) Error(action logAction.LoggerAction, data any, maskingRules ...MaskingRule) {
	l.ErrorDetail(action, data, maskingRules...)
}

// Flush writes a summary log with success status and cleans up accumulated logs
func (l *Logger) Flush(statusCode int, message string) {
	l.mu.Lock()
	duration := time.Since(l.startTime).Milliseconds()
	transactionID := l.transactionID
	sessionID := l.sessionID
	// Copy metadata to avoid race
	summaryMetadata := make(map[string]any, len(l.metadata))
	maps.Copy(summaryMetadata, l.metadata)
	l.mu.Unlock()

	log := DetailLog{
		Level:         LevelInfo,
		Type:          TypeSummary,
		Message:       message,
		TransactionID: transactionID,
		SessionID:     sessionID,
		StatusCode:    statusCode,
		Duration:      duration,
		Metadata:      summaryMetadata,
		UseCase:       l.UseCase,
	}

	l.write(log)
	l.cleanup()
}

// FlushError writes a summary log with error status and cleans up accumulated logs
func (l *Logger) FlushError(statusCode int, message string) {
	l.mu.Lock()
	duration := time.Since(l.startTime).Milliseconds()

	log := DetailLog{
		Level:         LevelError,
		Type:          TypeSummary,
		Message:       message,
		TransactionID: l.transactionID,
		SessionID:     l.sessionID,
		UseCase:       l.UseCase,
		StatusCode:    statusCode,
		Duration:      duration,
	}
	// Copy metadata to avoid race
	summaryMetadata := make(map[string]any, len(l.metadata))
	for k, v := range l.metadata {
		if k == "resultCode" || k == "resultFlag" || k == "dependency" || k == "responseTime" {
			switch k {
			case "resultCode":
				log.ResultCode = v.(string)
			case "resultFlag":
				log.ResultFlag = v.(string)
			}
			continue
		}
		summaryMetadata[k] = v
	}
	l.mu.Unlock()
	if len(summaryMetadata) > 0 {
		log.Metadata = summaryMetadata
	}

	l.write(log)
	l.cleanup()
}

// cleanup resets the logger state for next transaction
func (l *Logger) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.detailLogs = make([]DetailLog, 0)
	l.metadata = make(map[string]any)
	l.startTime = time.Now()
}

// StartTransaction initializes a new transaction with IDs
func (l *Logger) StartTransaction(transactionID, sessionID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.transactionID = transactionID
	l.sessionID = sessionID
}

// AddMetadata adds or overwrites a metadata key-value pair
func (l *Logger) AddMetadata(key string, value any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.metadata[key] = value
}

func (l *Logger) SetDependencyMetadata(metadata DependencyMetadata) ILogger {
	l.mu.Lock()
	defer l.mu.Unlock()
	if metadata.Dependency != "" {
		l.metadata["dependency"] = metadata.Dependency
	}
	if metadata.ResponseTime != 0 {
		l.metadata["responseTime"] = metadata.ResponseTime
	}
	if metadata.ResultCode != "" {
		l.metadata["resultCode"] = metadata.ResultCode
	}
	if metadata.ResultFlag != "" {
		l.metadata["resultFlag"] = metadata.ResultFlag
	}
	return l
}

// AddSuccess adds a value to metadata, creating an array if the key already exists
// This is useful for accumulating multiple values for the same key
func (l *Logger) AddSuccess(key string, value any) {
	l.mu.Lock()
	defer l.mu.Unlock()

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

func (l *Logger) SessionID() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.sessionID
}

func (l *Logger) TransactionID() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.transactionID
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
