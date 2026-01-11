package logger

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	configs "github.com/sing3demons/oauth/kp/internal/config"
	"github.com/sing3demons/oauth/kp/pkg/logAction"
)

func TestNewLogger(t *testing.T) {
	logger := NewLogger("test-service", "1.0.0")
	if logger == nil {
		t.Fatal("Expected logger to be created")
	}
}

func TestNewLoggerWithConfig(t *testing.T) {
	config := &configs.LoggerConfig{
		Detail: configs.LogOutputConfig{
			Console: true,
			File:    false,
		},
		Summary: configs.LogOutputConfig{
			Console: true,
			File:    false,
		},
		Rotation: configs.RotationConfig{
			MaxSize:    10 * 1024 * 1024,
			MaxAge:     7,
			MaxBackups: 5,
			Compress:   true,
		},
	}

	logger := NewLoggerWithConfig("test", "1.0.0", config)
	if logger == nil {
		t.Fatal("Expected logger to be created")
	}
}

func TestSettersAndGetters(t *testing.T) {
	logger := NewLogger("test", "1.0.0").(*Logger)

	logger.SetSessionID("session-123")
	if logger.SessionID() != "session-123" {
		t.Error("Expected session ID to match")
	}

	logger.SetTransactionID("txn-456")
	if logger.TransactionID() != "txn-456" {
		t.Error("Expected transaction ID to match")
	}

	logger.SetUseCase("payment")
	if logger.UseCase != "payment" {
		t.Error("Expected use case to match")
	}
}

func TestLoggerContext(t *testing.T) {
	logger := NewLogger("test", "1.0.0")
	ctx := SetLogger(context.Background(), logger)

	retrieved := GetLogger(ctx)
	if retrieved == nil {
		t.Fatal("Expected to retrieve logger from context")
	}

	if GetLogger(nil) != nil {
		t.Error("Expected nil logger from nil context")
	}

	if GetLogger(context.Background()) != nil {
		t.Error("Expected nil logger from empty context")
	}
}

func TestAddMetadata(t *testing.T) {
	logger := NewLogger("test", "1.0.0").(*Logger)

	logger.AddMetadata("key1", "value1")
	if logger.metadata["key1"] != "value1" {
		t.Error("Expected metadata to be set")
	}
}

func TestSetDependencyMetadata(t *testing.T) {
	logger := NewLogger("test", "1.0.0").(*Logger)

	metadata := DependencyMetadata{
		Dependency:   "postgres",
		ResponseTime: 100,
		ResultCode:   "200",
		ResultFlag:   "SUCCESS",
	}

	result := logger.SetDependencyMetadata(metadata)
	if result == nil {
		t.Error("Expected logger to be returned")
	}
}

func TestCloneAndRelease(t *testing.T) {
	parent := NewLogger("test", "1.0.0").(*Logger)
	parent.SetSessionID("parent-session")

	cloned := parent.Clone().(*Logger)
	if cloned.service != parent.service {
		t.Error("Expected cloned logger to have same service")
	}

	cloned.SetSessionID("cloned-session")
	cloned.Release()

	if len(cloned.metadata) != 0 {
		t.Error("Expected metadata to be cleared after release")
	}
}

func TestLoggingMethods(t *testing.T) {
	tmpDir := t.TempDir()
	config := &configs.LoggerConfig{
		Detail: configs.LogOutputConfig{
			Console: false,
			File:    true,
			Path:    tmpDir,
		},
		Summary: configs.LogOutputConfig{
			Console: false,
			File:    true,
			Path:    tmpDir,
		},
		Rotation: configs.DefaultRotationConfig(),
	}

	logger := NewLoggerWithConfig("test", "1.0.0", config)
	logger.SetSessionID("sess-123")
	logger.SetTransactionID("txn-456")

	action := logAction.LoggerAction{
		Action:            "test",
		ActionDescription: "Testing",
	}

	logger.Info(action, "test message")
	logger.Debug(action, "debug message")
	logger.Warn(action, "warn message")
	logger.Error(action, "error message")

	logger.Close()
}

func TestFlush(t *testing.T) {
	tmpDir := t.TempDir()
	config := &configs.LoggerConfig{
		Detail: configs.LogOutputConfig{
			Console: false,
			File:    false,
		},
		Summary: configs.LogOutputConfig{
			Console: false,
			File:    true,
			Path:    tmpDir,
		},
		Rotation: configs.DefaultRotationConfig(),
	}

	logger := NewLoggerWithConfig("test", "1.0.0", config)
	logger.SetSessionID("sess-123")
	logger.SetTransactionID("txn-456")
	logger.AddMetadata("test", "value")

	logger.Flush(200, "Request completed")
}

func TestFlushError(t *testing.T) {
	tmpDir := t.TempDir()
	config := &configs.LoggerConfig{
		Detail: configs.LogOutputConfig{
			Console: false,
			File:    false,
		},
		Summary: configs.LogOutputConfig{
			Console: false,
			File:    true,
			Path:    tmpDir,
		},
		Rotation: configs.DefaultRotationConfig(),
	}

	logger := NewLoggerWithConfig("test", "1.0.0", config)
	logger.SetSessionID("sess-123")
	logger.AddMetadata("resultCode", "500")
	logger.AddMetadata("resultFlag", "FAILURE")

	logger.FlushError(500, "Request failed")
}

func TestLogError(t *testing.T) {
	tmpDir := t.TempDir()
	config := &configs.LoggerConfig{
		Detail: configs.LogOutputConfig{
			Console: false,
			File:    true,
			Path:    tmpDir,
		},
		Summary: configs.LogOutputConfig{
			Console: false,
			File:    false,
		},
		Rotation: configs.DefaultRotationConfig(),
	}

	logger := NewLoggerWithConfig("test", "1.0.0", config).(*Logger)

	errDetail := ErrorDetail{
		Code:    "ERR_001",
		Message: "Test error",
		Source: ErrorSource{
			Node: "test-node",
		},
		Retryable: true,
	}

	logger.LogError(errDetail)
	logger.Close()
}

func TestConcurrentLogging(t *testing.T) {
	tmpDir := t.TempDir()
	config := &configs.LoggerConfig{
		Detail: configs.LogOutputConfig{
			Console: false,
			File:    true,
			Path:    tmpDir,
		},
		Summary: configs.LogOutputConfig{
			Console: false,
			File:    false,
		},
		Rotation: configs.DefaultRotationConfig(),
	}

	parent := NewLoggerWithConfig("test", "1.0.0", config)

	action := logAction.LoggerAction{
		Action: "concurrent",
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			logger := parent.Clone()
			logger.Info(action, "test")
			logger.Release()
		}(i)
	}

	wg.Wait()
	parent.Close()
}

func TestWithTraceContext(t *testing.T) {
	logger := NewLogger("test", "1.0.0")
	ctx := context.WithValue(context.Background(), "traceId", "trace-123")

	result := logger.WithTraceContext(ctx)
	if result == nil {
		t.Error("Expected logger to be returned")
	}
}

func TestInjectContext(t *testing.T) {
	logger := NewLogger("test", "1.0.0").(*Logger)
	logger.AddMetadata("traceId", "trace-123")

	ctx := logger.InjectContext(context.Background())
	if ctx.Value("traceId") != "trace-123" {
		t.Error("Expected traceId to be injected")
	}
}

func TestDataToString(t *testing.T) {
	if dataToString(nil) != "" {
		t.Error("Expected empty string for nil")
	}

	if dataToString("hello") != "hello" {
		t.Error("Expected string to be returned as-is")
	}
}

func TestAddSuccess(t *testing.T) {
	logger := NewLogger("test", "1.0.0").(*Logger)

	logger.AddSuccess("results", "result1")
	if logger.metadata["results"] != "result1" {
		t.Error("Expected first value to be stored directly")
	}

	logger.AddSuccess("results", "result2")
	arr, ok := logger.metadata["results"].([]any)
	if !ok || len(arr) != 2 {
		t.Error("Expected metadata to be converted to array")
	}
}

func TestFileRotation(t *testing.T) {
	tmpDir := t.TempDir()
	config := &configs.LoggerConfig{
		Detail: configs.LogOutputConfig{
			Console: false,
			File:    true,
			Path:    tmpDir,
		},
		Summary: configs.LogOutputConfig{
			Console: false,
			File:    false,
		},
		Rotation: configs.RotationConfig{
			MaxSize:    1024,
			MaxAge:     1,
			MaxBackups: 2,
			Compress:   false,
		},
	}

	logger := NewLoggerWithConfig("test", "1.0.0", config).(*Logger)

	action := logAction.LoggerAction{
		Action: "test",
	}

	largeData := make([]byte, 500)
	for i := 0; i < 5; i++ {
		logger.Info(action, string(largeData))
	}

	logger.Close()
}

func TestPeriodicFlush(t *testing.T) {
	tmpDir := t.TempDir()
	config := &configs.LoggerConfig{
		Detail: configs.LogOutputConfig{
			Console: false,
			File:    true,
			Path:    tmpDir,
		},
		Summary: configs.LogOutputConfig{
			Console: false,
			File:    false,
		},
		Rotation: configs.DefaultRotationConfig(),
	}

	logger := NewLoggerWithConfig("test", "1.0.0", config).(*Logger)

	action := logAction.LoggerAction{
		Action: "test",
	}

	logger.Info(action, "test message")
	time.Sleep(6 * time.Second)
	logger.Close()
}

func TestCleanupOldFiles(t *testing.T) {
	tmpDir := t.TempDir()

	oldFile := filepath.Join(tmpDir, "old.log")
	os.WriteFile(oldFile, []byte("old"), 0644)

	oldTime := time.Now().AddDate(0, 0, -10)
	os.Chtimes(oldFile, oldTime, oldTime)

	config := &configs.LoggerConfig{
		Detail: configs.LogOutputConfig{
			Console: false,
			File:    true,
			Path:    tmpDir,
		},
		Summary: configs.LogOutputConfig{
			Console: false,
			File:    false,
		},
		Rotation: configs.RotationConfig{
			MaxSize:    1024,
			MaxAge:     7,
			MaxBackups: 2,
			Compress:   false,
		},
	}

	logger := NewLoggerWithConfig("test", "1.0.0", config).(*Logger)

	action := logAction.LoggerAction{
		Action: "test",
	}

	logger.Info(action, "test")

	largeData := make([]byte, 600)
	for i := 0; i < 3; i++ {
		logger.Info(action, string(largeData))
	}

	time.Sleep(100 * time.Millisecond)
	logger.Close()
}

func TestLogWithContext(t *testing.T) {
	logger := NewLogger("test", "1.0.0")
	ctx := SetLogger(context.Background(), logger)

	// Test with valid context
	result := logger.LogWithContext(ctx)
	if result == nil {
		t.Error("Expected logger from context")
	}

	// Test with nil context
	result2 := logger.LogWithContext(nil)
	if result2 == nil {
		t.Error("Expected new logger with nil context")
	}

	// Test with context without logger
	result3 := logger.LogWithContext(context.Background())
	if result3 == nil {
		t.Error("Expected new logger with empty context")
	}
}

func TestSummary(t *testing.T) {
	tmpDir := t.TempDir()
	config := &configs.LoggerConfig{
		Detail: configs.LogOutputConfig{
			Console: false,
			File:    false,
		},
		Summary: configs.LogOutputConfig{
			Console: false,
			File:    true,
			Path:    tmpDir,
		},
		Rotation: configs.DefaultRotationConfig(),
	}

	logger := NewLoggerWithConfig("test", "1.0.0", config).(*Logger)

	action := logAction.LoggerAction{
		Action:            "summary",
		ActionDescription: "Test Summary",
	}

	logger.Summary(LevelInfo, action, map[string]any{"status": "ok"})
	logger.Close()
}

func TestDetailLogging_AllMethods(t *testing.T) {
	tmpDir := t.TempDir()
	config := &configs.LoggerConfig{
		Detail: configs.LogOutputConfig{
			Console: false,
			File:    true,
			Path:    tmpDir,
		},
		Summary: configs.LogOutputConfig{
			Console: false,
			File:    false,
		},
		Rotation: configs.DefaultRotationConfig(),
	}

	logger := NewLoggerWithConfig("test", "1.0.0", config).(*Logger)

	action := logAction.LoggerAction{
		Action: "test",
	}

	logger.InfoDetail(action, "info")
	logger.DebugDetail(action, "debug")
	logger.WarnDetail(action, "warn")
	logger.ErrorDetail(action, "error")

	logger.Close()
}

func TestSummaryLogging_AllMethods(t *testing.T) {
	tmpDir := t.TempDir()
	config := &configs.LoggerConfig{
		Detail: configs.LogOutputConfig{
			Console: false,
			File:    false,
		},
		Summary: configs.LogOutputConfig{
			Console: false,
			File:    true,
			Path:    tmpDir,
		},
		Rotation: configs.DefaultRotationConfig(),
	}

	logger := NewLoggerWithConfig("test", "1.0.0", config).(*Logger)

	action := logAction.LoggerAction{
		Action: "test",
	}

	logger.InfoSummary(action, map[string]any{"status": "ok"})
	logger.ErrorSummary(action, map[string]any{"status": "error"})

	logger.Close()
}

func TestStartTransaction(t *testing.T) {
	logger := NewLogger("test", "1.0.0").(*Logger)

	logger.StartTransaction("txn-123", "sess-456")
	if logger.transactionID != "txn-123" {
		t.Error("Expected transaction ID to be set")
	}
	if logger.sessionID != "sess-456" {
		t.Error("Expected session ID to be set")
	}
}

func TestFlushBuffers(t *testing.T) {
	tmpDir := t.TempDir()
	config := &configs.LoggerConfig{
		Detail: configs.LogOutputConfig{
			Console: false,
			File:    true,
			Path:    tmpDir,
		},
		Summary: configs.LogOutputConfig{
			Console: false,
			File:    false,
		},
		Rotation: configs.DefaultRotationConfig(),
	}

	logger := NewLoggerWithConfig("test", "1.0.0", config).(*Logger)

	action := logAction.LoggerAction{
		Action: "test",
	}

	logger.Info(action, "test message")
	logger.FlushBuffers()
	logger.Close()
}

func TestMasking(t *testing.T) {
	tmpDir := t.TempDir()
	config := &configs.LoggerConfig{
		Detail: configs.LogOutputConfig{
			Console: false,
			File:    true,
			Path:    tmpDir,
		},
		Summary: configs.LogOutputConfig{
			Console: false,
			File:    false,
		},
		Rotation: configs.DefaultRotationConfig(),
	}

	logger := NewLoggerWithConfig("test", "1.0.0", config)

	action := logAction.LoggerAction{
		Action: "test",
	}

	data := map[string]string{
		"password": "secret123",
		"token":    "abc123xyz",
		"email":    "test@example.com",
		"card":     "4111111111111111",
	}

	maskingRules := []MaskingRule{
		{Field: "password", Type: MaskingTypeFull},
		{Field: "token", Type: MaskingTypeFull},
		{Field: "email", Type: MaskingTypeEmail},
		{Field: "card", Type: MaskingTypeCard},
	}

	logger.Info(action, data, maskingRules...)
	logger.Close()
}

func TestLogError_WithMasking(t *testing.T) {
	tmpDir := t.TempDir()
	config := &configs.LoggerConfig{
		Detail: configs.LogOutputConfig{
			Console: false,
			File:    true,
			Path:    tmpDir,
		},
		Summary: configs.LogOutputConfig{
			Console: false,
			File:    false,
		},
		Rotation: configs.DefaultRotationConfig(),
	}

	logger := NewLoggerWithConfig("test", "1.0.0", config).(*Logger)

	errDetail := ErrorDetail{
		Code:    "ERR_001",
		Message: "Sensitive error",
		Details: map[string]interface{}{
			"password": "secret",
		},
		Retryable: false,
	}

	maskingRules := []MaskingRule{
		{Field: "password", Type: MaskingTypeFull},
	}

	logger.LogError(errDetail, maskingRules...)
	logger.Close()
}

func TestFileCompression(t *testing.T) {
	tmpDir := t.TempDir()
	config := &configs.LoggerConfig{
		Detail: configs.LogOutputConfig{
			Console: false,
			File:    true,
			Path:    tmpDir,
		},
		Summary: configs.LogOutputConfig{
			Console: false,
			File:    false,
		},
		Rotation: configs.RotationConfig{
			MaxSize:    500,
			MaxAge:     1,
			MaxBackups: 2,
			Compress:   true,
		},
	}

	logger := NewLoggerWithConfig("test", "1.0.0", config).(*Logger)

	action := logAction.LoggerAction{
		Action: "test",
	}

	largeData := make([]byte, 300)
	for i := 0; i < 3; i++ {
		logger.Info(action, string(largeData))
	}

	time.Sleep(200 * time.Millisecond)
	logger.Close()
	time.Sleep(200 * time.Millisecond)
}

func TestConsoleOutput(t *testing.T) {
	config := &configs.LoggerConfig{
		Detail: configs.LogOutputConfig{
			Console: true,
			File:    false,
		},
		Summary: configs.LogOutputConfig{
			Console: true,
			File:    false,
		},
		Rotation: configs.DefaultRotationConfig(),
	}

	logger := NewLoggerWithConfig("test", "1.0.0", config)

	action := logAction.LoggerAction{
		Action: "test",
	}

	logger.Info(action, "console output test")
	logger.Close()
}

func TestDataToString_WithStruct(t *testing.T) {
	data := map[string]string{"key": "value"}
	result := dataToString(data)
	if result == "" {
		t.Error("Expected non-empty string")
	}
}

func TestWithTraceContext_EmptyValues(t *testing.T) {
	logger := NewLogger("test", "1.0.0")
	ctx := context.WithValue(context.Background(), "traceId", "")

	logger.WithTraceContext(ctx)

	l := logger.(*Logger)
	if l.metadata["traceId"] != nil {
		t.Error("Expected empty traceId not to be set")
	}
}

func TestInjectContext_EmptyValues(t *testing.T) {
	logger := NewLogger("test", "1.0.0").(*Logger)
	ctx := logger.InjectContext(context.Background())
	if ctx == nil {
		t.Error("Expected context to be returned")
	}
}
