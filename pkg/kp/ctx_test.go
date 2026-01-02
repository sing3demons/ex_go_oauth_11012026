package kp

import (
	"bytes"
	"encoding/xml"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sing3demons/oauth/kp/internal/config"
	"github.com/sing3demons/oauth/kp/pkg/logger"
)

func TestCtx_Body_JSON(t *testing.T) {
	cfg := &config.AppConfig{}

	tests := []struct {
		name    string
		body    string
		want    map[string]any
		wantErr bool
	}{
		{
			name: "Valid JSON",
			body: `{"name":"test","age":25}`,
			want: map[string]any{"name": "test", "age": float64(25)},
		},
		{
			name:    "Invalid JSON",
			body:    `{invalid}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")

			ctx := &Ctx{
				Res: httptest.NewRecorder(),
				Req: req,
				Cfg: cfg,
			}

			var result map[string]any
			err := ctx.Bind(&result)

			if (err != nil) != tt.wantErr {
				t.Errorf("Body() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if result["name"] != tt.want["name"] {
					t.Errorf("got %v, want %v", result, tt.want)
				}
			}
		})
	}
}

func TestCtx_Body_XML(t *testing.T) {
	cfg := &config.AppConfig{}

	type Person struct {
		XMLName xml.Name `xml:"person"`
		Name    string   `xml:"name"`
		Age     int      `xml:"age"`
	}

	xmlBody := `<?xml version="1.0"?><person><name>John</name><age>30</age></person>`

	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(xmlBody))
	req.Header.Set("Content-Type", "application/xml")

	ctx := &Ctx{
		Res: httptest.NewRecorder(),
		Req: req,
		Cfg: cfg,
	}

	var result Person
	err := ctx.Bind(&result)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Name != "John" || result.Age != 30 {
		t.Errorf("got %+v, want Name=John Age=30", result)
	}
}

func TestCtx_Body_Form(t *testing.T) {
	cfg := &config.AppConfig{}

	formData := url.Values{}
	formData.Set("username", "john")
	formData.Set("password", "secret")

	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	ctx := &Ctx{
		Res: httptest.NewRecorder(),
		Req: req,
		Cfg: cfg,
	}

	var result map[string]string
	err := ctx.Bind(&result)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result["username"] != "john" || result["password"] != "secret" {
		t.Errorf("got %v, want username=john password=secret", result)
	}
}

func TestCtx_Body_MultipartForm(t *testing.T) {
	cfg := &config.AppConfig{}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	writer.WriteField("username", "john")
	writer.WriteField("email", "john@example.com")

	// Add a file
	fileWriter, _ := writer.CreateFormFile("avatar", "avatar.jpg")
	fileWriter.Write([]byte("fake image data"))

	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/test", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	ctx := &Ctx{
		Res: httptest.NewRecorder(),
		Req: req,
		Cfg: cfg,
	}

	var result map[string]any
	err := ctx.Bind(&result)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result["username"] != "john" {
		t.Errorf("got username=%v, want john", result["username"])
	}

	// Check file info
	files := result["_files"].(map[string]any)
	if files["avatar"] == nil {
		t.Error("expected avatar file info")
	}
}

func TestCtx_Body_PlainText(t *testing.T) {
	cfg := &config.AppConfig{}

	textBody := "Hello, World!"

	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(textBody))
	req.Header.Set("Content-Type", "text/plain")

	ctx := &Ctx{
		Res: httptest.NewRecorder(),
		Req: req,
		Cfg: cfg,
	}

	var result string
	err := ctx.Bind(&result)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != textBody {
		t.Errorf("got %q, want %q", result, textBody)
	}
}
func TestCtx_GetFile(t *testing.T) {
	cfg := &config.AppConfig{}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	fileWriter, _ := writer.CreateFormFile("document", "test.pdf")
	fileWriter.Write([]byte("PDF content"))
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	ctx := &Ctx{
		Res: httptest.NewRecorder(),
		Req: req,
		Cfg: cfg,
	}

	file, err := ctx.GetFile("document")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if file.Filename != "test.pdf" {
		t.Errorf("got filename %q, want test.pdf", file.Filename)
	}
}

func TestCtx_SessionID_Idempotent(t *testing.T) {
	cfg := &config.AppConfig{ServiceName: "test", Version: "1.0"}
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	ctx := &Ctx{
		Res: httptest.NewRecorder(),
		Req: req,
		Cfg: cfg,
		Log: logger.NewLogger(cfg.ServiceName, cfg.Version),
	}

	// First call
	sid1 := ctx.SessionID()

	// Second call should return same value
	sid2 := ctx.SessionID()

	if sid1 != sid2 {
		t.Errorf("SessionID() not idempotent: %q != %q", sid1, sid2)
	}
}

func TestCtx_TransactionID_Idempotent(t *testing.T) {
	cfg := &config.AppConfig{ServiceName: "test", Version: "1.0"}
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	ctx := &Ctx{
		Res: httptest.NewRecorder(),
		Req: req,
		Cfg: cfg,
		Log: logger.NewLogger(cfg.ServiceName, cfg.Version),
	}

	// First call
	tid1 := ctx.TransactionID()

	// Second call should return same value
	tid2 := ctx.TransactionID()

	if tid1 != tid2 {
		t.Errorf("TransactionID() not idempotent: %q != %q", tid1, tid2)
	}
}

func trimString(s string) string {
	return strings.TrimSpace(s)
}
