package config

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

type AppConfig struct {
	ServiceName string
	Version     string

	Port         string
	DatabaseURL  string
	BaseURL      string
	OidcConfig   OpenidConfiguration
	LoggerConfig LoggerConfig
	RedisConfig  RedisConfig
}

type LogOutputConfig struct {
	Path    string
	Console bool
	File    bool
}

type RedisConfig struct {
	Addr     string `json:"addr"`
	Password string `json:"password"`
	DB       int    `json:"db"`
}

// RotationConfig defines log rotation settings
type RotationConfig struct {
	MaxSize    int64 // Maximum size in bytes before rotation (default: 100MB)
	MaxAge     int   // Maximum number of days to retain old logs (default: 30)
	MaxBackups int   // Maximum number of backup files to keep (default: 10)
	Compress   bool  // Whether to compress rotated files (default: true)
}

type LoggerConfig struct {
	Summary  LogOutputConfig
	Detail   LogOutputConfig
	Rotation RotationConfig
}

type OpenidConfiguration struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
}
type ConfigManager struct {
	// Configuration fields go here
	mu   sync.RWMutex
	data *AppConfig
}

func NewConfigManager() *AppConfig {
	databaseURL := os.Getenv("MONGO_URI")
	baseURL := os.Getenv("BASE_URL")
	Port := os.Getenv("PORT")
	if Port == "" {
		Port = "8080"
	}
	serviceName := os.Getenv("SERVICE_NAME")
	version := os.Getenv("VERSION")
	redisHost := os.Getenv("REDIS_HOST")
	redisPassword := os.Getenv("REDIS_PASSWORD")
	var redisDB int = 0

	cm := &ConfigManager{
		data: &AppConfig{
			Port:        Port,
			ServiceName: serviceName,
			Version:     version,
			BaseURL:     baseURL,
			DatabaseURL: databaseURL,
			OidcConfig:  OpenidConfiguration{},
			LoggerConfig: LoggerConfig{
				Summary: LogOutputConfig{Path: "./logs/summary/", Console: true, File: true},
				Detail:  LogOutputConfig{Path: "./logs/detail/", Console: true, File: true},
				Rotation: RotationConfig{
					MaxSize:    50 * 1024 * 1024, // 50MB
					MaxAge:     7,                // 7 days
					MaxBackups: 5,
					Compress:   true,
				},
			},
		},
	}

	if redisHost != "" {
		cm.data.RedisConfig = RedisConfig{
			Addr:     redisHost,
			Password: redisPassword,
			DB:       redisDB,
		}
	}

	return cm.data
}

func (cm *ConfigManager) GetConfig() *AppConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return cm.data
}

func (cm *AppConfig) LoadDefaults() error {
	if cm.BaseURL == "" {
		cm.BaseURL = "http://localhost:" + cm.Port
	}
	config := OpenidConfiguration{
		Issuer:                 cm.BaseURL,
		AuthorizationEndpoint:  cm.BaseURL + "/authorize",
		TokenEndpoint:          cm.BaseURL + "/token",
		UserinfoEndpoint:       cm.BaseURL + "/userinfo",
		RevocationEndpoint:     cm.BaseURL + "/revoke",
		JwksURI:                cm.BaseURL + "/.well-known/jwks.json",
		ResponseTypesSupported: []string{"code"},
		ResponseModesSupported: []string{"query", "fragment", "form_post"},
		SubjectTypesSupported:  []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{
			"RS256",
		},
		ScopesSupported: []string{
			"openid",
			"profile",
			"email",
		},
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic",
			"client_secret_post",
			"private_key_jwt",
			"none",
		},
		ClaimsSupported: []string{
			"aud",
			"email",
			"email_verified",
			"exp",
			"family_name",
			"given_name",
			"iat",
			"iss",
			"name",
			"picture",
			"sub",
		},
		CodeChallengeMethodsSupported: []string{
			"plain",
			"S256",
		},
		GrantTypesSupported: []string{
			"authorization_code",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:jwt-bearer",
		},
	}
	if cm.OidcConfig.Issuer == "" {
		cm.OidcConfig.Issuer = config.Issuer
	}
	if cm.OidcConfig.AuthorizationEndpoint == "" {
		cm.OidcConfig.AuthorizationEndpoint = config.AuthorizationEndpoint
	}
	if cm.OidcConfig.TokenEndpoint == "" {
		cm.OidcConfig.TokenEndpoint = config.TokenEndpoint
	}
	if cm.OidcConfig.UserinfoEndpoint == "" {
		cm.OidcConfig.UserinfoEndpoint = config.UserinfoEndpoint
	}
	if cm.OidcConfig.RevocationEndpoint == "" {
		cm.OidcConfig.RevocationEndpoint = config.RevocationEndpoint
	}
	if cm.OidcConfig.JwksURI == "" {
		cm.OidcConfig.JwksURI = config.JwksURI
	}
	if len(cm.OidcConfig.ResponseTypesSupported) == 0 {
		cm.OidcConfig.ResponseTypesSupported = config.ResponseTypesSupported
	}
	if len(cm.OidcConfig.ResponseModesSupported) == 0 {
		cm.OidcConfig.ResponseModesSupported = config.ResponseModesSupported
	}
	if len(cm.OidcConfig.SubjectTypesSupported) == 0 {
		cm.OidcConfig.SubjectTypesSupported = config.SubjectTypesSupported
	}
	if len(cm.OidcConfig.IDTokenSigningAlgValuesSupported) == 0 {
		cm.OidcConfig.IDTokenSigningAlgValuesSupported = config.IDTokenSigningAlgValuesSupported
	}
	if len(cm.OidcConfig.ScopesSupported) == 0 {
		cm.OidcConfig.ScopesSupported = config.ScopesSupported
	}
	if len(cm.OidcConfig.TokenEndpointAuthMethodsSupported) == 0 {
		cm.OidcConfig.TokenEndpointAuthMethodsSupported = config.TokenEndpointAuthMethodsSupported
	}
	if len(cm.OidcConfig.ClaimsSupported) == 0 {
		cm.OidcConfig.ClaimsSupported = config.ClaimsSupported
	}
	if len(cm.OidcConfig.CodeChallengeMethodsSupported) == 0 {
		cm.OidcConfig.CodeChallengeMethodsSupported = config.CodeChallengeMethodsSupported
	}
	if len(cm.OidcConfig.GrantTypesSupported) == 0 {
		cm.OidcConfig.GrantTypesSupported = config.GrantTypesSupported
	}

	fmt.Println("load config...")
	return nil
}

func (c *ConfigManager) SetConfig(newConfig *AppConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = newConfig
}

func (o *OpenidConfiguration) ToJSON() ([]byte, error) {
	return json.Marshal(o)
}

func (o *OpenidConfiguration) GetOIDC() OpenidConfiguration {
	return *o
}

func (o *OpenidConfiguration) ValidateIDTokenSigningAlgValuesSupported(alg string) bool {
	for _, a := range o.IDTokenSigningAlgValuesSupported {
		if a == alg {
			return true
		}
	}
	return false
}

func (o *OpenidConfiguration) ValidateGrantTypesSupported(grantType string) bool {
	for _, g := range o.GrantTypesSupported {
		if g == grantType {
			return true
		}
	}
	return false
}

func (o *OpenidConfiguration) ValidateTokenEndpointAuthMethodsSupported(method string) bool {
	for _, m := range o.TokenEndpointAuthMethodsSupported {
		if m == method {
			return true
		}
	}
	return false
}

// DefaultRotationConfig returns default rotation settings
func DefaultRotationConfig() RotationConfig {
	return RotationConfig{
		MaxSize:    100 * 1024 * 1024, // 100MB
		MaxAge:     30,                // 30 days
		MaxBackups: 10,
		Compress:   true,
	}
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
		Rotation: DefaultRotationConfig(),
	}
}
