// Package appwrite is the shared server-side Appwrite access layer. It wraps
// the official Appwrite Go SDK so handlers never hand-roll REST calls: typed
// list/get/create/update/delete, query builders, and SDK errors mapped to the
// httpx error contract.
//
// Connection settings are explicit. The package embeds no endpoint, project or
// database identifiers; callers pass a Config or supply the documented
// environment variables.
package appwrite

import (
	"errors"
	"os"
	"strings"

	sdk "github.com/appwrite/sdk-for-go/client"
	"github.com/appwrite/sdk-for-go/tablesdb"
	"github.com/open-runtimes/types-for-go/v4/openruntimes"
)

// DefaultResponseFormat is the Appwrite API response format requested by the
// client. It is a protocol version, not a project identifier.
const DefaultResponseFormat = "2.6.1"

// ResponseFormat is kept for compatibility with v0.1.x callers. New code
// should set Config.ResponseFormat or rely on DefaultResponseFormat.
const ResponseFormat = DefaultResponseFormat

// Environment variables read by ConfigFromEnv. The APPWRITE_FUNCTION_* names
// are injected automatically by the Appwrite function runtime; the generic
// names let non-function jobs use the same package.
const (
	EnvEndpoint          = "APPWRITE_ENDPOINT"
	EnvProjectID         = "APPWRITE_PROJECT_ID"
	EnvDatabaseID        = "APPWRITE_DATABASE_ID"
	EnvFunctionEndpoint  = "APPWRITE_FUNCTION_API_ENDPOINT"
	EnvFunctionProjectID = "APPWRITE_FUNCTION_PROJECT_ID"
)

// Configuration errors. They are safe to return from a handler: httpx.Fail
// logs the detail privately and responds with a generic 500 body.
var (
	ErrMissingEndpoint   = errors.New("appwrite: endpoint is required")
	ErrMissingProjectID  = errors.New("appwrite: project ID is required")
	ErrMissingDatabaseID = errors.New("appwrite: database ID is required")
)

// Config is the explicit Appwrite connection configuration.
//
// Endpoint, ProjectID and DatabaseID have no defaults. APIKey is optional for
// read-only clients but is required for operations that need a server key.
type Config struct {
	Endpoint       string
	ProjectID      string
	DatabaseID     string
	APIKey         string
	ResponseFormat string
}

// Validate checks the full tables configuration.
func (c Config) Validate() error {
	if err := c.validateClient(); err != nil {
		return err
	}
	if strings.TrimSpace(c.DatabaseID) == "" {
		return ErrMissingDatabaseID
	}
	return nil
}

func (c Config) validateClient() error {
	if strings.TrimSpace(c.Endpoint) == "" {
		return ErrMissingEndpoint
	}
	if strings.TrimSpace(c.ProjectID) == "" {
		return ErrMissingProjectID
	}
	return nil
}

// withDefaults trims whitespace, normalises the endpoint and fills the
// protocol-level response format. It never invents an endpoint, project or
// database.
func (c Config) withDefaults() Config {
	c.Endpoint = strings.TrimRight(strings.TrimSpace(c.Endpoint), "/")
	c.ProjectID = strings.TrimSpace(c.ProjectID)
	c.DatabaseID = strings.TrimSpace(c.DatabaseID)
	c.APIKey = strings.TrimSpace(c.APIKey)
	if strings.TrimSpace(c.ResponseFormat) == "" {
		c.ResponseFormat = DefaultResponseFormat
	}
	return c
}

// ConfigFromEnv builds a Config from the runtime environment and the caller's
// short-lived execution key. It performs no fallback to a hard-coded project.
func ConfigFromEnv(ctx openruntimes.Context) Config {
	return Config{
		Endpoint:   firstNonEmpty(os.Getenv(EnvEndpoint), os.Getenv(EnvFunctionEndpoint)),
		ProjectID:  firstNonEmpty(os.Getenv(EnvProjectID), os.Getenv(EnvFunctionProjectID)),
		DatabaseID: os.Getenv(EnvDatabaseID),
		APIKey:     headerValue(ctx.Req.Headers, "x-appwrite-key"),
	}
}

// NewClient builds a server SDK client from explicit configuration.
func NewClient(cfg Config) (sdk.Client, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validateClient(); err != nil {
		return sdk.Client{}, err
	}

	clt := sdk.New()
	clt.Endpoint = cfg.Endpoint
	clt.AddHeader("X-Appwrite-Project", cfg.ProjectID)
	if cfg.APIKey != "" {
		clt.AddHeader("X-Appwrite-Key", cfg.APIKey)
	}
	clt.AddHeader("X-Appwrite-Response-Format", cfg.ResponseFormat)
	return clt, nil
}

// NewTables builds a TablesDB service from explicit configuration.
func NewTables(cfg Config) (*tablesdb.TablesDB, error) {
	cfg = cfg.withDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	clt, err := NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return tablesdb.New(clt), nil
}

// Client is the v0.1.x convenience constructor. It reads ConfigFromEnv and, on
// invalid configuration, logs privately and returns an unconfigured client so
// the caller's request fails as an upstream error instead of using a default
// project. Prefer NewClient with an explicit Config.
func Client(ctx openruntimes.Context) sdk.Client {
	clt, err := NewClient(ConfigFromEnv(ctx))
	if err != nil {
		ctx.Error("appwrite: " + err.Error())
		// Return a usable struct with no endpoint rather than the SDK's cloud
		// default; requests fail closed instead of hitting another project.
		empty := sdk.New()
		empty.Endpoint = ""
		return empty
	}
	return clt
}

// Tables is the v0.1.x convenience constructor. Prefer NewTables with an
// explicit Config when the database id is not read from the environment.
func Tables(ctx openruntimes.Context) *tablesdb.TablesDB {
	return tablesdb.New(Client(ctx))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func headerValue(headers map[string]string, key string) string {
	if value := strings.TrimSpace(headers[key]); value != "" {
		return value
	}
	for name, value := range headers {
		if strings.EqualFold(name, key) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
