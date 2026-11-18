// Package botcheck verifies the bot challenge a browser solved before a guest
// write (PAR-1211a): public booking, shop enquiries and chat starts.
//
// Two providers are supported, chosen by configuration:
//
//   - "turnstile": Cloudflare Turnstile (siteverify returns success and the
//     action the widget was rendered with);
//   - "recaptcha": Google reCAPTCHA v3 (siteverify also returns a 0..1 score,
//     which must reach MinScore).
//
// The check is server-side only. A token is single-use at the provider, so a
// replayed token fails there. When no provider or secret is configured the
// check is switched off and Require returns nil: a shop can run without a
// challenge, exactly as before, until keys are added.
//
// When the provider cannot be reached the write is refused with 503 unless
// FailOpen is set; a bot that can make siteverify fail must not get through.
package botcheck

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ModdingFriendly/appwrite-library/httpx"
)

// Providers.
const (
	ProviderTurnstile = "turnstile"
	ProviderRecaptcha = "recaptcha"
)

// Environment variables read by FromEnv.
const (
	EnvProvider = "REPARIX_BOT_CHALLENGE_PROVIDER"
	EnvSecret   = "REPARIX_BOT_CHALLENGE_SECRET"
	EnvMinScore = "REPARIX_BOT_CHALLENGE_MIN_SCORE"
	EnvFailOpen = "REPARIX_BOT_CHALLENGE_FAIL_OPEN"
)

// DefaultMinScore is the reCAPTCHA v3 pass mark when none is configured.
const DefaultMinScore = 0.5

var endpoints = map[string]string{
	ProviderTurnstile: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	ProviderRecaptcha: "https://www.google.com/recaptcha/api/siteverify",
}

// Config selects and configures the provider. The zero value is disabled.
type Config struct {
	Provider string
	Secret   string
	// MinScore is the reCAPTCHA v3 pass mark (0..1). Ignored for Turnstile.
	MinScore float64
	// FailOpen lets a write through when the provider cannot be reached.
	FailOpen bool
	// Endpoint overrides the provider's siteverify URL (tests).
	Endpoint string
	// Client is the HTTP client; nil uses one with a 5 second timeout.
	Client *http.Client
}

// FromEnv reads the configuration from the environment. An unknown provider
// is returned as is, so Require reports it instead of silently switching off.
func FromEnv(getenv func(string) string) Config {
	if getenv == nil {
		getenv = os.Getenv
	}
	cfg := Config{
		Provider: strings.ToLower(strings.TrimSpace(getenv(EnvProvider))),
		Secret:   strings.TrimSpace(getenv(EnvSecret)),
		MinScore: DefaultMinScore,
	}
	if raw := strings.TrimSpace(getenv(EnvMinScore)); raw != "" {
		if v, err := strconv.ParseFloat(raw, 64); err == nil && v >= 0 && v <= 1 {
			cfg.MinScore = v
		}
	}
	switch strings.ToLower(strings.TrimSpace(getenv(EnvFailOpen))) {
	case "1", "true", "yes":
		cfg.FailOpen = true
	}
	return cfg
}

// Enabled reports whether a challenge is required.
func (c Config) Enabled() bool { return c.Provider != "" && c.Secret != "" }

// Result is the provider's answer.
type Result struct {
	OK     bool
	Score  float64
	Action string
	Codes  []string
}

// Errors returned by Verify.
var (
	ErrMissingToken = errors.New("botcheck: no challenge token")
	ErrUnknown      = errors.New("botcheck: unknown provider")
	ErrUnavailable  = errors.New("botcheck: provider unavailable")
)

// MaxTokenLength bounds the token sent to the provider (both document ~2 KB).
const MaxTokenLength = 4096

// Verify asks the provider whether token is a fresh, solved challenge for the
// expected action. remoteIP is optional. A failed challenge is a Result with
// OK false and a nil error; an error means the answer could not be obtained.
func Verify(ctx context.Context, cfg Config, token, remoteIP, action string) (Result, error) {
	token = strings.TrimSpace(token)
	if token == "" || len(token) > MaxTokenLength {
		return Result{}, ErrMissingToken
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = endpoints[cfg.Provider]
	}
	if endpoint == "" {
		return Result{}, ErrUnknown
	}
	form := url.Values{"secret": {cfg.Secret}, "response": {token}}
	if ip := strings.TrimSpace(remoteIP); ip != "" {
		form.Set("remoteip", ip)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Result{}, ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	res, err := client.Do(req)
	if err != nil {
		return Result{}, ErrUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return Result{}, ErrUnavailable
	}
	var body struct {
		Success bool     `json:"success"`
		Score   *float64 `json:"score"`
		Action  string   `json:"action"`
		Codes   []string `json:"error-codes"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&body); err != nil {
		return Result{}, ErrUnavailable
	}
	result := Result{OK: body.Success, Action: body.Action, Codes: body.Codes}
	if body.Score != nil {
		result.Score = *body.Score
	}
	if action != "" && body.Action != "" && body.Action != action {
		result.OK = false
		result.Codes = append(result.Codes, "action-mismatch")
	}
	if cfg.Provider == ProviderRecaptcha {
		min := cfg.MinScore
		if min == 0 {
			min = DefaultMinScore
		}
		if body.Score == nil || *body.Score < min {
			result.OK = false
			result.Codes = append(result.Codes, "score-too-low")
		}
	}
	return result, nil
}

// Require is the route guard: nil when the challenge is switched off or was
// passed, otherwise an httpx error the route returns as is.
//
//   - 400 bot_challenge_required: no token was sent;
//   - 403 bot_challenge_failed: the provider rejected it;
//   - 503 bot_challenge_unavailable: the provider could not be reached (unless FailOpen);
//   - 500 bot_challenge_misconfigured: the provider name is not known.
func Require(ctx context.Context, cfg Config, token, remoteIP, action string) error {
	if !cfg.Enabled() {
		return nil
	}
	result, err := Verify(ctx, cfg, token, remoteIP, action)
	switch {
	case errors.Is(err, ErrMissingToken):
		return &httpx.Error{Status: 400, Code: "bot_challenge_required", Message: "complete the anti-spam check and try again", Params: map[string]any{"field": "challenge_token"}}
	case errors.Is(err, ErrUnknown):
		return &httpx.Error{Status: 500, Code: "bot_challenge_misconfigured", Message: "the anti-spam check is not configured correctly"}
	case err != nil:
		if cfg.FailOpen {
			return nil
		}
		return &httpx.Error{Status: 503, Code: "bot_challenge_unavailable", Message: "the anti-spam check is unavailable, try again shortly"}
	case !result.OK:
		return &httpx.Error{Status: 403, Code: "bot_challenge_failed", Message: "the anti-spam check failed, try again", Params: map[string]any{"codes": result.Codes}}
	}
	return nil
}
