package botcheck_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ModdingFriendly/appwrite-library/httpx"
	"github.com/ModdingFriendly/appwrite-library/reparix/botcheck"
)

func provider(t *testing.T, status int, body string, seen *map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if seen != nil {
			*seen = map[string]string{"secret": r.PostForm.Get("secret"), "response": r.PostForm.Get("response"), "remoteip": r.PostForm.Get("remoteip")}
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func code(err error) string {
	var e *httpx.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestFromEnvAndDisabledByDefault(t *testing.T) {
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	if botcheck.FromEnv(get).Enabled() {
		t.Fatal("enabled with no configuration")
	}
	if err := botcheck.Require(context.Background(), botcheck.FromEnv(get), "", "", "booking"); err != nil {
		t.Fatalf("a switched-off check refused: %v", err)
	}
	env[botcheck.EnvProvider] = " Turnstile "
	if botcheck.FromEnv(get).Enabled() {
		t.Fatal("enabled without a secret")
	}
	env[botcheck.EnvSecret] = "s3cret"
	env[botcheck.EnvMinScore] = "0.7"
	env[botcheck.EnvFailOpen] = "true"
	cfg := botcheck.FromEnv(get)
	if !cfg.Enabled() || cfg.Provider != "turnstile" || cfg.MinScore != 0.7 || !cfg.FailOpen {
		t.Fatalf("config: %+v", cfg)
	}
	env[botcheck.EnvMinScore] = "7"
	if botcheck.FromEnv(get).MinScore != botcheck.DefaultMinScore {
		t.Fatal("an out-of-range score was accepted")
	}
}

func TestTurnstilePassAndFail(t *testing.T) {
	var seen map[string]string
	ok := provider(t, 200, `{"success":true,"action":"booking"}`, &seen)
	cfg := botcheck.Config{Provider: botcheck.ProviderTurnstile, Secret: "s", Endpoint: ok.URL}
	if err := botcheck.Require(context.Background(), cfg, "tok", "203.0.113.9", "booking"); err != nil {
		t.Fatal(err)
	}
	if seen["secret"] != "s" || seen["response"] != "tok" || seen["remoteip"] != "203.0.113.9" {
		t.Fatalf("siteverify form: %v", seen)
	}
	if err := botcheck.Require(context.Background(), cfg, "tok", "", "chat_start"); code(err) != "bot_challenge_failed" {
		t.Fatalf("a token for another action passed: %v", err)
	}
	bad := provider(t, 200, `{"success":false,"error-codes":["timeout-or-duplicate"]}`, nil)
	cfg.Endpoint = bad.URL
	err := botcheck.Require(context.Background(), cfg, "tok", "", "booking")
	if code(err) != "bot_challenge_failed" {
		t.Fatalf("a rejected token passed: %v", err)
	}
	if code(botcheck.Require(context.Background(), cfg, "  ", "", "booking")) != "bot_challenge_required" {
		t.Fatal("a missing token was not reported")
	}
}

func TestRecaptchaNeedsTheScore(t *testing.T) {
	low := provider(t, 200, `{"success":true,"score":0.3,"action":"booking"}`, nil)
	cfg := botcheck.Config{Provider: botcheck.ProviderRecaptcha, Secret: "s", Endpoint: low.URL}
	if code(botcheck.Require(context.Background(), cfg, "tok", "", "booking")) != "bot_challenge_failed" {
		t.Fatal("a low score passed")
	}
	high := provider(t, 200, `{"success":true,"score":0.9,"action":"booking"}`, nil)
	cfg.Endpoint = high.URL
	if err := botcheck.Require(context.Background(), cfg, "tok", "", "booking"); err != nil {
		t.Fatal(err)
	}
	noScore := provider(t, 200, `{"success":true}`, nil)
	cfg.Endpoint = noScore.URL
	if code(botcheck.Require(context.Background(), cfg, "tok", "", "booking")) != "bot_challenge_failed" {
		t.Fatal("a reCAPTCHA answer with no score passed")
	}
}

func TestUnavailableFailsClosedUnlessFailOpen(t *testing.T) {
	down := provider(t, 500, `oops`, nil)
	cfg := botcheck.Config{Provider: botcheck.ProviderTurnstile, Secret: "s", Endpoint: down.URL}
	if code(botcheck.Require(context.Background(), cfg, "tok", "", "booking")) != "bot_challenge_unavailable" {
		t.Fatal("an unreachable provider let the write through")
	}
	cfg.FailOpen = true
	if err := botcheck.Require(context.Background(), cfg, "tok", "", "booking"); err != nil {
		t.Fatalf("fail-open refused: %v", err)
	}
	garbled := provider(t, 200, `not json`, nil)
	cfg = botcheck.Config{Provider: botcheck.ProviderTurnstile, Secret: "s", Endpoint: garbled.URL}
	if code(botcheck.Require(context.Background(), cfg, "tok", "", "booking")) != "bot_challenge_unavailable" {
		t.Fatal("a garbled answer let the write through")
	}
	unknown := botcheck.Config{Provider: "hcaptcha", Secret: "s"}
	if code(botcheck.Require(context.Background(), unknown, "tok", "", "booking")) != "bot_challenge_misconfigured" {
		t.Fatal("an unknown provider was not reported")
	}
}
