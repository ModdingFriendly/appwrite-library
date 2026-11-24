package credentials

import (
	"encoding/hex"
	"os"
	"testing"
)

func TestOpensLegacyFixtures(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	old, had := os.LookupEnv("SECRET_HASH")
	if err := os.Setenv("SECRET_HASH", hex.EncodeToString(key)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("SECRET_HASH", old)
		} else {
			_ = os.Unsetenv("SECRET_HASH")
		}
	})

	var integration struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	const integrationFixture = "v1:AAECAwQFBgcICQoLPCC1d6yArG/SKPOpi8seBPui8kaVVjwQUQKL8T9FItFtecuS255h/RfWGpmqvQpehyEU+Cizjqla9Fh8bMGIInSfZjmv0hNl8j8EWSGFCw=="
	if err := OpenIntegrationJSON("team-fixture", "fedex", integrationFixture, &integration); err != nil {
		t.Fatal(err)
	}
	if integration.ClientID != "fixture-client" || integration.ClientSecret != "fixture-secret" {
		t.Fatalf("unexpected integration value: %#v", integration)
	}

	var messaging struct {
		Password string `json:"password"`
		Enabled  bool   `json:"enabled"`
	}
	const messagingFixture = "v1:AAECAwQFBgcICQoLPCCmeraWtXT/JbWxk48RFfej9VHdCz4PSxCK93lLLJBkfs+ew6R2uk7QDZjt+io9Faxszl4acSyOrycKGHc="
	if err := OpenMessagingJSON("team-fixture", "sms", "smsgate", messagingFixture, &messaging); err != nil {
		t.Fatal(err)
	}
	if messaging.Password != "fixture-password" || !messaging.Enabled {
		t.Fatalf("unexpected messaging value: %#v", messaging)
	}
}

func TestContextBinding(t *testing.T) {
	t.Setenv("SECRET_HASH", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	for _, tc := range []struct {
		seal func() (string, error)
		open func(string) error
	}{
		{func() (string, error) { return SealIntegrationJSON("team", "fedex", map[string]string{"x": "y"}) }, func(v string) error { var x map[string]string; return OpenIntegrationJSON("other", "fedex", v, &x) }},
		{func() (string, error) {
			return SealMessagingJSON("team", "sms", "smsgate", map[string]string{"x": "y"})
		}, func(v string) error {
			var x map[string]string
			return OpenMessagingJSON("team", "whatsapp", "smsgate", v, &x)
		}},
	} {
		v, err := tc.seal()
		if err != nil {
			t.Fatal(err)
		}
		if tc.open(v) == nil {
			t.Fatal("accepted ciphertext with changed context")
		}
	}
}
