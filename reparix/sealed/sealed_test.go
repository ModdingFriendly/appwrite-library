package sealed

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

const hex32 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func TestParseKeyKeepsTheExistingMappings(t *testing.T) {
	raw, _ := hex.DecodeString(hex32)
	if k, err := ParseKey("  " + hex32 + "\n"); err != nil || !bytes.Equal(k, raw) {
		t.Fatalf("32-byte hex must be used as is: %x %v", k, err)
	}
	long := hex32 + hex32
	longRaw, _ := hex.DecodeString(long)
	want := sha256.Sum256(longRaw)
	if k, err := ParseKey(long); err != nil || !bytes.Equal(k, want[:]) {
		t.Fatalf("longer hex must be reduced with SHA-256: %x %v", k, err)
	}
	b64 := base64.StdEncoding.EncodeToString(raw)
	if k, err := ParseKey(b64); err != nil || !bytes.Equal(k, raw) {
		t.Fatalf("32-byte base64 must be used as is: %x %v", k, err)
	}
	for _, bad := range []string{"", "short", hex32[:62], base64.StdEncoding.EncodeToString(raw[:16])} {
		if _, err := ParseKey(bad); !errors.Is(err, ErrKey) {
			t.Fatalf("%q: want ErrKey, got %v", bad, err)
		}
	}
}

func TestSealOpensOnlyWithTheSameKeyAndOwner(t *testing.T) {
	key, _ := ParseKey(hex32)
	aad := []byte("credentials|team-a|fedex")
	env, err := Seal(key, []byte("very-secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(env, "v1:") || strings.Contains(env, "very-secret") {
		t.Fatalf("envelope: %s", env)
	}
	again, _ := Seal(key, []byte("very-secret"), aad)
	if again == env {
		t.Fatal("each seal must use a fresh nonce")
	}
	plain, err := Open(key, env, aad)
	if err != nil || string(plain) != "very-secret" {
		t.Fatalf("open: %q %v", plain, err)
	}
	if _, err := Open(key, env, []byte("credentials|team-b|fedex")); !errors.Is(err, ErrOpen) {
		t.Fatalf("another owner must not open it: %v", err)
	}
	other, _ := ParseKey(hex32 + hex32)
	if _, err := Open(other, env, aad); !errors.Is(err, ErrOpen) {
		t.Fatalf("another key must not open it: %v", err)
	}
	box, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(env, "v1:"))
	box[len(box)-1] ^= 1
	if _, err := Open(key, "v1:"+base64.StdEncoding.EncodeToString(box), aad); !errors.Is(err, ErrOpen) {
		t.Fatalf("a tampered value must not open: %v", err)
	}
	for _, bad := range []string{"", "v2:abc", "v1:not base64!", "v1:" + base64.StdEncoding.EncodeToString([]byte("tiny"))} {
		if _, err := Open(key, bad, aad); !errors.Is(err, ErrEnvelope) {
			t.Fatalf("%q: want ErrEnvelope, got %v", bad, err)
		}
	}
	if _, err := Seal([]byte("short"), nil, aad); !errors.Is(err, ErrKey) {
		t.Fatalf("a short key must be refused: %v", err)
	}
}

func TestJSONHelpersUseTheEnvironmentKey(t *testing.T) {
	type settings struct {
		ClientSecret string `json:"client_secret"`
	}
	t.Setenv(KeyEnv, "")
	if _, err := SealJSON(settings{"x"}, nil); !errors.Is(err, ErrKey) {
		t.Fatalf("missing key: %v", err)
	}
	t.Setenv(KeyEnv, hex32)
	env, err := SealJSON(settings{"very-secret"}, []byte("owner"))
	if err != nil {
		t.Fatal(err)
	}
	var got settings
	if err := OpenJSON(env, []byte("owner"), &got); err != nil || got.ClientSecret != "very-secret" {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if err := OpenJSON(env, []byte("someone else"), &got); err == nil || strings.Contains(err.Error(), "very-secret") {
		t.Fatalf("wrong owner: %v", err)
	}
}

// Values sealed by the code this package replaces, in service-integrations and
// service-messaging, with SECRET_HASH=hex32. They must keep opening: Reparix
// stores credentials in this format.
func TestOpensValuesSealedByTheCodeItReplaces(t *testing.T) {
	key, _ := ParseKey(hex32)
	cases := []struct{ name, envelope, aad, want string }{
		{"service-integrations", "v1:A6C6sx3pRs3nikHbJVcAN5FMq2jNAkheS8atZuOmDqT28kBAtdHZp3B7imHjYcpk+cwezhO3vylfPXI=",
			"credentials|team-a|fedex", `{"client_secret":"very-secret"}`},
		{"service-messaging", "v1:hhQChXBJiAbyzKEmjcviaXFD+O3lYq+BApsPcz1S",
			"reparix:messaging:v1:team-a:email:smtp", `{}`},
	}
	for _, tc := range cases {
		plain, err := Open(key, tc.envelope, []byte(tc.aad))
		if err != nil || string(plain) != tc.want {
			t.Fatalf("%s: %q %v", tc.name, plain, err)
		}
	}
}
