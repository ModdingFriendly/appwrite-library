// Package sealed encrypts server-only secrets, such as an organisation's
// provider credentials, for storage in a database column.
//
// A sealed value is the envelope "v1:" + base64(nonce || AES-256-GCM
// ciphertext). The caller supplies additional authenticated data (AAD) that
// names what the secret belongs to, for example the organisation and the
// provider. A value copied to another row, organisation or provider then fails
// to open instead of decrypting under the wrong owner.
//
// The key comes from SECRET_HASH. The name is historical: it is an encryption
// key, not a hash. Two encodings are accepted, and their mapping to the AES key
// must never change, or stored values become unreadable:
//
//   - hex of exactly 32 bytes is used as is;
//   - hex of more than 32 bytes (such as `openssl rand -hex 64`) is reduced
//     with SHA-256;
//   - base64 of exactly 32 bytes is used as is.
//
// Errors never contain the key, the plaintext or the envelope.
package sealed

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
)

// KeyEnv is the environment variable that holds the key.
const KeyEnv = "SECRET_HASH"

const prefix = "v1:"

var (
	// ErrKey reports a missing or malformed SECRET_HASH.
	ErrKey = errors.New("SECRET_HASH must be random hex encoding at least 32 bytes, or a base64-encoded 32-byte key")
	// ErrEnvelope reports a value that is not a v1 envelope.
	ErrEnvelope = errors.New("invalid sealed value")
	// ErrOpen reports a value that does not open with this key and AAD: the
	// wrong key, the wrong owner, or tampering.
	ErrOpen = errors.New("sealed value could not be opened")
)

// ParseKey turns a SECRET_HASH value into a 32-byte AES key.
func ParseKey(secret string) ([]byte, error) {
	secret = strings.TrimSpace(secret)
	if raw, err := hex.DecodeString(secret); err == nil && len(raw) >= 32 {
		if len(raw) == 32 {
			return raw, nil
		}
		k := sha256.Sum256(raw)
		return k[:], nil
	}
	if k, err := base64.StdEncoding.DecodeString(secret); err == nil && len(k) == 32 {
		return k, nil
	}
	return nil, ErrKey
}

// KeyFromEnv reads and parses SECRET_HASH.
func KeyFromEnv() ([]byte, error) { return ParseKey(os.Getenv(KeyEnv)) }

func aead(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrKey
	}
	return cipher.NewGCM(block)
}

// Seal encrypts plain under key, bound to aad.
func Seal(key, plain, aad []byte) (string, error) {
	a, err := aead(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return prefix + base64.StdEncoding.EncodeToString(a.Seal(nonce, nonce, plain, aad)), nil
}

// Open decrypts an envelope made by Seal with the same key and aad.
func Open(key []byte, envelope string, aad []byte) ([]byte, error) {
	a, err := aead(key)
	if err != nil {
		return nil, err
	}
	raw, ok := strings.CutPrefix(envelope, prefix)
	if !ok {
		return nil, ErrEnvelope
	}
	box, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(box) < a.NonceSize()+a.Overhead() {
		return nil, ErrEnvelope
	}
	plain, err := a.Open(nil, box[:a.NonceSize()], box[a.NonceSize():], aad)
	if err != nil {
		return nil, ErrOpen
	}
	return plain, nil
}

// SealJSON marshals v and seals it with the SECRET_HASH key.
func SealJSON(v any, aad []byte) (string, error) {
	key, err := KeyFromEnv()
	if err != nil {
		return "", err
	}
	plain, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return Seal(key, plain, aad)
}

// OpenJSON opens an envelope with the SECRET_HASH key and unmarshals it into out.
func OpenJSON(envelope string, aad []byte, out any) error {
	key, err := KeyFromEnv()
	if err != nil {
		return err
	}
	plain, err := Open(key, envelope, aad)
	if err != nil {
		return err
	}
	if json.Unmarshal(plain, out) != nil {
		return ErrEnvelope
	}
	return nil
}
