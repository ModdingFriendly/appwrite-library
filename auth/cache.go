package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// CacheTTL is how long a verified identity or membership is reused in a warm
// runtime before it is checked against Appwrite again.
//
// Every authenticated request used to make two sequential Appwrite calls
// (Account.Get, then Teams.ListMemberships) before any real work. Within this
// window a repeat request with the same JWT skips both. The trade-off: a
// membership that is removed, or an account that is disabled, keeps working for
// up to CacheTTL on a runtime that already verified it. The organisation
// suspension check (reparix/orgstatus) already accepts a 30 second window.
//
// Only successful lookups are cached; refusals and errors are always
// re-checked. Set CacheTTL to 0 to disable caching (for example in tests that
// change a membership between requests with the same JWT).
var CacheTTL = 15 * time.Second

// maxCacheEntries bounds memory: once reached, expired entries are dropped,
// and if that is not enough the cache is cleared.
const maxCacheEntries = 4096

type cacheEntry struct {
	identity   *Identity
	membership *Membership
	expires    time.Time
}

var (
	cacheMu  sync.Mutex
	cache    = map[string]cacheEntry{}
	cacheNow = time.Now
)

// cacheKey binds an entry to the Appwrite endpoint, project and JWT, so a
// different project, test server or token never shares an entry. The JWT is
// hashed so tokens are not kept in memory as map keys.
func cacheKey(cfg Config, jwt string, parts ...string) string {
	h := sha256.New()
	for _, part := range append([]string{cfg.Endpoint, cfg.ProjectID, jwt}, parts...) {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func cacheGet(key string) (cacheEntry, bool) {
	if CacheTTL <= 0 {
		return cacheEntry{}, false
	}
	cacheMu.Lock()
	defer cacheMu.Unlock()
	entry, ok := cache[key]
	if !ok {
		return cacheEntry{}, false
	}
	if !cacheNow().Before(entry.expires) {
		delete(cache, key)
		return cacheEntry{}, false
	}
	return entry, true
}

func cachePut(key string, entry cacheEntry) {
	if CacheTTL <= 0 {
		return
	}
	now := cacheNow()
	entry.expires = now.Add(CacheTTL)
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if len(cache) >= maxCacheEntries {
		for k, e := range cache {
			if !now.Before(e.expires) {
				delete(cache, k)
			}
		}
		if len(cache) >= maxCacheEntries {
			cache = map[string]cacheEntry{}
		}
	}
	cache[key] = entry
}

// ResetCache drops every cached identity and membership.
func ResetCache() {
	cacheMu.Lock()
	cache = map[string]cacheEntry{}
	cacheMu.Unlock()
}

func copyIdentity(id *Identity) *Identity {
	if id == nil {
		return nil
	}
	c := *id
	return &c
}

func copyMembership(m *Membership) *Membership {
	if m == nil {
		return nil
	}
	c := *m
	c.Roles = append([]string(nil), m.Roles...)
	return &c
}
